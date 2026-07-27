"""The in-container entry point for the Independent Reviewer.

Two properties matter more than the happy path: the grant must not survive in
the environment past client construction, and a malformed assignment must fail
closed with a well-formed manifest rather than a traceback.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from cairn.analysis.contracts import ToolStatus
from cairn.semantic.runner import GATEWAY_ENV, GRANT_ENV
from cairn.verify.contracts import VERIFY_CONTRACT, VERIFY_TOOL_NAME, VerifyResult
from cairn.verify.runner import (
    ASSIGNMENT_FILENAME,
    REASON_ASSIGNMENT_INVALID,
    REASON_GRANT_MISSING,
    RESULT_FILENAME,
    load_assignment,
    main,
    run,
)

FIXTURE_ROOT = Path(__file__).parents[1] / "semantic" / "fixtures" / "injected-app"
CONTROLLER = "web/src/main/java/dev/cairn/shop/OrderController.java"
GRANT = f"{'A' * 40}.{'B' * 40}"
ROOT_CAUSE_KEY = "b" * 64

ASSIGNMENT = {
    "root_cause_key": ROOT_CAUSE_KEY,
    "module": "web",
    "category": "sql-injection",
    "cwe_ids": ["CWE-89"],
    "sink": "Statement.executeQuery",
    "locations": [
        {
            "path": CONTROLLER,
            "start_line": 1,
            "end_line": 2,
            "symbol": "OrderController.list",
            "role": "sink",
        }
    ],
}


@pytest.fixture
def workspace(tmp_path: Path) -> tuple[Path, Path, Path]:
    scratch = tmp_path / "scratch"
    output = tmp_path / "output"
    scratch.mkdir()
    output.mkdir()
    return FIXTURE_ROOT, scratch, output


def write_assignment(scratch: Path, payload: object) -> None:
    (scratch / ASSIGNMENT_FILENAME).write_text(
        json.dumps(payload), encoding="utf-8"
    )


@pytest.fixture(autouse=True)
def clean_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(GRANT_ENV, raising=False)
    monkeypatch.delenv(GATEWAY_ENV, raising=False)


# --- the assignment -----------------------------------------------------------


def test_a_valid_assignment_parses_into_the_facts_the_reviewer_may_see(
    workspace: tuple[Path, Path, Path],
) -> None:
    _source, scratch, _output = workspace
    write_assignment(scratch, ASSIGNMENT)

    assignment = load_assignment(scratch)

    assert assignment.root_cause_key == ROOT_CAUSE_KEY
    assert assignment.category == "sql-injection"
    assert assignment.cwe_ids == ("CWE-89",)
    assert assignment.locations[0]["path"] == CONTROLLER


def test_the_runner_reads_no_field_outside_the_blind_set(
    workspace: tuple[Path, Path, Path],
) -> None:
    """Even a file that somehow carried the reporting worker's prose could not
    surface it: nothing here reads those keys."""

    _source, scratch, _output = workspace
    write_assignment(
        scratch,
        {
            **ASSIGNMENT,
            "message": "the original author's reasoning",
            "call_chain": [{"path": CONTROLLER, "start_line": 1}],
            "controllability": "the `owner` parameter",
        },
    )

    assignment = load_assignment(scratch)

    rendered = json.dumps(
        {
            "module": assignment.module,
            "category": assignment.category,
            "cwe_ids": list(assignment.cwe_ids),
            "sink": assignment.sink,
            "locations": list(assignment.locations),
        }
    )
    assert "reasoning" not in rendered
    assert "controllability" not in rendered
    assert not hasattr(assignment, "message")


@pytest.mark.parametrize(
    "payload",
    [
        pytest.param({"module": "web", "category": "x", "locations": []}, id="no-key"),
        pytest.param({**ASSIGNMENT, "locations": []}, id="no-locations"),
        pytest.param({**ASSIGNMENT, "root_cause_key": ""}, id="blank-key"),
        pytest.param([ASSIGNMENT], id="not-an-object"),
    ],
)
def test_a_malformed_assignment_is_refused(
    workspace: tuple[Path, Path, Path],
    payload: object,
) -> None:
    _source, scratch, _output = workspace
    write_assignment(scratch, payload)

    with pytest.raises(ValueError):
        load_assignment(scratch)


def test_a_missing_assignment_fails_closed_with_a_valid_manifest(
    workspace: tuple[Path, Path, Path],
) -> None:
    source, scratch, output = workspace

    result = run(source, scratch, output)

    assert result.status is ToolStatus.FAILED
    assert result.reason_code == REASON_ASSIGNMENT_INVALID
    assert result.verdict is None
    assert result.contract == VERIFY_CONTRACT
    assert result.tool_name == VERIFY_TOOL_NAME


def test_unparseable_json_fails_closed(
    workspace: tuple[Path, Path, Path],
) -> None:
    source, scratch, output = workspace
    (scratch / ASSIGNMENT_FILENAME).write_text("{not json", encoding="utf-8")

    assert run(source, scratch, output).reason_code == REASON_ASSIGNMENT_INVALID


# --- the credential -----------------------------------------------------------


def test_a_missing_grant_fails_closed_rather_than_calling_out_unauthenticated(
    workspace: tuple[Path, Path, Path],
) -> None:
    source, scratch, output = workspace
    write_assignment(scratch, ASSIGNMENT)

    result = run(source, scratch, output)

    assert result.status is ToolStatus.FAILED
    assert result.reason_code == REASON_GRANT_MISSING
    assert result.root_cause_key == ROOT_CAUSE_KEY


def test_the_grant_does_not_survive_in_the_environment(
    workspace: tuple[Path, Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Nothing the reviewer runs afterwards — including any tool — can read the
    credential back out of `os.environ` or `/proc/self/environ`."""

    source, scratch, output = workspace
    write_assignment(scratch, ASSIGNMENT)
    monkeypatch.setenv(GRANT_ENV, GRANT)
    monkeypatch.setenv(GATEWAY_ENV, "http://cairn-llm-gateway:8002")

    # The review itself fails at the transport (no SDK, no gateway), which is
    # irrelevant: what matters is the environment afterwards.
    run(source, scratch, output)

    assert GRANT_ENV not in os.environ
    assert GATEWAY_ENV not in os.environ
    assert GRANT not in json.dumps(dict(os.environ))


# --- the manifest -------------------------------------------------------------


def test_main_always_writes_a_contract_valid_manifest_and_exits_zero(
    workspace: tuple[Path, Path, Path],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """A failed review is a reported outcome, not a crashed container."""

    source, scratch, output = workspace
    write_assignment(scratch, ASSIGNMENT)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        "cairn.verify.runner.Path",
        lambda value: {
            "/work/source": source,
            "/work/scratch": scratch,
            "/work/output": output,
        }.get(value, Path(value)),
    )

    assert main([]) == 0

    payload = json.loads((output / RESULT_FILENAME).read_text(encoding="utf-8"))
    result = VerifyResult.model_validate(payload)
    assert result.status is not ToolStatus.COMPLETED
    assert result.reason_code == REASON_GRANT_MISSING


def test_the_semantic_entry_point_routes_the_verify_operation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`run-semantic independent-verify` must reach this runner, not a review."""

    from cairn.semantic import runner as semantic_runner

    seen: list[list[str]] = []
    monkeypatch.setattr(
        "cairn.verify.runner.main",
        lambda argv: seen.append(list(argv)) or 0,
    )

    assert semantic_runner.main(["independent-verify"]) == 0
    assert seen == [["independent-verify"]]
