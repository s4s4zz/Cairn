"""The in-container PoC Author entry point.

Two properties matter beyond the happy path: the grant must not survive in the
environment past client construction, and a malformed assignment must fail
closed with a well-formed manifest rather than a traceback.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from cairn.poc.contracts import POC_CONTRACT, POC_TOOL_NAME, PocResult
from cairn.poc.runner import (
    ASSIGNMENT_FILENAME,
    REASON_ASSIGNMENT_INVALID,
    REASON_GRANT_MISSING,
    RESULT_FILENAME,
    load_assignment,
    main,
    run,
)
from cairn.semantic.runner import GATEWAY_ENV, GRANT_ENV

FIXTURE_ROOT = Path(__file__).parents[1] / "semantic" / "fixtures" / "injected-app"
CONTROLLER = "web/src/main/java/dev/cairn/shop/OrderController.java"
GRANT = f"{'A' * 40}.{'B' * 40}"
FINDING_ID = "11111111-1111-1111-1111-111111111111"

ASSIGNMENT = {
    "finding_id": FINDING_ID,
    "module": "web",
    "category": "expression-injection",
    "cwe_ids": ["CWE-917"],
    "sink": "SpelExpressionParser.parseExpression",
    "http_method": "POST",
    "route": "/orders",
    "route_prefixes": [],
    "locations": [
        {
            "path": CONTROLLER,
            "start_line": 1,
            "end_line": 2,
            "symbol": "OrderController.create",
            "role": "sink",
        }
    ],
}


@pytest.fixture
def workspace(tmp_path: Path) -> tuple[Path, Path, Path]:
    source, scratch, output = (
        tmp_path / "source",
        tmp_path / "scratch",
        tmp_path / "output",
    )
    for path in (source, scratch, output):
        path.mkdir()
    return FIXTURE_ROOT, scratch, output


def write_assignment(scratch: Path, payload: object) -> None:
    (scratch / ASSIGNMENT_FILENAME).write_text(json.dumps(payload), encoding="utf-8")


@pytest.fixture(autouse=True)
def clean_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(GRANT_ENV, raising=False)
    monkeypatch.delenv(GATEWAY_ENV, raising=False)


def test_a_valid_assignment_parses_with_its_route() -> None:
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        scratch = Path(tmp)
        write_assignment(scratch, ASSIGNMENT)

        assignment = load_assignment(scratch)

    assert assignment.finding_id == FINDING_ID
    assert assignment.http_method == "POST"
    assert assignment.route == "/orders"
    assert assignment.category == "expression-injection"


@pytest.mark.parametrize(
    "payload",
    [
        pytest.param({"module": "web", "category": "x"}, id="no-finding-id"),
        pytest.param({**ASSIGNMENT, "finding_id": ""}, id="blank-finding-id"),
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


def test_a_missing_assignment_fails_closed(
    workspace: tuple[Path, Path, Path],
) -> None:
    source, scratch, output = workspace

    result = run(source, scratch, output)

    assert result.status == "failed"
    assert result.reason_code == REASON_ASSIGNMENT_INVALID
    assert result.plan is None
    assert result.contract == POC_CONTRACT
    assert result.tool_name == POC_TOOL_NAME


def test_a_missing_grant_fails_closed(
    workspace: tuple[Path, Path, Path],
) -> None:
    source, scratch, output = workspace
    write_assignment(scratch, ASSIGNMENT)

    result = run(source, scratch, output)

    assert result.status == "failed"
    assert result.reason_code == REASON_GRANT_MISSING
    assert result.finding_id == FINDING_ID


def test_the_grant_does_not_survive_in_the_environment(
    workspace: tuple[Path, Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source, scratch, output = workspace
    write_assignment(scratch, ASSIGNMENT)
    monkeypatch.setenv(GRANT_ENV, GRANT)
    monkeypatch.setenv(GATEWAY_ENV, "http://cairn-llm-gateway:8002")

    run(source, scratch, output)

    assert GRANT_ENV not in os.environ
    assert GATEWAY_ENV not in os.environ
    assert GRANT not in json.dumps(dict(os.environ))


def test_main_always_writes_a_manifest_and_exits_zero(
    workspace: tuple[Path, Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source, scratch, output = workspace
    write_assignment(scratch, ASSIGNMENT)
    monkeypatch.setattr(
        "cairn.poc.runner.Path",
        lambda value: {
            "/work/source": source,
            "/work/scratch": scratch,
            "/work/output": output,
        }.get(value, Path(value)),
    )

    assert main([]) == 0

    payload = json.loads((output / RESULT_FILENAME).read_text(encoding="utf-8"))
    result = PocResult.model_validate(payload)
    assert result.status != "completed"
    assert result.reason_code == REASON_GRANT_MISSING


def test_the_semantic_entry_point_routes_author_poc(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from cairn.semantic import runner as semantic_runner

    seen: list[list[str]] = []
    monkeypatch.setattr(
        "cairn.poc.runner.main",
        lambda argv: seen.append(list(argv)) or 0,
    )

    assert semantic_runner.main(["author-poc"]) == 0
    assert seen == [["author-poc"]]
