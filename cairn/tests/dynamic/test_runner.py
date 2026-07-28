"""The in-container Dynamic Verifier entry point.

Every environment failure has to arrive at the Orchestrator as a well-formed
manifest carrying inconclusive outcomes, never as an empty output directory or
a traceback. The contract itself refuses to represent the alternative — a
non-completed `DynamicResult` cannot hold a settled verdict — so these tests
mostly check that the runner reaches that contract rather than raising.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cairn.analysis.contracts import ToolStatus
from cairn.dynamic.contracts import (
    DYNAMIC_CONTRACT,
    REASON_APP_START_FAILED,
    REASON_PLAN_INVALID,
    REASON_SERVICE_UNAVAILABLE,
    DynamicResult,
)
from cairn.dynamic.runner import (
    PLAN_FILENAME,
    RESULT_FILENAME,
    load_plan,
    main,
    parse_targets,
    run,
)

PLAN = {
    "app_jar": "artifacts/web_app.jar",
    "app_port": 8080,
    "build_directory": "build",
    "service_hosts": {"echo": "echo-host:8081"},
    "targets": [
        {
            "finding_id": "11111111-1111-1111-1111-111111111111",
            "category": "sql-injection",
            "http_method": "GET",
            "route": "/items/{id}",
            "route_prefixes": [],
            "parameter": None,
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
    return source, scratch, output


def write_plan(scratch: Path, payload: object) -> None:
    (scratch / PLAN_FILENAME).write_text(json.dumps(payload), encoding="utf-8")


# --- the plan -----------------------------------------------------------------


def test_a_valid_plan_parses(workspace: tuple[Path, Path, Path]) -> None:
    _source, scratch, _output = workspace
    write_plan(scratch, PLAN)

    plan = load_plan(scratch)
    targets = parse_targets(plan)

    assert plan["app_port"] == 8080
    assert len(targets) == 1
    assert targets[0].category == "sql-injection"


@pytest.mark.parametrize(
    "payload",
    [
        pytest.param({**PLAN, "app_jar": ""}, id="no-runnable-artifact"),
        pytest.param([PLAN], id="not-an-object"),
    ],
)
def test_a_malformed_plan_is_refused(
    workspace: tuple[Path, Path, Path],
    payload: object,
) -> None:
    _source, scratch, _output = workspace
    write_plan(scratch, payload)

    with pytest.raises(ValueError):
        load_plan(scratch)


def test_a_target_missing_its_identity_is_dropped_not_guessed(
    workspace: tuple[Path, Path, Path],
) -> None:
    targets = parse_targets({"targets": [{"category": "ssrf"}, {"finding_id": "x"}]})

    assert targets == []


# --- failing closed ------------------------------------------------------------


def test_a_missing_plan_fails_closed_with_a_valid_manifest(
    workspace: tuple[Path, Path, Path],
) -> None:
    source, scratch, output = workspace

    result = run(source, scratch, output)

    assert result.contract == DYNAMIC_CONTRACT
    assert result.status is ToolStatus.FAILED
    assert result.reason_code == REASON_PLAN_INVALID
    assert result.app_started is False


def test_unreachable_services_fail_closed_and_mark_every_target_inconclusive(
    workspace: tuple[Path, Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Per-finding, so a reader sees why each one was not verified rather than
    only a run-level note."""

    source, scratch, output = workspace
    write_plan(scratch, {**PLAN, "service_hosts": {"postgres": "db:5432"}})
    monkeypatch.setattr(
        "cairn.dynamic.runner.wait_for_services",
        _raise(REASON_SERVICE_UNAVAILABLE, "postgres never accepted a connection"),
    )

    result = run(source, scratch, output)

    assert result.status is ToolStatus.FAILED
    assert result.reason_code == REASON_SERVICE_UNAVAILABLE
    assert len(result.outcomes) == 1
    assert result.outcomes[0].verdict == "inconclusive"
    assert result.outcomes[0].reason_code == REASON_SERVICE_UNAVAILABLE


def test_an_application_that_will_not_start_fails_closed(
    workspace: tuple[Path, Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source, scratch, output = workspace
    write_plan(scratch, PLAN)
    monkeypatch.setattr("cairn.dynamic.runner.wait_for_services", lambda hosts: [])
    monkeypatch.setattr(
        "cairn.dynamic.runner.start_application",
        _raise(REASON_APP_START_FAILED, "the jar is not there"),
    )

    result = run(source, scratch, output)

    assert result.status is ToolStatus.FAILED
    assert result.reason_code == REASON_APP_START_FAILED
    assert all(outcome.verdict == "inconclusive" for outcome in result.outcomes)


def test_a_failed_run_cannot_carry_a_settled_verdict() -> None:
    """The contract refuses it, so no future caller can construct one."""

    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        DynamicResult(
            contract=DYNAMIC_CONTRACT,
            status=ToolStatus.FAILED,
            tool_name="dynamic-verifier",
            reason_code=REASON_APP_START_FAILED,
            outcomes=[
                {
                    "finding_id": "f",
                    "category": "ssrf",
                    "verdict": "rejected",
                    "detail": "nothing happened",
                }
            ],
        )


def test_main_always_writes_a_manifest_and_exits_zero(
    workspace: tuple[Path, Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source, scratch, output = workspace
    monkeypatch.setattr(
        "cairn.dynamic.runner.Path",
        lambda value: {
            "/work/source": source,
            "/work/scratch": scratch,
            "/work/output": output,
        }.get(value, Path(value)),
    )

    assert main([]) == 0

    payload = json.loads((output / RESULT_FILENAME).read_text(encoding="utf-8"))
    result = DynamicResult.model_validate(payload)
    assert result.status is not ToolStatus.COMPLETED


def _raise(reason_code: str, detail: str):
    from cairn.dynamic.app import EnvironmentError_

    def raiser(*args, **kwargs):
        del args, kwargs
        raise EnvironmentError_(reason_code, detail)

    return raiser
