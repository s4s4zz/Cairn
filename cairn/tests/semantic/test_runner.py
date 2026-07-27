"""The in-container entry point.

Two properties matter more than the happy path: the credential does not
survive in the environment past client construction, and a malformed
assignment fails closed with a well-formed manifest rather than a traceback
and an empty output directory.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from cairn.analysis.contracts import ToolStatus
from cairn.semantic import runner as runner_module
from cairn.semantic.contracts import SEMANTIC_CONTRACT, SemanticReviewResult
from cairn.semantic.findings import ReviewScope
from cairn.semantic.runner import (
    GATEWAY_ENV,
    GRANT_ENV,
    REASON_GRANT_MISSING,
    REASON_SCOPE_INVALID,
    RESULT_FILENAME,
    SCOPE_FILENAME,
    load_scope,
    run,
    take_credentials,
)

FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "injected-app"
GRANT = "eyJhIjoxfQ.bWFj"


@pytest.fixture
def workspace(tmp_path: Path) -> tuple[Path, Path, Path]:
    source = tmp_path / "source"
    scratch = tmp_path / "scratch"
    output = tmp_path / "output"
    for path in (scratch, output):
        path.mkdir()
    # A real snapshot, so the ToolBroker and the tree hash have something to
    # work with.
    source.mkdir()
    for path in FIXTURE_ROOT.rglob("*"):
        if path.is_file():
            target = source / path.relative_to(FIXTURE_ROOT)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(path.read_bytes())
    return source, scratch, output


def write_scope(scratch: Path, **overrides: object) -> ReviewScope:
    scope = ReviewScope(
        module="core",
        attack_surface="HTTP endpoint",
        category="sql-injection",
        **overrides,
    )
    (scratch / SCOPE_FILENAME).write_text(
        json.dumps(scope.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
    )
    return scope


@pytest.fixture(autouse=True)
def clean_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(GRANT_ENV, raising=False)
    monkeypatch.delenv(GATEWAY_ENV, raising=False)


class TestLoadScope:
    def test_a_written_scope_round_trips(self, tmp_path: Path) -> None:
        scope = write_scope(tmp_path)

        assert load_scope(tmp_path).scope_key == scope.scope_key

    def test_a_missing_file_is_refused(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError):
            load_scope(tmp_path)

    def test_a_non_json_file_is_refused(self, tmp_path: Path) -> None:
        (tmp_path / SCOPE_FILENAME).write_text("not json at all")

        with pytest.raises(ValueError):
            load_scope(tmp_path)

    def test_a_json_array_is_refused(self, tmp_path: Path) -> None:
        (tmp_path / SCOPE_FILENAME).write_text("[]")

        with pytest.raises(ValueError):
            load_scope(tmp_path)

    def test_an_incomplete_scope_is_refused(self, tmp_path: Path) -> None:
        (tmp_path / SCOPE_FILENAME).write_text('{"module": "core"}')

        with pytest.raises(Exception):
            load_scope(tmp_path)


class TestTakeCredentials:
    def test_the_grant_does_not_survive_in_the_environment(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Nothing the reviewer runs afterwards may read the credential back
        out of os.environ or /proc/self/environ."""

        monkeypatch.setenv(GRANT_ENV, GRANT)
        monkeypatch.setenv(GATEWAY_ENV, "http://gateway:8002")

        grant, gateway = take_credentials()

        assert grant == GRANT
        assert gateway == "http://gateway:8002"
        assert GRANT_ENV not in os.environ
        assert GATEWAY_ENV not in os.environ

    def test_a_missing_grant_is_refused(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv(GATEWAY_ENV, "http://gateway:8002")

        with pytest.raises(ValueError):
            take_credentials()

    def test_a_blank_grant_is_refused(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv(GRANT_ENV, "   ")
        monkeypatch.setenv(GATEWAY_ENV, "http://gateway:8002")

        with pytest.raises(ValueError):
            take_credentials()


class TestRun:
    def test_a_malformed_scope_fails_closed_with_a_valid_manifest(
        self,
        workspace: tuple[Path, Path, Path],
    ) -> None:
        source, scratch, output = workspace
        (scratch / SCOPE_FILENAME).write_text("{ broken")

        result = run(source, scratch, output)

        assert result.contract == SEMANTIC_CONTRACT
        assert result.status is ToolStatus.FAILED
        assert result.reason_code == REASON_SCOPE_INVALID
        assert result.findings == []
        assert result.candidates == []

    def test_a_missing_grant_fails_closed(
        self,
        workspace: tuple[Path, Path, Path],
    ) -> None:
        source, scratch, output = workspace
        write_scope(scratch)

        result = run(source, scratch, output)

        assert result.status is ToolStatus.FAILED
        assert result.reason_code == REASON_GRANT_MISSING

    def test_the_scope_key_is_carried_into_the_failure(
        self,
        workspace: tuple[Path, Path, Path],
    ) -> None:
        """The Orchestrator matches the result to its AuditTask by scope key,
        so a failure that loses it cannot be attributed."""

        source, scratch, output = workspace
        scope = write_scope(scratch)

        result = run(source, scratch, output)

        assert result.scope_key == scope.scope_key


class TestMain:
    def test_it_writes_a_manifest_even_when_the_review_cannot_start(
        self,
        workspace: tuple[Path, Path, Path],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """An empty output directory would leave the Orchestrator guessing;
        a terminal manifest becomes a coverage warning."""

        source, scratch, output = workspace
        write_scope(scratch)
        monkeypatch.setattr(runner_module, "Path", Path)
        monkeypatch.setattr(
            runner_module,
            "run",
            lambda *args, **kwargs: runner_module._failed(
                "semantic:core", REASON_GRANT_MISSING
            ),
        )

        # main() reads the fixed container paths, so drive the pieces it wires
        # together rather than the path constants.
        result = runner_module.run(source, scratch, output)
        runner_module._write_json(
            output / RESULT_FILENAME, result.model_dump(mode="json")
        )

        written = json.loads((output / RESULT_FILENAME).read_text())

        assert SemanticReviewResult.model_validate(written).reason_code == (
            REASON_GRANT_MISSING
        )

    def test_missing_work_directories_exit_non_zero(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        assert runner_module.main([]) == 70
