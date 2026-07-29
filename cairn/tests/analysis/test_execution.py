from pathlib import Path
from dataclasses import replace
import json
import shutil

from cairn.analysis.contracts import AnalysisManifest
from cairn.analysis.execution import CommandResult, execute_build
from cairn.analysis.runner import run_operation
from cairn.analysis import runner
from cairn.analysis import tooling
from cairn.analysis.tooling import run_external_scanner
from cairn.analysis.tree_hash import source_tree_sha256
from cairn.server.ingestion import IngestionLimits, collect_snapshot_tree


FIXTURES = Path(__file__).parent / "fixtures"


def test_source_tree_hash_matches_ingestion_canonical_hash() -> None:
    root = FIXTURES / "maven-multi"

    detected = source_tree_sha256(root)
    ingested = collect_snapshot_tree(
        root,
        IngestionLimits(
            upload_max_bytes=100 * 1024 * 1024,
            max_files=10_000,
            max_total_bytes=100 * 1024 * 1024,
            max_file_bytes=10 * 1024 * 1024,
            max_compression_ratio=200,
            max_path_length=1024,
            max_path_depth=64,
        ),
    ).content_sha256

    assert detected == ingested


def test_build_uses_writable_copy_and_fixed_wrapper_arguments(
    tmp_path: Path,
) -> None:
    source = FIXTURES / "maven-multi"
    scratch = tmp_path / "scratch"
    output = tmp_path / "output"
    scratch.mkdir()
    output.mkdir()
    calls: list[tuple[list[str], Path]] = []

    def fake_executor(argv, cwd, log_path, environment, timeout):  # noqa: ANN001
        del environment, timeout
        calls.append((argv, cwd))
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text("fixture build\n")
        return CommandResult(0)

    result = execute_build(
        source,
        scratch,
        output,
        executor=fake_executor,
    )

    assert result["status"] == "success"
    assert len(calls) == 1
    argv, cwd = calls[0]
    assert argv[0] == "./mvnw"
    assert argv[-1] == "package"
    assert any(argument.startswith("-Dmaven.repo.local=") for argument in argv)
    assert cwd == scratch / "project"
    assert (scratch / "project/pom.xml").is_file()
    assert source.joinpath("target").exists() is False


def test_build_failure_is_a_completed_profile_with_failed_build_payload(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    shutil.copytree(FIXTURES / "gradle-multi", source)
    scratch = tmp_path / "scratch"
    output = tmp_path / "output"
    scratch.mkdir()
    output.mkdir()

    def failing_executor(argv, cwd, log_path, environment, timeout):  # noqa: ANN001
        del argv, cwd, environment, timeout
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text("compilation failed\n")
        return CommandResult(1)

    build = execute_build(
        source,
        scratch,
        output,
        executor=failing_executor,
    )
    manifest = {
        "contract": "cairn-deterministic-result-v1",
        "operation": "build",
        "status": "completed",
        "tool_name": "cairn-java-build",
        "tool_version": "1.0.0",
        "reason_code": None,
        "warnings": [],
        "raw_result_paths": ["build/000-gradle.log"],
        "inventory": None,
        "build": build,
        "candidates": [],
    }

    parsed = AnalysisManifest.model_validate(manifest)

    assert parsed.build is not None
    assert parsed.build.status == "failed"
    assert parsed.build.steps[0].reason_code == "PROJECT_BUILD_FAILED"


def test_inventory_and_config_runner_results_match_strict_contract(
    tmp_path: Path,
) -> None:
    scratch = tmp_path / "scratch"
    output = tmp_path / "output"
    scratch.mkdir()
    output.mkdir()

    inventory = run_operation(
        "inventory",
        source=FIXTURES / "maven-multi",
        scratch=scratch,
        output=output,
    )
    config = run_operation(
        "config-rules",
        source=FIXTURES / "maven-multi",
        scratch=scratch,
        output=output,
    )

    assert AnalysisManifest.model_validate(inventory).inventory is not None
    parsed_config = AnalysisManifest.model_validate(config)
    assert parsed_config.tool_version == "1.0.0"
    assert len(parsed_config.candidates) == 1


def test_bytecode_index_runner_result_matches_strict_contract(
    tmp_path: Path,
    monkeypatch,
) -> None:  # noqa: ANN001
    scratch = tmp_path / "scratch"
    output = tmp_path / "output"
    source = tmp_path / "source"
    scratch.mkdir()
    output.mkdir()
    source.mkdir()
    output.joinpath("asm-index.jsonl").write_text("")
    output.joinpath("asm-index.log").write_text("")

    class FakeIndex:
        def model_dump(self, *, mode: str) -> dict[str, object]:
            assert mode == "json"
            return {
                "contract": "cairn-program-index-v2",
                "asm_version": "9.8",
                "target_java_version": 17,
                "components": [],
                "resources": [],
                "classes": [],
                "methods": [],
                "fields": [],
                "calls": [],
                "field_accesses": [],
                "decompiled_views": [],
                "coverage_gaps": [],
                "classes_total": 0,
                "classes_parsed": 0,
            }

    monkeypatch.setattr(runner, "build_bytecode_index", lambda *args: FakeIndex())
    monkeypatch.setattr(runner, "bytecode_sink_candidates", lambda *args, **kwargs: [])

    payload = run_operation(
        "bytecode-index",
        source=source,
        scratch=scratch,
        output=output,
    )
    manifest = AnalysisManifest.model_validate(payload)

    assert manifest.bytecode_index is None
    assert manifest.bytecode_index_path == "program-index-v2.json"
    assert manifest.bytecode_index_summary is not None
    assert manifest.bytecode_index_summary.classes_parsed == 0
    assert manifest.candidates_path == "bytecode-candidates.json"
    assert manifest.candidate_count == 0
    assert manifest.raw_result_paths == [
        "asm-index.jsonl",
        "asm-index.log",
        "bytecode-candidates.json",
        "program-index-v2.json",
    ]


def test_missing_external_scanner_is_explicitly_unavailable(
    tmp_path: Path,
    monkeypatch,
) -> None:  # noqa: ANN001
    scratch = tmp_path / "scratch"
    output = tmp_path / "output"
    scratch.mkdir()
    output.mkdir()
    monkeypatch.setenv("PATH", str(tmp_path / "empty-bin"))

    result = run_external_scanner(
        "semgrep",
        FIXTURES / "maven-multi",
        scratch,
        output,
        snapshot_sha256="a" * 64,
    )

    assert result == {
        "status": "unavailable",
        "tool_name": "semgrep",
        "tool_version": None,
        "reason_code": "SCANNER_BINARY_UNAVAILABLE",
        "raw_result_paths": [],
        "candidates": [],
    }


def test_external_scanner_records_version_and_normalized_result(
    tmp_path: Path,
    monkeypatch,
) -> None:  # noqa: ANN001
    scratch = tmp_path / "scratch"
    output = tmp_path / "output"
    binary_root = tmp_path / "bin"
    rules = tmp_path / "rules"
    scratch.mkdir()
    output.mkdir()
    binary_root.mkdir()
    rules.mkdir()
    binary = binary_root / "semgrep"
    binary.write_text("#!/bin/sh\nexit 0\n")
    binary.chmod(0o755)
    monkeypatch.setenv("PATH", str(binary_root))
    monkeypatch.setitem(
        tooling.TOOL_SPECS,
        "semgrep",
        replace(
            tooling.TOOL_SPECS["semgrep"],
            required_asset=str(rules),
        ),
    )

    def fake_executor(argv, cwd, log_path, environment, timeout):  # noqa: ANN001
        del cwd, environment, timeout
        log_path.parent.mkdir(parents=True, exist_ok=True)
        if argv == ["semgrep", "--version"]:
            log_path.write_text("1.130.0\n")
        else:
            raw_path = Path(argv[argv.index("--output") + 1])
            raw_path.write_text(
                json.dumps(
                    {
                        "results": [
                            {
                                "check_id": "java.sql.fixture",
                                "path": (
                                    "core/src/main/java/dev/cairn/"
                                    "UserRepository.java"
                                ),
                                "start": {"line": 7, "col": 9},
                                "end": {"line": 7, "col": 20},
                                "extra": {
                                    "message": "Fixture SQL sink",
                                    "severity": "ERROR",
                                    "metadata": {"cwe": ["CWE-89"]},
                                },
                            }
                        ]
                    }
                )
            )
            log_path.write_text("scan complete\n")
        return CommandResult(0)

    result = run_external_scanner(
        "semgrep",
        FIXTURES / "maven-multi",
        scratch,
        output,
        snapshot_sha256="a" * 64,
        executor=fake_executor,
    )

    assert result["status"] == "completed"
    assert result["tool_version"] == "1.130.0"
    assert len(result["candidates"]) == 1
    assert result["candidates"][0]["cwe_ids"] == ["CWE-89"]
    assert set(result["raw_result_paths"]) == {
        "scanners/semgrep-version.txt",
        "scanners/semgrep.json",
        "scanners/semgrep.log",
    }
