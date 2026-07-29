from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from cairn.benchmarks.contracts import BenchmarkResult
from cairn.cli import main


def test_benchmarks_cli_emits_deterministic_result(
    tmp_path: Path,
    valid_gold_payload: dict[str, object],
    valid_audit_run_payload: dict[str, object],
) -> None:
    gold_path = tmp_path / "gold.json"
    export_path = tmp_path / "audit-run.json"
    gold_path.write_text(json.dumps(valid_gold_payload), encoding="utf-8")
    export_path.write_text(json.dumps(valid_audit_run_payload), encoding="utf-8")
    runner = CliRunner()

    first = runner.invoke(
        main,
        ["benchmarks", "--gold", str(gold_path), "--audit-run", str(export_path)],
    )
    second = runner.invoke(
        main,
        ["benchmarks", "--gold", str(gold_path), "--audit-run", str(export_path)],
    )

    assert first.exit_code == 0, first.output
    assert first.output == second.output
    result = BenchmarkResult.model_validate_json(first.output)
    assert result.schema_version == "benchmark-result-v1"
    assert "create-user" in runner.invoke(main, ["--help"]).output


def test_benchmarks_cli_writes_output_file(
    tmp_path: Path,
    valid_gold_payload: dict[str, object],
    valid_audit_run_payload: dict[str, object],
) -> None:
    gold_path = tmp_path / "gold.json"
    export_path = tmp_path / "audit-run.json"
    output_path = tmp_path / "result.json"
    gold_path.write_text(json.dumps(valid_gold_payload), encoding="utf-8")
    export_path.write_text(json.dumps(valid_audit_run_payload), encoding="utf-8")

    result = CliRunner().invoke(
        main,
        [
            "benchmarks",
            "--gold",
            str(gold_path),
            "--audit-run",
            str(export_path),
            "--output",
            str(output_path),
        ],
    )

    assert result.exit_code == 0, result.output
    assert result.output == ""
    BenchmarkResult.model_validate_json(output_path.read_text(encoding="utf-8"))


def test_benchmarks_cli_never_echoes_rejected_values(tmp_path: Path) -> None:
    marker = "PRIVATE-BINARY-OR-DECOMPILED-CONTENT"
    gold_path = tmp_path / "gold.json"
    export_path = tmp_path / "audit-run.json"
    gold_path.write_text(
        json.dumps(
            {
                "schema_version": "closed-platform-gold-v1",
                "decompiled_text": marker,
            }
        ),
        encoding="utf-8",
    )
    export_path.write_text("{}", encoding="utf-8")

    result = CliRunner().invoke(
        main,
        ["benchmarks", "--gold", str(gold_path), "--audit-run", str(export_path)],
    )

    assert result.exit_code != 0
    assert marker not in result.output
    assert "contract validation failed" in result.output
