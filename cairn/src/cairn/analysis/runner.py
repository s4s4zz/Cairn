from __future__ import annotations

import json
from pathlib import Path
import sys

from cairn.analysis.config_rules import RULESET_VERSION, scan_config
from cairn.analysis.execution import execute_build
from cairn.analysis.indexer import build_inventory
from cairn.analysis.tooling import TOOL_SPECS, run_external_scanner
from cairn.analysis.tree_hash import source_tree_sha256


_OPERATIONS = {
    "default",
    "inventory",
    "build",
    *TOOL_SPECS,
    "config-rules",
}


def _write_json(path: Path, payload: dict[str, object]) -> None:
    temporary = path.with_suffix(f"{path.suffix}.tmp")
    temporary.write_text(
        json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )
        + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def _manifest(
    operation: str,
    *,
    status: str,
    tool_name: str,
    tool_version: str | None,
    reason_code: str | None = None,
    raw_result_paths: list[str] | None = None,
    inventory: dict[str, object] | None = None,
    build: dict[str, object] | None = None,
    candidates: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    return {
        "contract": "cairn-deterministic-result-v1",
        "operation": operation,
        "status": status,
        "tool_name": tool_name,
        "tool_version": tool_version,
        "reason_code": reason_code,
        "warnings": [],
        "raw_result_paths": sorted(set(raw_result_paths or [])),
        "inventory": inventory,
        "build": build,
        "candidates": candidates or [],
    }


def run_operation(
    operation: str,
    *,
    source: Path,
    scratch: Path,
    output: Path,
) -> dict[str, object]:
    if operation not in _OPERATIONS:
        return _manifest(
            operation,
            status="failed",
            tool_name="cairn-analysis-runner",
            tool_version=None,
            reason_code="ANALYSIS_OPERATION_UNKNOWN",
        )
    if operation == "inventory":
        return _manifest(
            operation,
            status="completed",
            tool_name="cairn-java-inventory",
            tool_version="1.0.0",
            inventory=build_inventory(source),
        )
    if operation == "build":
        return _manifest(
            operation,
            status="completed",
            tool_name="cairn-java-build",
            tool_version="1.0.0",
            build=execute_build(source, scratch, output),
            raw_result_paths=sorted(
                path.relative_to(output).as_posix()
                for path in output.rglob("*")
                if path.is_file()
            ),
        )
    snapshot_sha256 = source_tree_sha256(source)
    if operation == "config-rules":
        return _manifest(
            operation,
            status="completed",
            tool_name="config-rules",
            tool_version=RULESET_VERSION,
            candidates=scan_config(
                source,
                snapshot_sha256=snapshot_sha256,
            ),
        )
    if operation in TOOL_SPECS:
        result = run_external_scanner(
            operation,
            source,
            scratch,
            output,
            snapshot_sha256=snapshot_sha256,
        )
        return _manifest(operation, **result)
    return _manifest(
        operation,
        status="completed",
        tool_name="cairn-template-probe",
        tool_version="1.0.0",
    )


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    operation = arguments[0] if arguments else "default"
    source = Path("/work/source")
    scratch = Path("/work/scratch")
    output = Path("/work/output")
    if not source.is_dir() or not scratch.is_dir() or not output.is_dir():
        return 70
    if operation == "default":
        template = Path(sys.argv[0]).name.removeprefix("run-")
        _write_json(
            output / "template-result.json",
            {
                "contract": "cairn-sandbox-template-v1",
                "status": "ready",
                "template": template,
            },
        )
        return 0
    try:
        result = run_operation(
            operation,
            source=source,
            scratch=scratch,
            output=output,
        )
    except Exception:
        result = _manifest(
            operation,
            status="failed",
            tool_name="cairn-analysis-runner",
            tool_version=None,
            reason_code="ANALYSIS_INTERNAL_FAILURE",
        )
    _write_json(output / "manifest.json", result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
