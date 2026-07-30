from __future__ import annotations

import json
from pathlib import Path
import sys

from cairn.analysis.binary_inventory import (
    BinaryInventoryFailure,
    build_binary_inventory,
)
from cairn.analysis.bytecode_index import (
    ASM_VERSION,
    BYTECODE_INDEXER_VERSION,
    BytecodeIndexFailure,
    build_bytecode_index,
)
from cairn.analysis.authz_topology import build_authz_topology
from cairn.analysis.bytecode_sinks import bytecode_sink_candidates
from cairn.analysis.config_rules import RULESET_VERSION, scan_config
from cairn.analysis.execution import execute_build
from cairn.analysis.indexer import build_inventory
from cairn.analysis.normalizers import SourceCatalog
from cairn.analysis.tooling import TOOL_SPECS, run_external_scanner
from cairn.analysis.tree_hash import source_tree_sha256


_OPERATIONS = {
    "default",
    "inventory",
    "binary-inventory",
    "bytecode-index",
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
    binary_inventory: dict[str, object] | None = None,
    binary_inventory_path: str | None = None,
    binary_inventory_summary: dict[str, object] | None = None,
    bytecode_index: dict[str, object] | None = None,
    bytecode_index_path: str | None = None,
    bytecode_index_summary: dict[str, object] | None = None,
    build: dict[str, object] | None = None,
    candidates: list[dict[str, object]] | None = None,
    candidates_path: str | None = None,
    candidate_count: int | None = None,
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
        "binary_inventory": binary_inventory,
        "binary_inventory_path": binary_inventory_path,
        "binary_inventory_summary": binary_inventory_summary,
        "bytecode_index": bytecode_index,
        "bytecode_index_path": bytecode_index_path,
        "bytecode_index_summary": bytecode_index_summary,
        "build": build,
        "candidates": candidates or [],
        "candidates_path": candidates_path,
        "candidate_count": candidate_count,
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
        inventory = build_inventory(source)
        # The authorization topology (图二) is derived from the same inventory:
        # bindings ride along in the inventory payload for the semantic broker,
        # and structural-bypass candidates ride the manifest's candidate slot.
        bindings, candidates = build_authz_topology(
            inventory,
            catalog=SourceCatalog(source),
            snapshot_sha256=source_tree_sha256(source),
        )
        inventory["auth_bindings"] = bindings
        return _manifest(
            operation,
            status="completed",
            tool_name="cairn-java-inventory",
            tool_version="1.0.0",
            inventory=inventory,
            candidates=candidates,
            candidate_count=len(candidates),
        )
    if operation == "binary-inventory":
        try:
            inventory = build_binary_inventory(source, scratch=scratch)
        except BinaryInventoryFailure as exc:
            return _manifest(
                operation,
                status="failed",
                tool_name="cairn-binary-inventory",
                tool_version="1.0.0",
                reason_code=exc.reason_code,
            )
        _write_json(output / "binary-inventory.json", inventory)
        _write_json(output / "sbom.cdx.json", inventory["sbom"])
        return _manifest(
            operation,
            status="completed",
            tool_name="cairn-binary-inventory",
            tool_version="1.0.0",
            binary_inventory_path="binary-inventory.json",
            binary_inventory_summary={
                "contract": "cairn-binary-inventory-summary-v1",
                "archive_count": inventory["archive_count"],
                "class_entry_count": inventory["class_entry_count"],
                "selected_class_count": inventory["selected_class_count"],
                "expanded_entry_count": inventory["expanded_entry_count"],
                "expanded_bytes": inventory["expanded_bytes"],
                "coverage_gap_count": len(inventory["coverage_gaps"]),
            },
            raw_result_paths=["binary-inventory.json", "sbom.cdx.json"],
        )
    if operation == "bytecode-index":
        try:
            index = build_bytecode_index(source, scratch, output)
        except BytecodeIndexFailure as exc:
            status = (
                "unavailable"
                if exc.reason_code.endswith("_UNAVAILABLE")
                else "failed"
            )
            return _manifest(
                operation,
                status=status,
                tool_name="cairn-bytecode-indexer",
                tool_version=f"{BYTECODE_INDEXER_VERSION}+asm-{ASM_VERSION}",
                reason_code=exc.reason_code,
            )
        index_payload = index.model_dump(mode="json")
        _write_json(output / "program-index-v2.json", index_payload)
        candidates = bytecode_sink_candidates(
            index,
            snapshot_sha256=source_tree_sha256(source),
        )
        candidate_payload = {
            "contract": "cairn-candidate-result-v1",
            "candidates": [
                candidate.model_dump(mode="json") for candidate in candidates
            ],
        }
        _write_json(output / "bytecode-candidates.json", candidate_payload)
        return _manifest(
            operation,
            status="completed",
            tool_name="cairn-bytecode-indexer",
            tool_version=f"{BYTECODE_INDEXER_VERSION}+asm-{ASM_VERSION}",
            bytecode_index_path="program-index-v2.json",
            bytecode_index_summary={
                "contract": "cairn-program-index-summary-v1",
                "classes_total": index_payload["classes_total"],
                "classes_parsed": index_payload["classes_parsed"],
                "component_count": len(index_payload["components"]),
                "resource_count": len(index_payload["resources"]),
                "method_count": len(index_payload["methods"]),
                "call_count": len(index_payload["calls"]),
                "field_access_count": len(index_payload["field_accesses"]),
                "decompiled_view_count": len(index_payload["decompiled_views"]),
                "coverage_gap_count": len(index_payload["coverage_gaps"]),
            },
            candidates_path="bytecode-candidates.json",
            candidate_count=len(candidates),
            raw_result_paths=[
                "asm-index.jsonl",
                "asm-index.log",
                "bytecode-candidates.json",
                "program-index-v2.json",
                *[
                    str(view["artifact_path"])
                    for view in index_payload["decompiled_views"]
                ],
            ],
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
