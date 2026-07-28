"""In-container entry point for the PoC Author (§7.7, §9.7).

Runs inside the `semantic` Sandbox template under the `author-poc` operation:
read-only source, the Tool Broker, the LLM Gateway, and no target application.
Same `/work/source` `/work/scratch` `/work/output` contract as the other
runners, and the same always-emit-a-manifest discipline.

The credential handling is reused wholesale from `cairn.semantic.runner`: the
grant arrives in the environment and is removed before any tool runs.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import sys

from cairn.semantic.broker import BrokerError, ToolBroker
from cairn.semantic.client import DEFAULT_MODEL, SemanticModelClient
from cairn.semantic.runner import GATEWAY_ENV, GRANT_ENV, take_credentials
from cairn.poc.author import PocAuthor
from cairn.poc.contracts import (
    POC_CONTRACT,
    POC_TOOL_NAME,
    REASON_MODEL_UNAVAILABLE,
    PocResult,
)
from cairn.poc.prompt import PocAssignment

ASSIGNMENT_FILENAME = "cairn-poc-assignment.json"
RESULT_FILENAME = "poc-result.json"
MAX_TURNS_ENV = "CAIRN_POC_MAX_TURNS"
MAX_TOKENS_ENV = "CAIRN_POC_MAX_OUTPUT_TOKENS"

REASON_ASSIGNMENT_INVALID = "POC_ASSIGNMENT_INVALID"
REASON_GRANT_MISSING = "POC_GRANT_MISSING"
REASON_SOURCE_INVALID = "POC_SOURCE_INVALID"

_LOCATION_KEYS = ("path", "start_line", "end_line", "symbol", "role")

__all__ = [
    "ASSIGNMENT_FILENAME",
    "RESULT_FILENAME",
    "load_assignment",
    "main",
    "run",
]


def _write_json(path: Path, payload: dict[str, object]) -> None:
    temporary = path.with_suffix(f"{path.suffix}.tmp")
    temporary.write_text(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def _failed(finding_id: str, reason_code: str) -> PocResult:
    return PocResult(
        contract=POC_CONTRACT,
        status="failed",
        tool_name=POC_TOOL_NAME,
        model=DEFAULT_MODEL,
        finding_id=finding_id or "unknown",
        reason_code=reason_code,
        plan=None,
        warnings=[],
    )


def load_assignment(scratch: Path) -> PocAssignment:
    """Read the assignment the Sandbox Manager wrote into scratch. Fails closed."""

    path = scratch / ASSIGNMENT_FILENAME
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError("poc assignment file is unreadable") from exc
    try:
        payload = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("poc assignment file is not valid JSON") from exc
    if not isinstance(payload, dict):
        raise ValueError("poc assignment file is not an object")

    finding_id = str(payload.get("finding_id") or "").strip()
    category = str(payload.get("category") or "").strip()
    module = str(payload.get("module") or "").strip()
    if not finding_id or not category or not module:
        raise ValueError("poc assignment is missing its identity")

    raw_locations = payload.get("locations")
    locations: list[dict[str, object]] = []
    if isinstance(raw_locations, list):
        for entry in raw_locations:
            if isinstance(entry, dict):
                locations.append({key: entry.get(key) for key in _LOCATION_KEYS})

    cwe_ids = payload.get("cwe_ids")
    prefixes = payload.get("route_prefixes")
    sink = payload.get("sink")
    route = payload.get("route")
    return PocAssignment(
        finding_id=finding_id,
        module=module,
        category=category,
        cwe_ids=tuple(str(value) for value in cwe_ids) if isinstance(cwe_ids, list) else (),
        sink=str(sink) if isinstance(sink, str) and sink.strip() else None,
        http_method=str(payload.get("http_method") or "GET"),
        route=str(route) if isinstance(route, str) and route.strip() else None,
        route_prefixes=tuple(str(p) for p in prefixes) if isinstance(prefixes, list) else (),
        locations=tuple(locations),
    )


def _positive_env(name: str, default: int) -> int:
    raw = os.environ.get(name, "")
    if not raw.isdigit():
        return default
    value = int(raw)
    return value if value > 0 else default


def run(source: Path, scratch: Path, output: Path) -> PocResult:
    del output
    finding_id = "unknown"
    try:
        assignment = load_assignment(scratch)
        finding_id = assignment.finding_id
    except (ValueError, OSError):
        return _failed(finding_id, REASON_ASSIGNMENT_INVALID)
    try:
        grant, gateway_url = take_credentials()
    except ValueError:
        return _failed(finding_id, REASON_GRANT_MISSING)
    try:
        broker = ToolBroker(source)
    except BrokerError:
        return _failed(finding_id, REASON_SOURCE_INVALID)

    try:
        client = SemanticModelClient(
            base_url=gateway_url,
            grant_token=grant,
            max_tokens=_positive_env(MAX_TOKENS_ENV, 16000),
        )
    except (ImportError, ValueError):
        return _failed(finding_id, REASON_MODEL_UNAVAILABLE)
    del grant

    author = PocAuthor(
        client,
        broker,
        assignment=assignment,
        max_turns=_positive_env(MAX_TURNS_ENV, 16),
    )
    return author.run()


def main(argv: list[str] | None = None) -> int:
    del argv
    source = Path("/work/source")
    scratch = Path("/work/scratch")
    output = Path("/work/output")
    if not source.is_dir() or not scratch.is_dir() or not output.is_dir():
        return 70
    result = run(source, scratch, output)
    _write_json(output / RESULT_FILENAME, result.model_dump(mode="json"))
    return 0


if __name__ == "__main__":  # pragma: no cover - container entry point
    sys.exit(main())
