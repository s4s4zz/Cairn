"""In-container entry point for the Independent Reviewer (§7.8, §9.7).

Runs inside the `semantic` Sandbox template under the `independent_verify`
operation, on the internal analysis network, with the source tree mounted
read-only. Same `/work/source` `/work/scratch` `/work/output` contract as
`cairn.semantic.runner`, same atomic write, same "always emit a manifest"
discipline so a crash is reported as a terminal status rather than as a
missing file.

The assignment arrives as a file the Sandbox Manager placed in scratch, and
its shape is what enforces blindness: `VerifyCandidateSpec` has no field for
the reporting worker's reasoning, so no assignment file can carry it, however
this runner is invoked.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import sys

from cairn.analysis.contracts import ToolStatus
from cairn.semantic.broker import BrokerError, ToolBroker
from cairn.semantic.client import DEFAULT_MODEL, SemanticModelClient
from cairn.semantic.runner import (
    GATEWAY_ENV,
    GRANT_ENV,
    take_credentials,
)
from cairn.verify.contracts import (
    REASON_MODEL_UNAVAILABLE,
    VERIFY_CONTRACT,
    VERIFY_TOOL_NAME,
    VerifyResult,
    VerifyUsage,
)
from cairn.verify.prompt import VerifyAssignment
from cairn.verify.review import IndependentReviewer

ASSIGNMENT_FILENAME = "cairn-verify-candidate.json"
RESULT_FILENAME = "verify-result.json"
MAX_TURNS_ENV = "CAIRN_VERIFY_MAX_TURNS"
MAX_TOKENS_ENV = "CAIRN_VERIFY_MAX_OUTPUT_TOKENS"

REASON_ASSIGNMENT_INVALID = "VERIFY_ASSIGNMENT_INVALID"
REASON_GRANT_MISSING = "VERIFY_GRANT_MISSING"
REASON_SOURCE_INVALID = "VERIFY_SOURCE_INVALID"

_LOCATION_KEYS = ("path", "start_line", "end_line", "symbol", "role")

__all__ = [
    "ASSIGNMENT_FILENAME",
    "GATEWAY_ENV",
    "GRANT_ENV",
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


def _failed(root_cause_key: str, reason_code: str) -> VerifyResult:
    """A terminal result carrying no verdict.

    Emitted instead of raising so the Orchestrator sees a well-formed
    `cairn-verify-result-v1`. It records the absent verdict as `inconclusive`,
    which is the only thing a failed review may produce.
    """

    return VerifyResult(
        contract=VERIFY_CONTRACT,
        status=ToolStatus.FAILED,
        tool_name=VERIFY_TOOL_NAME,
        model=DEFAULT_MODEL,
        root_cause_key=root_cause_key,
        reason_code=reason_code,
        verdict=None,
        warnings=[],
        usage=VerifyUsage(),
    )


def load_assignment(scratch: Path) -> VerifyAssignment:
    """Read the candidate the Sandbox Manager wrote into scratch.

    Fails closed. Unknown keys are ignored rather than rejected, but nothing is
    read beyond the fixed list below — so even a file that somehow carried the
    reporting worker's prose could not surface it to the model.
    """

    path = scratch / ASSIGNMENT_FILENAME
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError("verify assignment file is unreadable") from exc
    try:
        payload = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("verify assignment file is not valid JSON") from exc
    if not isinstance(payload, dict):
        raise ValueError("verify assignment file is not an object")

    root_cause_key = str(payload.get("root_cause_key") or "").strip()
    category = str(payload.get("category") or "").strip()
    module = str(payload.get("module") or "").strip()
    if not root_cause_key or not category or not module:
        raise ValueError("verify assignment is missing its identity")

    raw_locations = payload.get("locations")
    if not isinstance(raw_locations, list) or not raw_locations:
        raise ValueError("verify assignment carries no locations")
    locations: list[dict[str, object]] = []
    for entry in raw_locations:
        if not isinstance(entry, dict):
            raise ValueError("verify assignment location is not an object")
        locations.append({key: entry.get(key) for key in _LOCATION_KEYS})

    cwe_ids = payload.get("cwe_ids")
    sink = payload.get("sink")
    return VerifyAssignment(
        root_cause_key=root_cause_key,
        module=module,
        category=category,
        cwe_ids=tuple(str(value) for value in cwe_ids) if isinstance(cwe_ids, list) else (),
        sink=str(sink) if isinstance(sink, str) and sink.strip() else None,
        locations=tuple(locations),
    )


def _positive_env(name: str, default: int) -> int:
    raw = os.environ.get(name, "")
    if not raw.isdigit():
        return default
    value = int(raw)
    return value if value > 0 else default


def run(source: Path, scratch: Path, output: Path) -> VerifyResult:
    del output
    root_cause_key = "unknown"
    try:
        assignment = load_assignment(scratch)
        root_cause_key = assignment.root_cause_key
    except (ValueError, OSError):
        return _failed(root_cause_key, REASON_ASSIGNMENT_INVALID)
    try:
        grant, gateway_url = take_credentials()
    except ValueError:
        return _failed(root_cause_key, REASON_GRANT_MISSING)
    try:
        broker = ToolBroker(source)
    except BrokerError:
        return _failed(root_cause_key, REASON_SOURCE_INVALID)

    try:
        client = SemanticModelClient(
            base_url=gateway_url,
            grant_token=grant,
            max_tokens=_positive_env(MAX_TOKENS_ENV, 16000),
        )
    except (ImportError, ValueError):
        # ImportError included deliberately: an image built without the
        # `semantic` extra has no SDK, and the "always emit a manifest"
        # discipline means the Orchestrator must read that as an unavailable
        # model rather than as an empty output directory it has to guess about.
        return _failed(root_cause_key, REASON_MODEL_UNAVAILABLE)
    del grant

    reviewer = IndependentReviewer(
        client,
        broker,
        assignment=assignment,
        max_turns=_positive_env(MAX_TURNS_ENV, 16),
    )
    return reviewer.run()


def main(argv: list[str] | None = None) -> int:
    del argv
    source = Path("/work/source")
    scratch = Path("/work/scratch")
    output = Path("/work/output")
    if not source.is_dir() or not scratch.is_dir() or not output.is_dir():
        return 70
    result = run(source, scratch, output)
    _write_json(output / RESULT_FILENAME, result.model_dump(mode="json"))
    # A refused or failed review is a reported outcome, not a crashed container.
    return 0


if __name__ == "__main__":  # pragma: no cover - container entry point
    sys.exit(main())
