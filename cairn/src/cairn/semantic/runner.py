"""In-container entry point for the Semantic Reviewer (design spec §9.7).

This runs inside the `semantic` Sandbox template, on the internal analysis
network, with the source tree mounted read-only. It mirrors
`cairn.analysis.runner`: same `/work/source` `/work/scratch` `/work/output`
contract, same atomic write, same "always emit a manifest" discipline so a
crash is reported as a terminal status rather than as a missing file.

Two things differ, and both are security properties rather than conveniences:

* The review assignment arrives as a file the Sandbox Manager placed in
  scratch, not as an argument the container could be talked into changing.
* The grant token arrives in the environment and is removed from it before any
  tool runs, so nothing the reviewer later executes can read the credential
  back out of `os.environ` or `/proc/self/environ`.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import sys

from cairn.analysis.normalizers import NormalizationError
from cairn.analysis.tree_hash import source_tree_sha256
from cairn.semantic.broker import BrokerError, ToolBroker
from cairn.semantic.client import DEFAULT_MODEL, SemanticModelClient
from cairn.semantic.contracts import (
    REASON_MODEL_UNAVAILABLE,
    REASON_OUTPUT_INVALID,
    SEMANTIC_CONTRACT,
    SEMANTIC_TOOL_NAME,
    SemanticReviewResult,
    SemanticUsage,
    ToolStatus,
)
from cairn.semantic.findings import ReviewScope, to_candidates
from cairn.semantic.review import SemanticReviewer

SCOPE_FILENAME = "cairn-semantic-scope.json"
RESULT_FILENAME = "semantic-result.json"
GRANT_ENV = "CAIRN_LLM_GRANT_TOKEN"
GATEWAY_ENV = "CAIRN_LLM_GATEWAY_URL"
MAX_TURNS_ENV = "CAIRN_SEMANTIC_MAX_TURNS"
MAX_TOKENS_ENV = "CAIRN_SEMANTIC_MAX_OUTPUT_TOKENS"

REASON_SCOPE_INVALID = "SEMANTIC_SCOPE_INVALID"
REASON_GRANT_MISSING = "SEMANTIC_GRANT_MISSING"
REASON_SOURCE_INVALID = "SEMANTIC_SOURCE_INVALID"


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


def _failed(scope_key: str, reason_code: str) -> SemanticReviewResult:
    """A terminal result carrying no findings.

    Emitted instead of raising so the Orchestrator sees a well-formed
    `cairn-semantic-result-v1` and records a coverage warning, rather than an
    empty output directory it has to guess about.
    """

    return SemanticReviewResult(
        contract=SEMANTIC_CONTRACT,
        status=ToolStatus.FAILED,
        tool_name=SEMANTIC_TOOL_NAME,
        model=DEFAULT_MODEL,
        scope_key=scope_key,
        reason_code=reason_code,
        findings=[],
        rejections=[],
        warnings=[],
        usage=SemanticUsage(
            input_tokens=0,
            output_tokens=0,
            cache_read_input_tokens=0,
            cache_creation_input_tokens=0,
            requests=0,
        ),
    )


def load_scope(scratch: Path) -> ReviewScope:
    """Read the assignment the Sandbox Manager wrote into scratch.

    Fails closed: a missing, unreadable, non-JSON or non-conforming file means
    the reviewer has no idea what it was asked to audit, and guessing a scope
    would produce findings attributed to work nobody requested.
    """

    path = scratch / SCOPE_FILENAME
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError("semantic scope file is unreadable") from exc
    try:
        payload = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("semantic scope file is not valid JSON") from exc
    if not isinstance(payload, dict):
        raise ValueError("semantic scope file is not an object")
    return ReviewScope.model_validate(payload)


def take_credentials() -> tuple[str, str]:
    """Read the grant and Gateway origin, then remove both from the environment.

    §9.5 keeps long-term keys out of the worker entirely; this keeps the
    short-lived grant out of the worker's *environment* for all but the moment
    it takes to construct the client. Nothing the reviewer runs afterwards —
    including any tool — can read it back.
    """

    grant = os.environ.pop(GRANT_ENV, "")
    gateway_url = os.environ.pop(GATEWAY_ENV, "")
    if not grant.strip() or not gateway_url.strip():
        raise ValueError("semantic grant or Gateway origin is missing")
    return grant, gateway_url


def _positive_env(name: str, default: int) -> int:
    raw = os.environ.get(name, "")
    if not raw.isdigit():
        return default
    value = int(raw)
    return value if value > 0 else default


def run(source: Path, scratch: Path, output: Path) -> SemanticReviewResult:
    scope_key = "unknown"
    try:
        scope = load_scope(scratch)
        scope_key = scope.scope_key
    except (ValueError, OSError):
        return _failed(scope_key, REASON_SCOPE_INVALID)
    try:
        grant, gateway_url = take_credentials()
    except ValueError:
        return _failed(scope_key, REASON_GRANT_MISSING)
    try:
        broker = ToolBroker(source)
    except BrokerError:
        return _failed(scope_key, REASON_SOURCE_INVALID)

    max_tokens = _positive_env(MAX_TOKENS_ENV, 16000)
    try:
        client = SemanticModelClient(
            base_url=gateway_url,
            grant_token=grant,
            max_tokens=max_tokens,
        )
    except (ImportError, ValueError):
        # ImportError included deliberately: an image built without the
        # `semantic` extra has no SDK, and letting that propagate would leave
        # an empty output directory instead of a reported terminal status.
        return _failed(scope_key, REASON_MODEL_UNAVAILABLE)
    del grant

    reviewer = SemanticReviewer(
        client,
        broker,
        scope=scope,
        max_turns=_positive_env(MAX_TURNS_ENV, 24),
    )
    result = reviewer.run()
    if not result.findings:
        return result
    # Candidates are derived here, not by the Orchestrator: identity depends on
    # the Snapshot tree hash and every location is re-resolved against the
    # source, and the source exists only inside this container. This is exactly
    # what the deterministic runner does with scanner output.
    try:
        candidates = to_candidates(
            list(result.findings),
            catalog=broker.catalog,
            snapshot_sha256=source_tree_sha256(source),
        )
    except (NormalizationError, ValueError):
        # The findings and the Snapshot disagree. Emitting a candidate that
        # points somewhere unverified is worse than emitting none.
        return result.model_copy(
            update={
                "status": ToolStatus.FAILED,
                "reason_code": REASON_OUTPUT_INVALID,
                "findings": [],
                "candidates": [],
            }
        )
    return result.model_copy(update={"candidates": candidates})


def main(argv: list[str] | None = None) -> int:
    """Entry point for the `semantic` image, dispatching on the operation.

    The image hosts both model-backed reviewers: they have identical
    permissions (read-only source, the Tool Broker, the Gateway, nothing else),
    so §9.7 gives no reason to build a second image with the same rights.
    `TemplateRegistry.resolve` appends the operation to the command, so the
    routing key arrives as `argv[0]` here — the same shape
    `cairn.analysis.runner` uses for its scanner profiles.

    The import is function-local because `cairn.verify.runner` imports this
    module for the credential handling; at module scope the two would cycle.
    """

    arguments = list(sys.argv[1:] if argv is None else argv)
    operation = arguments[0] if arguments else "semantic"
    if operation == "independent-verify":
        from cairn.verify.runner import main as verify_main

        return verify_main(arguments)

    source = Path("/work/source")
    scratch = Path("/work/scratch")
    output = Path("/work/output")
    if not source.is_dir() or not scratch.is_dir() or not output.is_dir():
        return 70
    result = run(source, scratch, output)
    _write_json(output / RESULT_FILENAME, result.model_dump(mode="json"))
    # A refused or failed review is a reported outcome, not a crashed
    # container: the Orchestrator reads the status out of the manifest and
    # turns it into a coverage warning.
    return 0


if __name__ == "__main__":  # pragma: no cover - container entry point
    sys.exit(main())
