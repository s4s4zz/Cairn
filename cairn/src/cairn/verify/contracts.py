"""Output contract for the Independent Reviewer (§7.8, §13.6).

The blind reviewer answers one question about one candidate: does the weakness
hold. Its answer is not a finding — the candidate already exists — so this
contract carries a verdict and the evidence for it, not a new candidate.

Two rules make the verdict falsifiable rather than an opinion, and both are
enforced here against untrusted model output:

**A confirmation requires a chain the reviewer rebuilt itself.** §7.8 says the
independent worker "自行重建调用链" — it reconstructs the call chain rather than
inheriting one. It never receives the original's chain (see
:class:`~cairn.sandbox.contracts.VerifyCandidateSpec`, whose shape cannot carry
it), so a ``confirmed`` verdict with fewer than two traced steps means the work
was not done. That verdict is downgraded to ``inconclusive``.

**A rejection must name what stops the attack.** "I do not think this is
exploitable" is not a result anyone can check. A ``rejected`` verdict that
names no defeating control is likewise downgraded to ``inconclusive``.

Downgrading rather than discarding matters: §7.7's rule that a missing or
unusable verification yields ``inconclusive`` and never ``rejected`` applies to
this stage too. A reviewer that produces nothing usable must not be able to
delete a candidate.
"""

from __future__ import annotations

from typing import Literal

from pydantic import Field, model_validator

from cairn.analysis.contracts import CallChainStep, StrictModel, ToolStatus
from cairn.analysis.normalizers import NormalizationError, SourceCatalog
from cairn.semantic.findings import is_blank

VERIFY_CONTRACT = "cairn-verify-result-v1"
VERIFY_TOOL_NAME = "independent-reviewer"

REASON_OUTPUT_INVALID = "VERIFY_OUTPUT_INVALID"
REASON_MODEL_REFUSED = "VERIFY_MODEL_REFUSED"
REASON_MODEL_UNAVAILABLE = "VERIFY_MODEL_UNAVAILABLE"
REASON_OUTPUT_INCOMPLETE = "VERIFY_OUTPUT_INCOMPLETE"
REASON_TURN_LIMIT = "VERIFY_TURN_LIMIT_REACHED"
REASON_TOOL_BUDGET = "VERIFY_TOOL_BUDGET_REACHED"

WARN_NO_REBUILT_CHAIN = "VERIFY_CONFIRMED_WITHOUT_CHAIN"
WARN_NO_DEFEATING_CONTROL = "VERIFY_REJECTED_WITHOUT_CONTROL"

MIN_CHAIN_STEPS = 2


class IndependentVerdict(StrictModel):
    """One blind reviewer's conclusion about one candidate."""

    verdict: Literal["confirmed", "rejected", "inconclusive"]
    reasoning: str = Field(min_length=1, max_length=16_384)
    reachability: str = Field(min_length=1, max_length=8192)
    call_chain: list[CallChainStep] = Field(default_factory=list, max_length=64)
    defeating_control: str | None = Field(default=None, max_length=8192)


class VerifyUsage(StrictModel):
    input_tokens: int = Field(default=0, ge=0)
    output_tokens: int = Field(default=0, ge=0)
    cache_read_input_tokens: int = Field(default=0, ge=0)
    cache_creation_input_tokens: int = Field(default=0, ge=0)
    requests: int = Field(default=0, ge=0)


class VerifyResult(StrictModel):
    """Per-candidate manifest, mirroring the semantic review manifest."""

    contract: Literal["cairn-verify-result-v1"]
    status: ToolStatus
    tool_name: str = Field(min_length=1, max_length=128)
    model: str = Field(min_length=1, max_length=255)
    root_cause_key: str = Field(min_length=1, max_length=128)
    reason_code: str | None = Field(default=None, max_length=128)
    verdict: IndependentVerdict | None = None
    warnings: list[dict[str, object]] = Field(default_factory=list, max_length=64)
    usage: VerifyUsage = Field(default_factory=VerifyUsage)

    @model_validator(mode="after")
    def validate_status_payload(self) -> "VerifyResult":
        if self.status is ToolStatus.COMPLETED:
            if self.reason_code is not None:
                raise ValueError("completed result cannot contain reason_code")
            if self.verdict is None:
                raise ValueError("completed result requires a verdict")
        else:
            if not self.reason_code:
                raise ValueError("non-completed result requires reason_code")
            if self.verdict is not None:
                raise ValueError("non-completed result cannot carry a verdict")
        return self


def parse_verdict(
    payload: object,
    *,
    catalog: SourceCatalog,
) -> tuple[IndependentVerdict, list[tuple[str, str]]]:
    """Validate a model answer into a verdict, downgrading unsupported claims.

    Returns the verdict and the downgrades applied, as ``(reason_code, detail)``
    pairs the caller records as warnings. Raises :class:`ValueError` only when
    the payload is not a verdict at all — an unusable answer becomes the
    caller's ``inconclusive`` result, never a rejection.
    """

    if not isinstance(payload, dict):
        raise ValueError("verdict payload is not an object")
    fields = {key: payload.get(key) for key in _VERDICT_KEYS if key in payload}
    chain = fields.get("call_chain")
    if isinstance(chain, list):
        # Every rebuilt step is re-resolved against the Snapshot in strict mode:
        # a chain that cites a line the source does not have is not a chain.
        resolved: list[dict[str, object]] = []
        for step in chain:
            if not isinstance(step, dict):
                raise ValueError("call chain step is not an object")
            resolved.append(_step_dict(step, catalog=catalog))
        fields["call_chain"] = resolved

    verdict = IndependentVerdict.model_validate(fields)
    downgrades: list[tuple[str, str]] = []

    if verdict.verdict == "confirmed" and len(verdict.call_chain) < MIN_CHAIN_STEPS:
        downgrades.append(
            (
                WARN_NO_REBUILT_CHAIN,
                "confirmed without an independently rebuilt entrypoint-to-sink chain",
            )
        )
        verdict = verdict.model_copy(update={"verdict": "inconclusive"})
    elif verdict.verdict == "rejected" and is_blank(verdict.defeating_control or ""):
        # `is_blank` rather than `.strip()`: U+200B is not whitespace, so a
        # "control" that renders as nothing would otherwise pass and let a
        # candidate be deleted on no stated grounds.
        downgrades.append(
            (
                WARN_NO_DEFEATING_CONTROL,
                "rejected without naming the control that defeats the attack",
            )
        )
        verdict = verdict.model_copy(update={"verdict": "inconclusive"})

    return verdict, downgrades


_VERDICT_KEYS = (
    "verdict",
    "reasoning",
    "reachability",
    "call_chain",
    "defeating_control",
)
_STEP_KEYS = frozenset({"path", "start_line", "end_line", "symbol", "role", "note"})


def _step_dict(step: dict[object, object], *, catalog: SourceCatalog) -> dict[str, object]:
    fields = {
        str(key): value for key, value in step.items() if str(key) in _STEP_KEYS
    }
    try:
        resolved = catalog.location(
            fields.get("path"),
            fields.get("start_line"),
            fields.get("end_line"),
            symbol=fields.get("symbol"),
            role=str(fields.get("role") or ""),
            strict=True,
        )
    except NormalizationError as exc:
        raise ValueError(str(exc)) from exc
    note = fields.get("note")
    if isinstance(note, str) and note.strip():
        resolved["note"] = note
    resolved.pop("start_column", None)
    resolved.pop("end_column", None)
    return resolved


def verify_output_schema() -> dict[str, object]:
    """JSON Schema for ``output_config.format``.

    Only the supported subset, for the same reason as
    :func:`cairn.semantic.contracts.semantic_output_schema`: the SDK strips
    ``minItems``/``minLength``, so the schema shapes the answer and
    :func:`parse_verdict` is the gate.
    """

    step_schema: dict[str, object] = {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "path": {
                "type": "string",
                "description": (
                    "Snapshot-relative POSIX path, exactly as the tools give it."
                ),
            },
            "start_line": {"type": "integer"},
            "end_line": {"type": "integer"},
            "symbol": {
                "type": "string",
                "description": "Class and method containing this step.",
            },
            "role": {
                "type": "string",
                "enum": ["entrypoint", "source", "propagation", "sink"],
            },
            "note": {
                "type": ["string", "null"],
                "description": "How tainted data moves through this step.",
            },
        },
        "required": ["path", "start_line", "end_line", "symbol", "role", "note"],
    }
    return {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "verdict": {
                "type": "string",
                "description": (
                    "'confirmed' only when you traced the path yourself; "
                    "'rejected' only when you can name the control that stops "
                    "it; 'inconclusive' whenever the code does not settle it."
                ),
                "enum": ["confirmed", "rejected", "inconclusive"],
            },
            "reasoning": {
                "type": "string",
                "description": (
                    "What you read and what it establishes. Cite files and "
                    "lines."
                ),
            },
            "reachability": {
                "type": "string",
                "description": (
                    "How external input reaches the reported location, or why "
                    "it cannot."
                ),
            },
            "call_chain": {
                "type": "array",
                "description": (
                    "The entrypoint-to-sink chain you traced yourself. Required "
                    "for 'confirmed'; a confirmation without at least two steps "
                    "is downgraded to 'inconclusive'."
                ),
                "items": step_schema,
            },
            "defeating_control": {
                "type": ["string", "null"],
                "description": (
                    "The specific control that stops the attack, with file and "
                    "line. Required for 'rejected'; a rejection without one is "
                    "downgraded to 'inconclusive'."
                ),
            },
        },
        "required": [
            "verdict",
            "reasoning",
            "reachability",
            "call_chain",
            "defeating_control",
        ],
    }
