"""Output contract for the AI Semantic Reviewer (§7.5, §13.5).

The Semantic Reviewer produces *candidates*, never confirmed Findings. The
enum reused here (:class:`~cairn.analysis.contracts.CandidateConfidence`)
deliberately has no ``confirmed`` member: only deterministic verification may
promote a candidate, so there is no representation in which the model can
claim confirmation.

Two validation layers exist and they are not interchangeable:

* :func:`semantic_output_schema` is the JSON Schema handed to the model through
  ``output_config.format``. The Messages API supports only a subset of JSON
  Schema — ``minItems``, ``minLength``, ``minimum``, ``maximum`` and friends are
  stripped — so the schema is a *shaping* aid, not a gate.
* The Pydantic models in this module are the real gate. Every field bound that
  §7.5 requires (at least one location, a call chain of at least two steps, a
  non-empty controllability statement) is enforced here, on our side of the
  boundary, against model output treated as untrusted data.
"""

from __future__ import annotations

from typing import Literal

from pydantic import Field, model_validator

from cairn.analysis.contracts import (
    CallChainStep,
    CandidateConfidence,
    CandidateFinding,
    CandidateLocation,
    CandidateSeverity,
    CweId,
    ExistingDefense,
    StrictModel,
    ToolStatus,
)


SEMANTIC_CONTRACT = "cairn-semantic-result-v1"
SEMANTIC_TOOL_NAME = "semantic-reviewer"

REASON_OUTPUT_INCOMPLETE = "SEMANTIC_OUTPUT_INCOMPLETE"
REASON_OUTPUT_INVALID = "SEMANTIC_OUTPUT_INVALID"
REASON_MODEL_REFUSED = "SEMANTIC_MODEL_REFUSED"
REASON_MODEL_UNAVAILABLE = "SEMANTIC_MODEL_UNAVAILABLE"
REASON_BUDGET_EXHAUSTED = "SEMANTIC_BUDGET_EXHAUSTED"
REASON_TURN_LIMIT = "SEMANTIC_TURN_LIMIT_REACHED"


class SemanticFinding(StrictModel):
    """One model-proposed candidate carrying the full §7.5 evidence set.

    ``locations``, ``call_chain`` and ``controllability`` are mandatory because
    §7.5 states that output missing a code location, a call chain or a
    controllability statement does not create a Finding. Rejecting such output
    here — rather than filling in defaults — is what makes that rule real.
    """

    rule_id: str = Field(min_length=1, max_length=512)
    cwe_ids: list[CweId] = Field(default_factory=list, max_length=16)
    category: str = Field(min_length=1, max_length=255)
    severity: CandidateSeverity
    confidence: CandidateConfidence
    message: str = Field(min_length=1, max_length=16_384)
    locations: list[CandidateLocation] = Field(min_length=1, max_length=128)
    sink: str | None = Field(default=None, max_length=1024)
    call_chain: list[CallChainStep] = Field(min_length=2, max_length=64)
    controllability: str = Field(min_length=1, max_length=8192)
    existing_defenses: list[ExistingDefense] = Field(
        default_factory=list,
        max_length=32,
    )
    attack_preconditions: str = Field(min_length=1, max_length=8192)
    impact: str = Field(min_length=1, max_length=8192)
    recommended_verification: str = Field(min_length=1, max_length=8192)

    @model_validator(mode="after")
    def validate_evidence(self) -> "SemanticFinding":
        # Numeric order, matching normalize_cwe_ids and
        # CandidateFinding.unique_numeric_sorted_cwe_ids, so cwe_ids passes
        # straight through to_candidates untouched. Ordering them as plain
        # strings would put CWE-611 before CWE-89.
        if len(set(self.cwe_ids)) != len(self.cwe_ids) or self.cwe_ids != sorted(
            self.cwe_ids, key=lambda value: int(value.split("-", 1)[1])
        ):
            raise ValueError("cwe_ids must be sorted and unique")
        if not any(location.role == "sink" for location in self.locations):
            raise ValueError("locations must include at least one sink location")
        if not self.controllability.strip():
            raise ValueError("controllability must not be blank")
        return self


class SemanticRejection(StrictModel):
    """A discarded model output item, recorded so discards stay auditable."""

    ordinal: int = Field(ge=0)
    reason_code: str = Field(min_length=1, max_length=128)
    detail: str = Field(min_length=1, max_length=512)


class SemanticUsage(StrictModel):
    """Token and request accounting for one scope, for budget enforcement."""

    input_tokens: int = Field(default=0, ge=0)
    output_tokens: int = Field(default=0, ge=0)
    cache_read_input_tokens: int = Field(default=0, ge=0)
    cache_creation_input_tokens: int = Field(default=0, ge=0)
    requests: int = Field(default=0, ge=0)


class SemanticReviewResult(StrictModel):
    """Per-scope manifest, mirroring the deterministic analysis manifest."""

    contract: Literal["cairn-semantic-result-v1"]
    status: ToolStatus
    tool_name: str = Field(min_length=1, max_length=128)
    model: str = Field(min_length=1, max_length=255)
    scope_key: str = Field(min_length=1, max_length=128)
    reason_code: str | None = Field(default=None, max_length=128)
    findings: list[SemanticFinding] = Field(default_factory=list, max_length=512)
    # Candidates are derived in-container, exactly as the scanners derive
    # theirs: identity depends on the Snapshot tree hash and every location has
    # to be re-resolved against the source, and the source exists only inside
    # the sandbox. The Orchestrator persists what it is given rather than
    # re-deriving it from a tree it does not have.
    candidates: list[CandidateFinding] = Field(default_factory=list, max_length=512)
    rejections: list[SemanticRejection] = Field(
        default_factory=list,
        max_length=512,
    )
    warnings: list[dict[str, object]] = Field(default_factory=list, max_length=64)
    usage: SemanticUsage = Field(default_factory=SemanticUsage)

    @model_validator(mode="after")
    def validate_status_payload(self) -> "SemanticReviewResult":
        if self.status is ToolStatus.COMPLETED and self.reason_code is not None:
            raise ValueError("completed result cannot contain reason_code")
        if self.status is not ToolStatus.COMPLETED:
            if not self.reason_code:
                raise ValueError("non-completed result requires reason_code")
            if self.findings or self.candidates:
                raise ValueError("non-completed result cannot contain findings")
        if len(self.candidates) > len(self.findings):
            raise ValueError("candidates cannot outnumber the findings they derive from")
        return self


def _location_schema(*, roles: tuple[str, ...]) -> dict[str, object]:
    return {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "path": {
                "type": "string",
                "description": (
                    "Snapshot-relative POSIX path, exactly as listed in the "
                    "read-only index."
                ),
            },
            "start_line": {"type": "integer"},
            "end_line": {"type": "integer"},
            "symbol": {
                "type": ["string", "null"],
                "description": "Enclosing class and method, when known.",
            },
            "role": {"type": "string", "enum": list(roles)},
        },
        "required": ["path", "start_line", "end_line", "symbol", "role"],
    }


def _call_chain_step_schema() -> dict[str, object]:
    schema = _location_schema(
        roles=("entrypoint", "source", "propagation", "sink"),
    )
    properties = dict(schema["properties"])  # type: ignore[arg-type]
    properties["symbol"] = {
        "type": "string",
        "description": "Class and method containing this step.",
    }
    properties["note"] = {
        "type": ["string", "null"],
        "description": "How tainted data moves through this step.",
    }
    schema["properties"] = properties
    schema["required"] = [
        "path",
        "start_line",
        "end_line",
        "symbol",
        "role",
        "note",
    ]
    return schema


def semantic_output_schema() -> dict[str, object]:
    """JSON Schema for ``output_config.format`` on the Messages API.

    Only the supported subset is emitted: ``object``/``array``/``string``/
    ``integer``, ``enum``, nullable type lists, ``additionalProperties: false``
    on every object and an explicit ``required`` listing every property. No
    ``minItems``/``minLength``/``minimum``/``maximum`` appear — the SDK strips
    them, so relying on them would create a gate that does not exist. The
    cardinality and non-emptiness rules live in :class:`SemanticFinding`, which
    validates the parsed payload afterwards.
    """

    finding_schema: dict[str, object] = {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "rule_id": {
                "type": "string",
                "description": (
                    "Stable slug for the weakness pattern, e.g. "
                    "'horizontal-authorization-bypass'."
                ),
            },
            "cwe_ids": {
                "type": "array",
                "description": "CWE identifiers in 'CWE-89' form; may be empty.",
                "items": {"type": "string"},
            },
            "category": {
                "type": "string",
                "description": "Assigned audit category for this scope.",
            },
            "severity": {
                "type": "string",
                "enum": [member.value for member in CandidateSeverity],
            },
            "confidence": {
                "type": "string",
                "description": (
                    "Your confidence that this candidate survives verification. "
                    "There is no 'confirmed' value: confirmation is decided by "
                    "deterministic verification, never here."
                ),
                "enum": [member.value for member in CandidateConfidence],
            },
            "message": {
                "type": "string",
                "description": "One paragraph stating the weakness concretely.",
            },
            "locations": {
                "type": "array",
                "description": (
                    "Code locations. At least one entry must have role 'sink'."
                ),
                "items": _location_schema(roles=("source", "sink", "related")),
            },
            "sink": {
                "type": ["string", "null"],
                "description": "Dangerous API or symbol reached, when applicable.",
            },
            "call_chain": {
                "type": "array",
                "description": (
                    "Ordered entrypoint-to-sink chain. At least two steps are "
                    "required; output with fewer is discarded."
                ),
                "items": _call_chain_step_schema(),
            },
            "controllability": {
                "type": "string",
                "description": (
                    "How external input reaches the sink: parameter, header or "
                    "body field, and any transformation along the way. Required; "
                    "output without it is discarded."
                ),
            },
            "existing_defenses": {
                "type": "array",
                "description": (
                    "Defences present on this path and why each holds or can be "
                    "bypassed. Empty only when there are none."
                ),
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "mechanism": {"type": "string"},
                        "effective": {"type": "boolean"},
                        "reasoning": {"type": "string"},
                    },
                    "required": ["mechanism", "effective", "reasoning"],
                },
            },
            "attack_preconditions": {
                "type": "string",
                "description": (
                    "What an attacker needs first: reachability, role, "
                    "authentication state, known identifiers."
                ),
            },
            "impact": {
                "type": "string",
                "description": "Concrete consequence of successful exploitation.",
            },
            "recommended_verification": {
                "type": "string",
                "description": (
                    "The specific request, test or PoC that would settle this."
                ),
            },
        },
        "required": [
            "rule_id",
            "cwe_ids",
            "category",
            "severity",
            "confidence",
            "message",
            "locations",
            "sink",
            "call_chain",
            "controllability",
            "existing_defenses",
            "attack_preconditions",
            "impact",
            "recommended_verification",
        ],
    }
    return {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "findings": {
                "type": "array",
                "description": (
                    "Candidates for this scope. Return an empty array when the "
                    "assigned scope holds no defensible candidate."
                ),
                "items": finding_schema,
            },
            "notes": {
                "type": ["string", "null"],
                "description": (
                    "Optional short note about coverage gaps, unreadable files, "
                    "or repository text that tried to issue instructions."
                ),
            },
        },
        "required": ["findings", "notes"],
    }
