"""Scope description and the §13.5 acceptance gate for semantic output.

Everything the model returns is untrusted data. :func:`parse_findings` is the
single place where that data becomes platform state, so it enforces the §7.5
evidence rules directly rather than trusting the JSON Schema the model was
given: the Messages API strips length and cardinality constraints from the
schema, so the schema can shape output but cannot gate it.

Two properties matter more than tolerance here:

* One malformed item costs exactly one item. Each entry is validated on its
  own, so a single bad object cannot discard the good candidates beside it.
* Nothing is repaired quietly. Paths and line ranges are resolved only through
  :class:`~cairn.analysis.normalizers.SourceCatalog`, which raises instead of
  clamping, so a location outside the Snapshot becomes a recorded rejection
  rather than a plausible-looking Finding pointing at the wrong file.
"""

from __future__ import annotations

import hashlib
import re
import unicodedata

from pydantic import Field, ValidationError, field_validator, model_validator

from cairn.analysis.contracts import RelativePath, StrictModel
from cairn.analysis.fingerprints import candidate_identity, normalize_cwe_ids
from cairn.analysis.normalizers import NormalizationError, SourceCatalog
from cairn.semantic.contracts import (
    REASON_OUTPUT_INCOMPLETE,
    REASON_OUTPUT_INVALID,
    SEMANTIC_TOOL_NAME,
    SemanticFinding,
    SemanticRejection,
)


SCOPE_KEY_PREFIX = "semantic"
SCOPE_KEY_MAX_LENGTH = 128
SCOPE_SEGMENT_MAX_LENGTH = 48
MAX_OUTPUT_ITEMS = 512
_DETAIL_MAX_LENGTH = 240
_SCOPE_DIGEST_LENGTH = 12
# Scope segments that are plain ASCII words survive slugification without loss.
# Anything else — the Chinese category names the design document uses, for
# instance — does not, and needs a digest to stay distinguishable.
_PORTABLE_SEGMENT = re.compile(r"[A-Za-z0-9 _./\-]*")
_LOCATION_KEYS = frozenset(
    {"path", "start_line", "end_line", "start_column", "end_column", "symbol", "role"}
)
_CALL_CHAIN_KEYS = frozenset(
    {"path", "start_line", "end_line", "symbol", "role", "note"}
)
# Characters that render as nothing but are not whitespace, so `str.strip`
# leaves them behind. Unicode categories Cc/Cf cover the format and control
# characters; these are the space-like ones that fall outside both.
_INVISIBLE_CHARACTERS = frozenset(
    "⠀ㅤᅟᅠ឴឵﻿᠎"
)


def _slug(value: object, *, fallback: str) -> str:
    """Slugify one scope segment without letting distinct inputs collide.

    Slugification is lossy in two ways that matter for a uniquely-constrained
    key: it drops every non-ASCII character (the design document's category
    names are Chinese, so those would slug to nothing), and it truncates long
    module paths. Either way two different scopes could produce one key and the
    second task would be lost to
    ``uq_audit_tasks_run_scope_key``. A digest of the original value is appended
    whenever the slug is not a faithful representation, which keeps the key
    readable for ASCII input and merely unique for everything else.
    """

    original = str(value or "").strip()
    rendered = re.sub(r"[^a-z0-9]+", "-", original.lower()).strip("-")
    lossless = (
        _PORTABLE_SEGMENT.fullmatch(original) is not None
        and len(rendered) <= SCOPE_SEGMENT_MAX_LENGTH
    )
    if not original:
        return fallback
    if lossless:
        return rendered or fallback
    digest = hashlib.sha256(original.encode("utf-8")).hexdigest()[
        :_SCOPE_DIGEST_LENGTH
    ]
    keep = SCOPE_SEGMENT_MAX_LENGTH - _SCOPE_DIGEST_LENGTH - 1
    prefix = rendered[:keep].strip("-") or fallback
    return f"{prefix}-{digest}"


def _detail(value: object) -> str:
    """Bound a rejection detail.

    Details are read by operators, so they must describe the defect without
    becoming a channel for arbitrary model text: whitespace collapses and the
    result is truncated hard.
    """

    rendered = re.sub(r"\s+", " ", str(value or "")).strip()
    return rendered[:_DETAIL_MAX_LENGTH] or "unspecified validation failure"


def _validation_detail(error: ValidationError) -> str:
    """Describe a validation failure using only the field path and reason.

    Pydantic also carries the offending input; it is deliberately dropped so
    model output never round-trips into our logs verbatim.
    """

    errors = error.errors()
    if not errors:
        return _detail("model output failed validation")
    first = errors[0]
    location = ".".join(str(part) for part in first.get("loc", ())) or "finding"
    return _detail(f"{location}: {first.get('msg', 'invalid value')}")


def derive_scope_key(module: object, attack_surface: object, category: object) -> str:
    """Build the deterministic ``AuditTask.scope_key`` for a review scope.

    The same triple always yields the same key, which is what makes semantic
    task identity stable across re-runs of one Snapshot. Distinct triples always
    yield distinct keys (see :func:`_slug`) and the result always fits
    ``AuditTask.scope_key``'s ``String(128)``.
    """

    segments = [
        _slug(module, fallback="module"),
        _slug(attack_surface, fallback="surface"),
        _slug(category, fallback="category"),
    ]
    key = ":".join([SCOPE_KEY_PREFIX, *segments])
    if len(key) > SCOPE_KEY_MAX_LENGTH:  # pragma: no cover - bounded by _slug
        digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
        keep = SCOPE_KEY_MAX_LENGTH - _SCOPE_DIGEST_LENGTH - 1
        key = f"{key[:keep]}-{digest[:_SCOPE_DIGEST_LENGTH]}"
    return key


class ReviewScope(StrictModel):
    """One unit of semantic review: module, attack surface and category (§7.5)."""

    module: str = Field(min_length=1, max_length=1024)
    attack_surface: str = Field(min_length=1, max_length=255)
    category: str = Field(min_length=1, max_length=255)
    scope_key: str = Field(
        default="",
        min_length=1,
        max_length=SCOPE_KEY_MAX_LENGTH,
    )
    entrypoint_paths: list[RelativePath] = Field(default_factory=list, max_length=64)

    @field_validator("module", "attack_surface", "category", mode="before")
    @classmethod
    def keep_scope_text_on_one_line(cls, value: object) -> object:
        """Keep repository-derived scope text from becoming structure.

        ``module`` reaches this object from the index, which reads it out of a
        repository-controlled ``<artifactId>``. ``scope_instruction`` renders
        it into the ``role: "system"`` operator message, so an embedded newline
        would let a repository write its own headings and directives onto the
        one channel §9.6 reserves for the platform. Collapsing every whitespace,
        control and format character to a single space leaves a label that
        cannot open a new markdown block.
        """

        if not isinstance(value, str):
            return value
        flattened = "".join(
            " "
            if character.isspace()
            or unicodedata.category(character) in {"Cc", "Cf"}
            else character
            for character in value
        )
        return " ".join(flattened.split())

    @model_validator(mode="before")
    @classmethod
    def derive_identity(cls, data: object) -> object:
        """Fill ``scope_key`` from the scope triple, or verify a supplied one.

        The key is derived rather than accepted so two runs over one Snapshot
        cannot produce two task rows for the same scope; an explicit value is
        allowed only when it matches the derivation.
        """

        if not isinstance(data, dict):
            return data
        expected = derive_scope_key(
            data.get("module"),
            data.get("attack_surface"),
            data.get("category"),
        )
        if len(expected) > SCOPE_KEY_MAX_LENGTH:  # pragma: no cover - defensive
            raise ValueError("scope_key exceeds the persisted column width")
        supplied = data.get("scope_key")
        if supplied not in (None, "") and supplied != expected:
            raise ValueError("scope_key must match the derived scope identity")
        return {**data, "scope_key": expected}


def parse_findings(
    payload: object,
    *,
    catalog: SourceCatalog,
) -> tuple[list[SemanticFinding], list[SemanticRejection]]:
    """Validate raw model output into candidates plus recorded rejections.

    Accepts either the structured-output object (``{"findings": [...]}``) or a
    bare array. Items are validated independently; the return value is the
    accepted findings and one rejection per discarded item.

    Classification follows §7.5: output missing a code location, an
    entrypoint-to-sink call chain, or a controllability statement is
    *incomplete* and never becomes a candidate; anything else that fails
    validation — unknown keys, wrong types, an unknown enum value, a location
    outside the Snapshot, an impossible line range — is *invalid*.
    """

    items, rejections = _extract_items(payload)
    findings: list[SemanticFinding] = []
    for ordinal, item in enumerate(items):
        try:
            findings.append(_parse_finding(item, catalog=catalog))
        except _RejectedItem as rejected:
            rejections.append(
                SemanticRejection(
                    ordinal=ordinal,
                    reason_code=rejected.reason_code,
                    detail=rejected.detail,
                )
            )
    return findings, rejections


def to_candidates(
    findings: list[SemanticFinding],
    *,
    catalog: SourceCatalog,
    snapshot_sha256: str,
) -> list[dict[str, object]]:
    """Convert accepted semantic findings into ``CandidateFinding`` payloads.

    Identity is computed with the same tool-agnostic helper the scanners use,
    so a semantic candidate and a scanner candidate describing one root cause
    share a ``root_cause_key`` and merge without any semantic-specific casing.

    Locations are re-resolved through the catalog. Findings that reached this
    point already passed the catalog once, so a :class:`NormalizationError`
    here means the Snapshot and the findings disagree — that propagates rather
    than being swallowed into a candidate pointing somewhere unverified.
    """

    candidates: list[dict[str, object]] = []
    for finding in findings:
        locations = [
            _location_dict(location.model_dump(), catalog=catalog)
            for location in _sink_first(finding)
        ]
        call_chain = [
            _call_chain_dict(step.model_dump(), catalog=catalog)
            for step in finding.call_chain
        ]
        # candidate_identity keys off cwe_ids[0], and the scanner normalizers
        # feed it numerically ordered ids. Matching that order is what keeps
        # root_cause_key comparable across tools; the emitted list is sorted
        # lexicographically because that is what CandidateFinding validates.
        identity_cwe_ids = normalize_cwe_ids(finding.cwe_ids)
        fingerprint, root_cause_key = candidate_identity(
            snapshot_sha256=snapshot_sha256,
            rule_id=finding.rule_id,
            cwe_ids=identity_cwe_ids,
            category=finding.category,
            primary_location=locations[0],
            sink=finding.sink,
            tool_name=SEMANTIC_TOOL_NAME,
        )
        candidate: dict[str, object] = {
            "rule_id": finding.rule_id,
            "cwe_ids": normalize_cwe_ids(finding.cwe_ids),
            "category": finding.category,
            "severity": finding.severity.value,
            "confidence": finding.confidence.value,
            "message": finding.message,
            "locations": locations,
            "sink": finding.sink,
            "fingerprint": fingerprint,
            "root_cause_key": root_cause_key,
            "discovered_by": [SEMANTIC_TOOL_NAME],
            "source_rules": [finding.rule_id],
            "call_chain": call_chain,
            "controllability": finding.controllability,
            "attack_preconditions": finding.attack_preconditions,
            "impact": finding.impact,
            "recommended_verification": finding.recommended_verification,
        }
        if finding.existing_defenses:
            candidate["existing_defenses"] = [
                defense.model_dump() for defense in finding.existing_defenses
            ]
        candidates.append(candidate)
    return candidates


class _RejectedItem(Exception):
    def __init__(self, reason_code: str, detail: str) -> None:
        super().__init__(detail)
        self.reason_code = reason_code
        self.detail = _detail(detail)


def _extract_items(payload: object) -> tuple[list[object], list[SemanticRejection]]:
    if isinstance(payload, dict):
        raw = payload.get("findings")
        if not isinstance(raw, list):
            return [], [
                SemanticRejection(
                    ordinal=0,
                    reason_code=REASON_OUTPUT_INVALID,
                    detail="model output has no findings array",
                )
            ]
    elif isinstance(payload, list):
        raw = payload
    else:
        return [], [
            SemanticRejection(
                ordinal=0,
                reason_code=REASON_OUTPUT_INVALID,
                detail="model output is not an object or an array",
            )
        ]
    if len(raw) <= MAX_OUTPUT_ITEMS:
        return list(raw), []
    return list(raw[:MAX_OUTPUT_ITEMS]), [
        SemanticRejection(
            ordinal=MAX_OUTPUT_ITEMS,
            reason_code=REASON_OUTPUT_INVALID,
            detail="model output exceeds the per-scope finding limit",
        )
    ]


def _parse_finding(item: object, *, catalog: SourceCatalog) -> SemanticFinding:
    if not isinstance(item, dict):
        raise _RejectedItem(REASON_OUTPUT_INVALID, "finding is not an object")
    _require_evidence(item)
    normalized = dict(item)
    normalized["locations"] = [
        _location_dict(entry, catalog=catalog) for entry in item["locations"]
    ]
    normalized["call_chain"] = [
        _call_chain_dict(entry, catalog=catalog) for entry in item["call_chain"]
    ]
    normalized["cwe_ids"] = normalize_cwe_ids(item.get("cwe_ids"))
    sink_locations = [
        entry for entry in normalized["locations"] if entry.get("role") == "sink"
    ]
    if not sink_locations:
        raise _RejectedItem(
            REASON_OUTPUT_INCOMPLETE,
            "locations must include at least one sink location",
        )
    # The chain has to reach the weakness it claims to describe. Without this a
    # finding can pair a sink in one file with a chain that never touches it.
    sink_paths = {str(entry["path"]) for entry in sink_locations}
    if str(normalized["call_chain"][-1]["path"]) not in sink_paths:
        raise _RejectedItem(
            REASON_OUTPUT_INCOMPLETE,
            "call chain must terminate in a declared sink location",
        )
    try:
        return SemanticFinding.model_validate(normalized)
    except ValidationError as exc:
        raise _RejectedItem(
            REASON_OUTPUT_INVALID,
            _validation_detail(exc),
        ) from exc


def _require_evidence(item: dict[object, object]) -> None:
    """Apply the §7.5 completeness rule before any other validation."""

    locations = item.get("locations")
    if not isinstance(locations, list) or not locations:
        raise _RejectedItem(
            REASON_OUTPUT_INCOMPLETE,
            "finding is missing a code location",
        )
    call_chain = item.get("call_chain")
    if not isinstance(call_chain, list) or len(call_chain) < 2:
        raise _RejectedItem(
            REASON_OUTPUT_INCOMPLETE,
            "finding is missing an entrypoint-to-sink call chain",
        )
    _require_chain_shape(call_chain)
    controllability = item.get("controllability")
    if not isinstance(controllability, str) or _is_blank(controllability):
        raise _RejectedItem(
            REASON_OUTPUT_INCOMPLETE,
            "finding is missing a controllability statement",
        )
    for field in ("message", "attack_preconditions", "impact", "recommended_verification"):
        value = item.get(field)
        if not isinstance(value, str) or _is_blank(value):
            raise _RejectedItem(
                REASON_OUTPUT_INCOMPLETE,
                f"finding is missing {field.replace('_', ' ')}",
            )


def _require_chain_shape(call_chain: list[object]) -> None:
    """Enforce that the chain actually runs entrypoint to sink.

    §7.5 asks for an 入口到 Sink 调用链. Cardinality alone does not express
    that: two identical propagation steps, or the fixture chain reversed,
    satisfy ``len(call_chain) >= 2`` while describing no path at all.
    """

    steps = []
    for entry in call_chain:
        if not isinstance(entry, dict):
            raise _RejectedItem(
                REASON_OUTPUT_INVALID,
                "call chain step is not an object",
            )
        steps.append(entry)
    if str(steps[0].get("role") or "") != "entrypoint":
        raise _RejectedItem(
            REASON_OUTPUT_INCOMPLETE,
            "call chain must begin at an entrypoint step",
        )
    if str(steps[-1].get("role") or "") != "sink":
        raise _RejectedItem(
            REASON_OUTPUT_INCOMPLETE,
            "call chain must end at a sink step",
        )
    identities = {
        (
            str(step.get("path") or ""),
            str(step.get("start_line")),
            str(step.get("symbol") or ""),
        )
        for step in steps
    }
    if len(identities) < 2:
        raise _RejectedItem(
            REASON_OUTPUT_INCOMPLETE,
            "call chain must contain at least two distinct steps",
        )


def is_blank(value: str) -> bool:
    """Report emptiness the way a reader would see it.

    ``str.strip`` removes whitespace, and U+200B ZERO WIDTH SPACE is not
    whitespace, so ``"​".strip()`` is truthy while rendering as nothing.
    Required-evidence prose that renders as nothing is missing evidence.
    """

    visible = "".join(
        character
        for character in value
        if character not in _INVISIBLE_CHARACTERS
        and unicodedata.category(character) not in {"Cc", "Cf"}
    )
    return not visible.strip()


# Kept as the module-private name the rest of this file already uses.
_is_blank = is_blank


def _location_dict(
    entry: object,
    *,
    catalog: SourceCatalog,
) -> dict[str, object]:
    fields = _entry_fields(entry, allowed=_LOCATION_KEYS)
    try:
        return catalog.location(
            fields.get("path"),
            fields.get("start_line"),
            fields.get("end_line"),
            start_column=fields.get("start_column"),
            end_column=fields.get("end_column"),
            symbol=fields.get("symbol"),
            role=str(fields.get("role") or "related"),
            strict=True,
        )
    except NormalizationError as exc:
        raise _RejectedItem(REASON_OUTPUT_INVALID, str(exc)) from exc


def _call_chain_dict(
    entry: object,
    *,
    catalog: SourceCatalog,
) -> dict[str, object]:
    fields = _entry_fields(entry, allowed=_CALL_CHAIN_KEYS)
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
        raise _RejectedItem(REASON_OUTPUT_INVALID, str(exc)) from exc
    note = fields.get("note")
    return {
        "path": resolved["path"],
        "start_line": resolved["start_line"],
        "end_line": resolved["end_line"],
        "symbol": resolved["symbol"],
        "role": resolved["role"],
        "note": note if isinstance(note, str) and note.strip() else None,
    }


def _entry_fields(entry: object, *, allowed: frozenset[str]) -> dict[str, object]:
    if not isinstance(entry, dict):
        raise _RejectedItem(REASON_OUTPUT_INVALID, "location entry is not an object")
    unexpected = sorted(str(key) for key in entry if str(key) not in allowed)
    if unexpected:
        raise _RejectedItem(
            REASON_OUTPUT_INVALID,
            f"location entry has unexpected keys: {', '.join(unexpected)}",
        )
    return {str(key): value for key, value in entry.items()}


def _sink_first(finding: SemanticFinding) -> list:
    """Order locations so the sink is primary.

    ``candidate_identity`` anchors on the first location, and the scanners
    report the sink as their primary location. Putting the sink first is what
    lets a semantic candidate and a scanner candidate for the same root cause
    hash to the same ``root_cause_key``.
    """

    sinks = [entry for entry in finding.locations if entry.role == "sink"]
    others = [entry for entry in finding.locations if entry.role != "sink"]
    return [*sinks, *others]
