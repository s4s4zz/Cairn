from __future__ import annotations

import hashlib
import json
import re


_SEVERITY_ORDER = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}
_CONFIDENCE_ORDER = {
    "low": 0,
    "medium": 1,
    "high": 2,
}
_CWE_PATTERN = re.compile(r"(?i)\bCWE[-_ ]?0*([1-9][0-9]{0,5})\b")
_PROSE_FIELDS = (
    "controllability",
    "attack_preconditions",
    "impact",
    "recommended_verification",
)


def normalize_cwe_ids(values: object) -> list[str]:
    if values is None:
        return []
    if isinstance(values, (str, int)):
        candidates = [str(values)]
    elif isinstance(values, (list, tuple, set)):
        candidates = [str(value) for value in values]
    else:
        candidates = [str(values)]
    normalized: set[str] = set()
    for candidate in candidates:
        for match in _CWE_PATTERN.finditer(candidate):
            normalized.add(f"CWE-{int(match.group(1))}")
    return sorted(normalized, key=lambda value: int(value.split("-", 1)[1]))


def normalize_severity(value: object) -> str:
    rendered = str(value or "").strip().lower()
    aliases = {
        "error": "high",
        "warning": "medium",
        "warn": "medium",
        "note": "low",
        "unknown": "info",
        "negligible": "info",
        "moderate": "medium",
        "important": "high",
        "5": "critical",
        "4": "high",
        "3": "medium",
        "2": "low",
        "1": "info",
    }
    rendered = aliases.get(rendered, rendered)
    return rendered if rendered in _SEVERITY_ORDER else "medium"


def normalize_confidence(value: object) -> str:
    rendered = str(value or "").strip().lower()
    aliases = {
        "error": "high",
        "warning": "medium",
        "unknown": "low",
        "confirmed": "high",
        "certain": "high",
        "firm": "high",
        "tentative": "low",
    }
    rendered = aliases.get(rendered, rendered)
    return rendered if rendered in _CONFIDENCE_ORDER else "medium"


def _canonical_json(payload: object) -> str:
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )


def _hash_payload(prefix: bytes, payload: dict[str, object]) -> str:
    encoded = _canonical_json(payload).encode("utf-8")
    return hashlib.sha256(prefix + encoded).hexdigest()


def _v2_location_identity(primary_location: dict[str, object]) -> dict[str, object]:
    """Keep mutable presentation data out of bytecode identity.

    Decompiled Artifact ids and lines change when the pinned renderer changes.
    Source line metadata may also be absent from an otherwise identical class.
    The classfile owner, method name and JVM descriptor remain the fact source.
    """

    binary_identity = any(
        primary_location.get(field)
        for field in (
            "container_path",
            "entry_path",
            "class_name",
            "method_name",
            "method_descriptor",
        )
    )
    if binary_identity:
        return {
            "container_path": str(primary_location.get("container_path") or ""),
            "entry_path": str(primary_location.get("entry_path") or ""),
            "class_name": str(primary_location.get("class_name") or ""),
            # A JVM descriptor contains parameters and return type, not the name.
            "method_name": str(primary_location.get("method_name") or ""),
            "method_descriptor": str(
                primary_location.get("method_descriptor") or ""
            ),
        }
    symbol = str(primary_location.get("symbol") or "").strip()
    line = primary_location.get("start_line")
    return {
        "source_path": str(primary_location.get("source_path") or ""),
        "symbol_or_line": symbol or (int(line) if line is not None else ""),
    }


def candidate_identity(
    *,
    snapshot_sha256: str,
    rule_id: str,
    cwe_ids: list[str],
    category: str,
    primary_location: dict[str, object],
    sink: str | None,
    tool_name: str,
) -> tuple[str, str]:
    canonical_weakness = cwe_ids[0] if cwe_ids else category.lower()
    if primary_location.get("origin_kind") is not None:
        root_payload = {
            "snapshot": snapshot_sha256,
            "weakness": canonical_weakness,
            "location": _v2_location_identity(primary_location),
            "sink": (sink or "").strip().lower(),
        }
        root_cause_key = _hash_payload(b"cairn-root-cause-v2\0", root_payload)
        fingerprint = _hash_payload(
            b"cairn-candidate-v2\0",
            {
                **root_payload,
                "rule": rule_id,
                "tool": tool_name,
            },
        )
        return fingerprint, root_cause_key

    # This branch is intentionally byte-for-byte compatible with v1. Existing
    # snapshots and persisted candidate facts must retain their identities.
    symbol = str(primary_location.get("symbol") or "").strip()
    line = int(primary_location["start_line"])
    root_payload = {
        "snapshot": snapshot_sha256,
        "weakness": canonical_weakness,
        "path": primary_location["path"],
        "symbol_or_line": symbol or line,
        "sink": (sink or "").strip().lower(),
    }
    root_cause_key = _hash_payload(b"cairn-root-cause-v1\0", root_payload)
    fingerprint = _hash_payload(
        b"cairn-candidate-v1\0",
        {
            **root_payload,
            "rule": rule_id,
            "tool": tool_name,
        },
    )
    return fingerprint, root_cause_key


def _canonical_key(payload: object) -> str:
    """Deterministic total order over JSON-ish payloads, used only to break ties."""
    try:
        return _canonical_json(payload)
    except (TypeError, ValueError):
        return json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            default=str,
        )


def _merge_order_key(candidate: dict[str, object]) -> tuple[int, int, str, str]:
    """The existing merge ordering: severity, confidence, message, rule_id.

    Ordering keys off the strongest claim the candidate stands for rather than
    its stored `severity`. Since §7.6 collapses a disagreement to the lowest
    undisputed severity, a merged candidate's stored value is deliberately not
    what any tool asserted; using it here would move that candidate in the
    ordering and pick a different `primary` on re-merge, so `message` and
    `category` would flip between passes over the same evidence.
    """

    severity = str(candidate["severity"])
    confidence = str(candidate["confidence"])
    for (claimed_severity, claimed_confidence), _tools in _severity_claims(candidate):
        if _SEVERITY_ORDER[claimed_severity] > _SEVERITY_ORDER[severity]:
            severity = claimed_severity
        if _CONFIDENCE_ORDER[claimed_confidence] > _CONFIDENCE_ORDER[confidence]:
            confidence = claimed_confidence
    return (
        -_SEVERITY_ORDER[severity],
        -_CONFIDENCE_ORDER[confidence],
        str(candidate["message"]),
        str(candidate["rule_id"]),
    )


def _as_mapping(value: object) -> dict[str, object] | None:
    """Coerce a nested contract item to a plain dict, or None if it is not one.

    Merge inputs are JSON-ish dicts (`CandidateFinding.model_dump(mode="json")`
    in the orchestrator, adapter output in `normalizers`), but accepting a
    Pydantic instance as well keeps a caller that forgot to dump from having its
    evidence silently discarded.
    """
    if isinstance(value, dict):
        return dict(value)
    dump = getattr(value, "model_dump", None)
    if callable(dump):
        dumped = dump(mode="json")
        if isinstance(dumped, dict):
            return dumped
    return None


def _mapping_list(candidate: dict[str, object], field: str) -> list[dict[str, object]]:
    items = candidate.get(field)
    if not isinstance(items, (list, tuple)):
        return []
    mappings = (_as_mapping(item) for item in items)
    return [mapping for mapping in mappings if mapping is not None]


def _merge_call_chain(
    members: list[dict[str, object]],
) -> list[dict[str, object]]:
    """Keep the longest chain, tie-broken on its canonical serialization.

    The winner is a member chain reproduced verbatim, so re-merging a merged
    candidate against any of its members selects the same chain again.
    """
    chains = [
        chain
        for chain in (_mapping_list(member, "call_chain") for member in members)
        if chain
    ]
    if not chains:
        return []
    return min(chains, key=lambda chain: (-len(chain), _canonical_key(chain)))


def _merge_existing_defenses(
    members: list[dict[str, object]],
) -> list[dict[str, object]]:
    """Union the defenses, deduplicated and ordered by their own field tuple."""
    unique: set[tuple[str, bool, str]] = set()
    for member in members:
        for defense in _mapping_list(member, "existing_defenses"):
            unique.add(
                (
                    str(defense.get("mechanism") or ""),
                    bool(defense.get("effective")),
                    str(defense.get("reasoning") or ""),
                )
            )
    return [
        {"mechanism": mechanism, "effective": effective, "reasoning": reasoning}
        for mechanism, effective, reasoning in sorted(unique)
    ]


def _location_dedup_key(location: dict[str, object]) -> tuple[object, ...]:
    if location.get("origin_kind") is not None:
        return ("v2", _canonical_key(location))
    return (
        "v1",
        location["path"],
        location["start_line"],
        location["end_line"],
        location.get("start_column"),
        location.get("end_column"),
        location.get("symbol"),
        location.get("role"),
    )


def _location_sort_key(location: dict[str, object]) -> tuple[object, ...]:
    if location.get("origin_kind") is not None:
        return (1, _canonical_key(location))
    return (
        0,
        str(location["path"]).encode("utf-8"),
        int(location["start_line"]),
        int(location["end_line"]),
        -1
        if location.get("start_column") is None
        else int(location["start_column"]),
        -1
        if location.get("end_column") is None
        else int(location["end_column"]),
        str(location.get("symbol") or ""),
        str(location.get("role") or ""),
    )


def _merge_prose(
    members: list[dict[str, object]],
    field: str,
) -> object | None:
    """Prefer the non-empty value from the highest-ranked member.

    Ranking is the existing `ordered` sequence -- severity, confidence, message,
    rule_id -- extended with the canonical form of the value itself, so two
    members that tie on all four still resolve to one deterministic answer
    regardless of input order.

    The winner survives re-merge: a merged candidate carries the maximum
    severity and confidence of its members, `ordered[0]`'s message and the
    minimum rule_id, so it ranks at or before every member it was built from. On
    a full four-key tie the canonical-value tiebreak already chose the smaller
    value, and it wins that tie again.

    One caveat for the §7.6 follow-up: because the accumulator inherits the
    maximum severity, prose is order-dependent between a *bulk* merge and a
    *left fold* -- `merge_candidates([a, b, c])` and
    `merge_candidates([merge_candidates([c, b])[0], a])` can pick different
    values. It needs two members under one root_cause_key holding different
    non-empty values for the same field, which no scanner adapter can produce
    today (only the semantic reviewer emits prose). Both required guarantees --
    order independence within a single call, and stability under the re-merge
    `engine._persist_candidates` performs -- hold unconditionally.
    """
    holders = [
        member
        for member in members
        if str(member.get(field) or "").strip()
    ]
    if not holders:
        return None
    winner = min(
        holders,
        key=lambda member: (
            _merge_order_key(member),
            _canonical_key(member.get(field)),
        ),
    )
    return winner[field]


def _severity_claims(
    candidate: dict[str, object],
) -> list[tuple[tuple[str, str], set[str]]]:
    """Expand a candidate into the severity/confidence claims it stands for.

    A candidate that already carries `severity_conflict` is itself a merge
    result, so the claims it stands for are the recorded ones -- not its own
    `severity`/`confidence`, which are the max() across those claims and were
    asserted by nobody. Anything else stands for exactly one claim.
    """
    claims: list[tuple[tuple[str, str], set[str]]] = []
    recorded = candidate.get("severity_conflict")
    if isinstance(recorded, (list, tuple)):
        for item in recorded:
            entry = _as_mapping(item)
            if entry is None:
                continue
            severity = str(entry.get("severity") or "")
            confidence = str(entry.get("confidence") or "")
            tools = entry.get("discovered_by")
            if severity not in _SEVERITY_ORDER or confidence not in _CONFIDENCE_ORDER:
                continue
            if not isinstance(tools, (list, tuple)):
                continue
            claims.append(((severity, confidence), {str(tool) for tool in tools}))
    if claims:
        return claims
    return [
        (
            (str(candidate["severity"]), str(candidate["confidence"])),
            {str(tool) for tool in candidate["discovered_by"]},
        )
    ]


def _collect_claims(
    members: list[dict[str, object]],
) -> dict[tuple[str, str], set[str]]:
    """Every severity/confidence claim the members stand for, tools unioned.

    Recomputed from the members on every merge, never accumulated, and keyed on
    `(severity, confidence)`. That makes the operation an idempotent join:
    re-merging a member back into the merged candidate contributes a claim
    whose tools are already present under its key, so neither the recorded
    conflict nor the derived severity drifts.
    """

    claims: dict[tuple[str, str], set[str]] = {}
    for member in members:
        for key, tools in _severity_claims(member):
            claims.setdefault(key, set()).update(tools)
    return claims


def _merge_severity_conflict(
    claims: dict[tuple[str, str], set[str]],
) -> list[dict[str, object]]:
    """Record disagreeing severity/confidence claims for the verification stage."""

    if len({severity for severity, _ in claims}) < 2 and (
        len({confidence for _, confidence in claims}) < 2
    ):
        return []
    return [
        {
            "severity": severity,
            "confidence": confidence,
            "discovered_by": sorted(claims[(severity, confidence)]),
        }
        for severity, confidence in sorted(
            claims,
            key=lambda key: (
                -_SEVERITY_ORDER[key[0]],
                -_CONFIDENCE_ORDER[key[1]],
            ),
        )
    ]


def _resolved_severity(
    claims: dict[tuple[str, str], set[str]],
    field: str,
) -> str:
    """Collapse the claims to one value, conservatively when they disagree.

    Spec §7.6 routes conflicting conclusions to verification instead of
    adopting the most alarming one. Taking `max` would let a single tool's
    "critical" outvote three tools' "low" and reach a human as settled fact;
    taking the lowest keeps the finding in the queue at a severity nobody
    disputes, with `severity_conflict` carrying what was actually claimed so
    the verification stage can raise it on evidence rather than on assertion.
    """

    order = _SEVERITY_ORDER if field == "severity" else _CONFIDENCE_ORDER
    index = 0 if field == "severity" else 1
    values = {key[index] for key in claims}
    if not values:
        return ""
    if len(values) == 1:
        return next(iter(values))
    return min(values, key=order.__getitem__)


def merge_candidates(
    candidates: list[dict[str, object]],
) -> list[dict[str, object]]:
    grouped: dict[str, list[dict[str, object]]] = {}
    for candidate in candidates:
        grouped.setdefault(str(candidate["root_cause_key"]), []).append(candidate)

    merged: list[dict[str, object]] = []
    for root_cause_key, members in sorted(grouped.items()):
        ordered = sorted(members, key=_merge_order_key)
        primary = ordered[0]
        # Semantic evidence is additive: a key is emitted only when some member
        # actually carries it, so a merge over scanner-only members stays
        # byte-identical to the pre-extension payload.
        claims = _collect_claims(members)
        evidence: dict[str, object] = {
            "call_chain": _merge_call_chain(members),
            "existing_defenses": _merge_existing_defenses(members),
            "severity_conflict": _merge_severity_conflict(claims),
            **{field: _merge_prose(ordered, field) for field in _PROSE_FIELDS},
        }
        location_map: dict[tuple[object, ...], dict[str, object]] = {}
        for member in members:
            for location in member["locations"]:
                key = _location_dedup_key(location)
                location_map[key] = dict(location)
        merged.append(
            {
                "rule_id": min(str(member["rule_id"]) for member in members),
                "cwe_ids": sorted(
                    {
                        cwe
                        for member in members
                        for cwe in member.get("cwe_ids", [])
                    },
                    key=lambda value: int(str(value).split("-", 1)[1]),
                ),
                "category": str(primary["category"]),
                "severity": _resolved_severity(claims, "severity"),
                "confidence": _resolved_severity(claims, "confidence"),
                "message": str(primary["message"]),
                "locations": sorted(
                    location_map.values(),
                    key=_location_sort_key,
                ),
                "sink": primary.get("sink"),
                "fingerprint": root_cause_key,
                "root_cause_key": root_cause_key,
                "discovered_by": sorted(
                    {
                        tool
                        for member in members
                        for tool in member["discovered_by"]
                    }
                ),
                "source_rules": sorted(
                    {
                        rule
                        for member in members
                        for rule in member["source_rules"]
                    }
                ),
                **{key: value for key, value in evidence.items() if value},
            }
        )
    return merged
