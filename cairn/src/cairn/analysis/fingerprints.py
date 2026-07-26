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


def _hash_payload(prefix: bytes, payload: dict[str, object]) -> str:
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(prefix + encoded).hexdigest()


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


def merge_candidates(
    candidates: list[dict[str, object]],
) -> list[dict[str, object]]:
    grouped: dict[str, list[dict[str, object]]] = {}
    for candidate in candidates:
        grouped.setdefault(str(candidate["root_cause_key"]), []).append(candidate)

    merged: list[dict[str, object]] = []
    for root_cause_key, members in sorted(grouped.items()):
        ordered = sorted(
            members,
            key=lambda item: (
                -_SEVERITY_ORDER[str(item["severity"])],
                -_CONFIDENCE_ORDER[str(item["confidence"])],
                str(item["message"]),
                str(item["rule_id"]),
            ),
        )
        primary = ordered[0]
        location_map: dict[tuple[object, ...], dict[str, object]] = {}
        for member in members:
            for location in member["locations"]:
                key = (
                    location["path"],
                    location["start_line"],
                    location["end_line"],
                    location.get("start_column"),
                    location.get("end_column"),
                    location.get("symbol"),
                    location.get("role"),
                )
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
                "severity": max(
                    (str(member["severity"]) for member in members),
                    key=_SEVERITY_ORDER.__getitem__,
                ),
                "confidence": max(
                    (str(member["confidence"]) for member in members),
                    key=_CONFIDENCE_ORDER.__getitem__,
                ),
                "message": str(primary["message"]),
                "locations": sorted(
                    location_map.values(),
                    key=lambda item: (
                        str(item["path"]).encode("utf-8"),
                        int(item["start_line"]),
                        int(item["end_line"]),
                        str(item.get("role") or ""),
                    ),
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
            }
        )
    return merged
