"""The §13.5 acceptance gate for semantic output.

Everything the model returns is untrusted data, so these tests assert on the
boundary rather than on the happy path: what is rejected, what a rejection is
allowed to say, and that identity is a function of the Snapshot alone.
"""

from __future__ import annotations

import copy
from pathlib import Path

import pytest

from cairn.analysis.contracts import CandidateConfidence, CandidateFinding
from cairn.analysis.normalizers import SourceCatalog
from cairn.semantic.contracts import (
    REASON_OUTPUT_INCOMPLETE,
    REASON_OUTPUT_INVALID,
    SEMANTIC_CONTRACT,
    SEMANTIC_TOOL_NAME,
    SemanticFinding,
    semantic_output_schema,
)
from cairn.semantic.findings import parse_findings, to_candidates
from cairn.semantic.prompt import JAVA_AUDIT_SYSTEM_PROMPT


FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "injected-app"
CONTROLLER = "web/src/main/java/dev/cairn/shop/OrderController.java"
SERVICE = "core/src/main/java/dev/cairn/shop/OrderService.java"
REPOSITORY = "core/src/main/java/dev/cairn/shop/OrderRepository.java"
SNAPSHOT_SHA = "a" * 64
OTHER_SNAPSHOT_SHA = "b" * 64
# Every JSON Schema keyword the Messages API strips from output_config.format.
# A schema that leans on one of these declares a gate that does not exist.
STRIPPED_KEYWORDS = frozenset(
    {
        "exclusiveMaximum",
        "exclusiveMinimum",
        "maxItems",
        "maxLength",
        "maximum",
        "minItems",
        "minLength",
        "minimum",
        "multipleOf",
        "pattern",
    }
)


def catalog() -> SourceCatalog:
    return SourceCatalog(FIXTURE_ROOT)


def valid_finding() -> dict[str, object]:
    """A fully-populated candidate for the fixture's Controller->Repository flow."""

    return {
        "rule_id": "sql-injection-order-owner",
        "cwe_ids": ["CWE-89"],
        "category": "sql-injection",
        "severity": "high",
        "confidence": "medium",
        "message": (
            "The 'owner' request parameter is concatenated into a SQL string "
            "executed by Statement.execute."
        ),
        "locations": [
            {
                "path": REPOSITORY,
                "start_line": 15,
                "end_line": 15,
                "symbol": "OrderRepository.findByOwner",
                "role": "sink",
            },
            {
                "path": CONTROLLER,
                "start_line": 25,
                "end_line": 25,
                "symbol": "OrderController.search",
                "role": "source",
            },
        ],
        "sink": "java.sql.Statement.execute",
        "call_chain": [
            {
                "path": CONTROLLER,
                "start_line": 24,
                "end_line": 27,
                "symbol": "OrderController.search",
                "role": "entrypoint",
                "note": "GET /orders/search binds 'owner' from the query string.",
            },
            {
                "path": SERVICE,
                "start_line": 13,
                "end_line": 15,
                "symbol": "OrderService.findByOwner",
                "role": "propagation",
                "note": "Passes 'owner' through untouched.",
            },
            {
                "path": REPOSITORY,
                "start_line": 15,
                "end_line": 15,
                "symbol": "OrderRepository.findByOwner",
                "role": "sink",
                "note": "String concatenation into Statement.execute.",
            },
        ],
        "controllability": (
            "'owner' is an unvalidated @RequestParam reaching the query string "
            "verbatim; a single quote terminates the literal."
        ),
        "existing_defenses": [
            {
                "mechanism": "None on this path",
                "effective": False,
                "reasoning": "No parameter binding, escaping or allowlist runs.",
            }
        ],
        "attack_preconditions": "Unauthenticated reachability of GET /orders/search.",
        "impact": "Arbitrary read of the orders table and adjacent tables.",
        "recommended_verification": (
            "Issue GET /orders/search?owner=' OR '1'='1 and compare row counts."
        ),
    }


def parse_one(item: object) -> tuple[list[SemanticFinding], list]:
    return parse_findings({"findings": [item], "notes": None}, catalog=catalog())


def reject_reason(item: object) -> str:
    findings, rejections = parse_one(item)

    assert findings == []
    assert len(rejections) == 1
    return rejections[0].reason_code


def walk_schema(node: object) -> list[dict[str, object]]:
    """Every object node in a JSON Schema, depth first."""

    found: list[dict[str, object]] = []
    if isinstance(node, dict):
        found.append(node)
        for value in node.values():
            found.extend(walk_schema(value))
    elif isinstance(node, list):
        for value in node:
            found.extend(walk_schema(value))
    return found


def test_fully_populated_finding_validates_and_keeps_its_evidence() -> None:
    findings, rejections = parse_one(valid_finding())

    assert rejections == []
    assert len(findings) == 1
    finding = findings[0]
    assert isinstance(finding, SemanticFinding)
    assert finding.controllability.startswith("'owner' is an unvalidated")
    assert [step.role for step in finding.call_chain] == [
        "entrypoint",
        "propagation",
        "sink",
    ]
    assert any(location.role == "sink" for location in finding.locations)
    assert finding.existing_defenses[0].effective is False


def test_finding_without_any_location_is_incomplete() -> None:
    item = valid_finding()
    item["locations"] = []

    assert reject_reason(item) == REASON_OUTPUT_INCOMPLETE


def test_finding_with_missing_locations_key_is_incomplete() -> None:
    item = valid_finding()
    del item["locations"]

    assert reject_reason(item) == REASON_OUTPUT_INCOMPLETE


def test_call_chain_shorter_than_two_steps_is_incomplete() -> None:
    item = valid_finding()
    item["call_chain"] = [item["call_chain"][0]]

    assert reject_reason(item) == REASON_OUTPUT_INCOMPLETE


def test_empty_controllability_is_incomplete() -> None:
    item = valid_finding()
    item["controllability"] = ""

    assert reject_reason(item) == REASON_OUTPUT_INCOMPLETE


def test_whitespace_only_controllability_is_incomplete() -> None:
    item = valid_finding()
    item["controllability"] = "   \n\t  "

    assert reject_reason(item) == REASON_OUTPUT_INCOMPLETE


def test_finding_without_a_sink_location_is_rejected() -> None:
    item = valid_finding()
    for location in item["locations"]:
        location["role"] = "related"

    assert reject_reason(item) == REASON_OUTPUT_INCOMPLETE


def test_location_outside_the_snapshot_is_invalid() -> None:
    item = valid_finding()
    item["locations"][0]["path"] = "web/src/main/java/dev/cairn/shop/Absent.java"

    assert reject_reason(item) == REASON_OUTPUT_INVALID


def test_absolute_location_path_is_invalid() -> None:
    item = valid_finding()
    item["locations"][0]["path"] = "/etc/passwd"

    assert reject_reason(item) == REASON_OUTPUT_INVALID


def test_traversal_location_path_is_invalid() -> None:
    item = valid_finding()
    item["locations"][0]["path"] = f"core/../{REPOSITORY}"

    assert reject_reason(item) == REASON_OUTPUT_INVALID


def test_location_line_past_end_of_file_is_invalid() -> None:
    item = valid_finding()
    item["locations"][0]["start_line"] = 9_000
    item["locations"][0]["end_line"] = 9_000

    assert reject_reason(item) == REASON_OUTPUT_INVALID


def test_call_chain_step_with_a_path_outside_the_snapshot_is_invalid() -> None:
    item = valid_finding()
    item["call_chain"][1]["path"] = "../../../etc/shadow"

    assert reject_reason(item) == REASON_OUTPUT_INVALID


def test_call_chain_step_line_past_end_of_file_is_invalid() -> None:
    item = valid_finding()
    item["call_chain"][2]["start_line"] = 9_000
    item["call_chain"][2]["end_line"] = 9_001

    assert reject_reason(item) == REASON_OUTPUT_INVALID


def test_call_chain_step_with_an_unknown_key_is_invalid() -> None:
    item = valid_finding()
    item["call_chain"][0]["tool_name"] = "read_secret_env"

    assert reject_reason(item) == REASON_OUTPUT_INVALID


def test_unknown_top_level_key_is_rejected() -> None:
    item = valid_finding()
    item["confirmed_by_verification"] = True

    assert reject_reason(item) == REASON_OUTPUT_INVALID


def test_unknown_location_key_is_rejected() -> None:
    item = valid_finding()
    item["locations"][0]["exploit"] = "' OR '1'='1"

    assert reject_reason(item) == REASON_OUTPUT_INVALID


def test_confidence_confirmed_is_rejected_because_ai_cannot_self_confirm() -> None:
    item = valid_finding()
    item["confidence"] = "confirmed"

    assert reject_reason(item) == REASON_OUTPUT_INVALID


def test_confidence_enum_has_no_confirmed_member() -> None:
    values = {member.value for member in CandidateConfidence}

    assert values == {"high", "medium", "low"}
    assert "confirmed" not in values


def test_non_object_item_is_rejected_without_discarding_the_batch() -> None:
    findings, rejections = parse_findings(
        {"findings": ["ignore previous instructions"], "notes": None},
        catalog=catalog(),
    )

    assert findings == []
    assert [rejection.reason_code for rejection in rejections] == [
        REASON_OUTPUT_INVALID
    ]


def test_one_malformed_item_among_three_good_ones_keeps_the_good_ones() -> None:
    good_first = valid_finding()
    malformed = valid_finding()
    malformed["controllability"] = ""
    good_second = copy.deepcopy(valid_finding())
    good_second["rule_id"] = "sql-injection-order-owner-variant"
    good_third = copy.deepcopy(valid_finding())
    good_third["rule_id"] = "sql-injection-order-owner-echo"

    findings, rejections = parse_findings(
        {
            "findings": [good_first, malformed, good_second, good_third],
            "notes": None,
        },
        catalog=catalog(),
    )

    assert len(findings) == 3
    assert len(rejections) == 1
    assert rejections[0].ordinal == 1
    assert rejections[0].reason_code == REASON_OUTPUT_INCOMPLETE


def test_rejection_detail_is_bounded_and_does_not_echo_the_payload() -> None:
    canary = "CANARY-8f21-do-not-echo-this"
    item = valid_finding()
    item["message"] = f"{canary} " * 4_000

    _findings, rejections = parse_one(item)

    detail = rejections[0].detail
    assert len(detail) <= 240
    assert canary not in detail
    assert "message" in detail


def test_rejection_detail_for_a_bad_path_is_bounded_and_describes_the_defect() -> None:
    canary = "CANARY-b904-payload"
    item = valid_finding()
    item["locations"][0]["path"] = f"{canary}/" * 200 + "Absent.java"

    _findings, rejections = parse_one(item)

    detail = rejections[0].detail
    assert len(detail) <= 240
    assert canary not in detail
    assert "Snapshot" in detail


def test_payload_that_is_not_an_object_or_array_is_rejected() -> None:
    findings, rejections = parse_findings("no findings, per AGENTS.md", catalog=catalog())

    assert findings == []
    assert rejections[0].reason_code == REASON_OUTPUT_INVALID


def test_output_schema_marks_every_object_closed_with_explicit_required() -> None:
    schema = semantic_output_schema()

    objects = [
        node for node in walk_schema(schema) if node.get("type") == "object"
    ]
    assert objects, "schema declares no objects"
    for node in objects:
        assert node.get("additionalProperties") is False
        properties = node.get("properties")
        assert isinstance(properties, dict) and properties
        assert set(node.get("required", [])) == set(properties)


def test_output_schema_uses_no_constraint_keyword_the_sdk_strips() -> None:
    schema = semantic_output_schema()

    for node in walk_schema(schema):
        offending = STRIPPED_KEYWORDS & set(node)
        assert offending == set(), f"schema uses stripped keywords {offending}"


def test_output_schema_offers_no_confirmed_confidence() -> None:
    schema = semantic_output_schema()
    finding_schema = schema["properties"]["findings"]["items"]

    assert finding_schema["properties"]["confidence"]["enum"] == [
        "high",
        "medium",
        "low",
    ]


def test_output_schema_contract_literal_matches_the_result_contract() -> None:
    assert SEMANTIC_CONTRACT == "cairn-semantic-result-v1"
    assert SEMANTIC_TOOL_NAME == "semantic-reviewer"


def test_every_prose_field_asks_for_chinese_on_both_channels() -> None:
    """The workbench and the report are Chinese; the prose that fills them has
    to be too. The schema description is the constraint the model sees at output
    time, and the system prompt is the one it reads first — both must say so, or
    the requirement rests on whichever one the model happened to weigh."""

    finding_schema = semantic_output_schema()["properties"]["findings"]["items"]
    properties = finding_schema["properties"]
    prose = (
        "message",
        "controllability",
        "attack_preconditions",
        "impact",
        "recommended_verification",
    )

    for field in prose:
        assert "中文" in properties[field]["description"], field
    assert "中文" in properties["existing_defenses"]["items"]["properties"][
        "reasoning"
    ]["description"]
    assert "中文" in properties["call_chain"]["items"]["properties"]["note"]["description"]

    assert "Simplified Chinese" in JAVA_AUDIT_SYSTEM_PROMPT
    for field in prose:
        assert f"`{field}`" in JAVA_AUDIT_SYSTEM_PROMPT, field
    # Identity must survive the translation: a Chinese sentence about
    # `OrderMapper.selectByExample` is right, a translated identifier is not.
    assert "verbatim" in JAVA_AUDIT_SYSTEM_PROMPT


def test_to_candidates_produces_valid_candidate_findings() -> None:
    source_catalog = catalog()
    findings, _rejections = parse_findings(
        {"findings": [valid_finding()], "notes": None},
        catalog=source_catalog,
    )

    candidates = to_candidates(
        findings,
        catalog=source_catalog,
        snapshot_sha256=SNAPSHOT_SHA,
    )

    assert len(candidates) == 1
    candidate = CandidateFinding.model_validate(candidates[0])
    assert candidate.discovered_by == [SEMANTIC_TOOL_NAME]
    assert candidate.locations[0].role == "sink"
    assert len(candidate.call_chain) == 3
    assert candidate.controllability
    assert candidate.impact
    assert candidate.recommended_verification
    assert candidate.confidence is not None
    assert candidate.confidence.value in {"high", "medium", "low"}


def test_fingerprints_are_byte_identical_for_the_same_snapshot() -> None:
    source_catalog = catalog()
    findings, _rejections = parse_findings(
        {"findings": [valid_finding()], "notes": None},
        catalog=source_catalog,
    )

    first = to_candidates(
        findings, catalog=source_catalog, snapshot_sha256=SNAPSHOT_SHA
    )
    second = to_candidates(
        findings,
        catalog=SourceCatalog(FIXTURE_ROOT),
        snapshot_sha256=SNAPSHOT_SHA,
    )

    assert first[0]["fingerprint"] == second[0]["fingerprint"]
    assert first[0]["root_cause_key"] == second[0]["root_cause_key"]


def test_fingerprints_differ_across_snapshots() -> None:
    source_catalog = catalog()
    findings, _rejections = parse_findings(
        {"findings": [valid_finding()], "notes": None},
        catalog=source_catalog,
    )

    first = to_candidates(
        findings, catalog=source_catalog, snapshot_sha256=SNAPSHOT_SHA
    )
    other = to_candidates(
        findings, catalog=source_catalog, snapshot_sha256=OTHER_SNAPSHOT_SHA
    )

    assert first[0]["fingerprint"] != other[0]["fingerprint"]
    assert first[0]["root_cause_key"] != other[0]["root_cause_key"]


# --- evidence the model never actually established --------------------------
#
# `SourceCatalog` was built for scanner output, where a bare basename and an
# omitted line number are sloppiness worth normalising. Applied unchanged to
# untrusted model output, each of these is a way to satisfy §7.5 without ever
# opening the file, so the semantic path resolves locations in strict mode.


def test_location_without_line_numbers_is_rejected_rather_than_defaulted() -> None:
    """A missing line number used to be manufactured as line 1, which turns
    'no code location' into an accepted location (§13.5 #2)."""

    finding = copy.deepcopy(valid_finding())
    finding["locations"] = [
        {"path": REPOSITORY, "symbol": "OrderRepository.findByOwner", "role": "sink"}
    ]

    assert reject_reason(finding) == REASON_OUTPUT_INVALID


def test_location_with_explicitly_null_line_numbers_is_rejected() -> None:
    finding = copy.deepcopy(valid_finding())
    finding["locations"] = [
        {
            "path": REPOSITORY,
            "start_line": None,
            "end_line": None,
            "role": "sink",
        }
    ]

    assert reject_reason(finding) == REASON_OUTPUT_INVALID


@pytest.mark.parametrize("value", ["15", 15.0, True])
def test_line_numbers_are_not_coerced_from_other_types(value: object) -> None:
    """int() would turn "15", 15.0 and True into line numbers — and True into
    line 1. The broker's argument parser already refuses these; the untrusted
    output path must not be weaker than the tool path."""

    finding = copy.deepcopy(valid_finding())
    finding["locations"] = [
        {"path": REPOSITORY, "start_line": value, "end_line": value, "role": "sink"}
    ]

    assert reject_reason(finding) == REASON_OUTPUT_INVALID


def test_a_bare_basename_cannot_stand_in_for_a_path() -> None:
    """The suffix-match fallback exists for scanners, which legitimately emit
    basenames. Extended to model output it lets the platform, not the model,
    decide which module the evidence points at."""

    finding = copy.deepcopy(valid_finding())
    finding["locations"][0]["path"] = "OrderRepository.java"

    assert reject_reason(finding) == REASON_OUTPUT_INVALID


def test_the_last_real_line_is_accepted_but_the_line_after_it_is_not() -> None:
    """The lenient ceiling allowed two lines past real EOF, so a candidate
    could be anchored to a line that does not exist."""

    real_lines = len((FIXTURE_ROOT / REPOSITORY).read_text().splitlines())

    accepted = copy.deepcopy(valid_finding())
    accepted["locations"][0]["start_line"] = real_lines
    accepted["locations"][0]["end_line"] = real_lines
    findings, rejections = parse_one(accepted)
    assert len(findings) == 1 and rejections == []

    for beyond in (real_lines + 1, real_lines + 2):
        past_eof = copy.deepcopy(valid_finding())
        past_eof["locations"][0]["start_line"] = beyond
        past_eof["locations"][0]["end_line"] = beyond
        assert reject_reason(past_eof) == REASON_OUTPUT_INVALID


# --- prose that renders as nothing ------------------------------------------


@pytest.mark.parametrize(
    "invisible",
    ["​", "‌", "‍", "⁠", "﻿", "⠀", "ㅤ", "᠎"],
)
def test_controllability_of_invisible_characters_is_incomplete(
    invisible: str,
) -> None:
    """U+200B is not whitespace, so `.strip()` leaves it and a controllability
    statement that renders as nothing satisfies min_length=1."""

    finding = copy.deepcopy(valid_finding())
    finding["controllability"] = invisible

    assert reject_reason(finding) == REASON_OUTPUT_INCOMPLETE


@pytest.mark.parametrize(
    "field",
    ["message", "attack_preconditions", "impact", "recommended_verification"],
)
def test_every_required_prose_field_must_render_as_something(field: str) -> None:
    finding = copy.deepcopy(valid_finding())
    finding[field] = "​"

    assert reject_reason(finding) == REASON_OUTPUT_INCOMPLETE


# --- a chain that actually runs entrypoint to sink --------------------------


def test_two_identical_steps_do_not_constitute_a_call_chain() -> None:
    """`len(call_chain) >= 2` is satisfiable by duplicating one step, which
    describes no path at all (§7.5 requires an 入口到 Sink 调用链)."""

    finding = copy.deepcopy(valid_finding())
    step = copy.deepcopy(finding["call_chain"][2])
    step["role"] = "propagation"
    finding["call_chain"] = [step, copy.deepcopy(step)]

    assert reject_reason(finding) == REASON_OUTPUT_INCOMPLETE


def test_a_reversed_chain_is_rejected() -> None:
    finding = copy.deepcopy(valid_finding())
    finding["call_chain"] = list(reversed(finding["call_chain"]))

    assert reject_reason(finding) == REASON_OUTPUT_INCOMPLETE


def test_a_chain_must_begin_at_an_entrypoint() -> None:
    finding = copy.deepcopy(valid_finding())
    finding["call_chain"][0]["role"] = "propagation"

    assert reject_reason(finding) == REASON_OUTPUT_INCOMPLETE


def test_a_chain_must_terminate_in_a_declared_sink_location() -> None:
    """Otherwise a finding can pair a sink in one file with a chain that never
    touches it."""

    finding = copy.deepcopy(valid_finding())
    finding["call_chain"][-1]["path"] = CONTROLLER
    finding["call_chain"][-1]["start_line"] = 25
    finding["call_chain"][-1]["end_line"] = 25

    assert reject_reason(finding) == REASON_OUTPUT_INCOMPLETE


def test_cwe_ids_of_differing_digit_counts_survive_the_candidate_contract() -> None:
    """CWE ids are ordered numerically end to end; ordering them as plain
    strings put CWE-611 before CWE-89 and rejected the candidate outright."""

    finding = copy.deepcopy(valid_finding())
    finding["cwe_ids"] = ["CWE-89", "CWE-611"]

    findings, rejections = parse_one(finding)
    assert rejections == []

    candidates = to_candidates(
        findings, catalog=catalog(), snapshot_sha256=SNAPSHOT_SHA
    )

    assert candidates[0]["cwe_ids"] == ["CWE-89", "CWE-611"]
    assert CandidateFinding.model_validate(candidates[0]).cwe_ids == [
        "CWE-89",
        "CWE-611",
    ]
