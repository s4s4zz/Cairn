"""Identity and merge semantics for candidate findings.

Two properties are load-bearing for the platform and are therefore asserted
here rather than left implicit:

* §13.5 acceptance #4 — a fingerprint is stable for a given Snapshot, and a
  ``root_cause_key`` is tool-agnostic so a semantic candidate and a scanner
  candidate describing one weakness collapse into one record.
* ``merge_candidates`` builds its result as a fresh dict with a fixed key set.
  Any evidence field it does not name is dropped silently, so the semantic
  reviewer's call chain and controllability would vanish the first time a
  scanner reported the same root cause. That is the regression the bulk of
  this module guards.

``cairn.orchestrator.engine._persist_candidates`` merges by re-merging an
already-merged payload (``merge_candidates([current, candidate])[0]``), so
every merge property is also asserted under re-merge.
"""

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from cairn.analysis.contracts import CandidateFinding
from cairn.analysis.fingerprints import candidate_identity, merge_candidates
from cairn.analysis.normalizers import (
    SourceCatalog,
    normalize_gitleaks,
    normalize_sarif,
    normalize_semgrep,
)


SOURCE_ROOT = Path(__file__).parent / "fixtures" / "maven-multi"
SNAPSHOT_SHA = "a" * 64
OTHER_SNAPSHOT_SHA = "b" * 64
SINK_PATH = "core/src/main/java/dev/cairn/UserRepository.java"
ENTRY_PATH = "web/src/main/java/dev/cairn/UserController.java"

SEMANTIC_FIELDS = (
    "call_chain",
    "controllability",
    "existing_defenses",
    "attack_preconditions",
    "impact",
    "recommended_verification",
)


def location(
    *,
    path: str = SINK_PATH,
    start_line: int = 7,
    end_line: int = 7,
    start_column: int | None = None,
    end_column: int | None = None,
    symbol: str | None = None,
    role: str = "sink",
) -> dict[str, object]:
    return {
        "path": path,
        "start_line": start_line,
        "end_line": end_line,
        "start_column": start_column,
        "end_column": end_column,
        "symbol": symbol,
        "role": role,
    }


def step(
    path: str,
    line: int,
    symbol: str,
    role: str,
    note: str | None = None,
) -> dict[str, object]:
    return {
        "path": path,
        "start_line": line,
        "end_line": line,
        "symbol": symbol,
        "role": role,
        "note": note,
    }


CALL_CHAIN = [
    step(ENTRY_PATH, 12, "UserController.user", "entrypoint", "@GetMapping"),
    step(SINK_PATH, 7, "UserRepository.find", "sink", "Statement.execute"),
]
LONG_CALL_CHAIN = [
    step(ENTRY_PATH, 12, "UserController.user", "entrypoint", "@GetMapping"),
    step(ENTRY_PATH, 15, "UserController.user", "propagation", "returned"),
    step(SINK_PATH, 7, "UserRepository.find", "sink", "Statement.execute"),
]


def candidate(
    *,
    tool: str,
    rule_id: str,
    severity: str = "high",
    confidence: str = "high",
    message: str | None = None,
    cwe_ids: list[str] | None = None,
    category: str = "sql-injection",
    locations: list[dict[str, object]] | None = None,
    sink: str | None = None,
    snapshot_sha256: str = SNAPSHOT_SHA,
    **evidence: object,
) -> dict[str, object]:
    """Build a candidate exactly as `normalizers._candidate` and
    `semantic.findings.to_candidates` do: identity derived from the primary
    location, then the payload keyed by the contract's field names."""

    resolved_cwes = ["CWE-89"] if cwe_ids is None else cwe_ids
    resolved_locations = [location()] if locations is None else locations
    fingerprint, root_cause_key = candidate_identity(
        snapshot_sha256=snapshot_sha256,
        rule_id=rule_id,
        cwe_ids=resolved_cwes,
        category=category,
        primary_location=resolved_locations[0],
        sink=sink,
        tool_name=tool,
    )
    payload: dict[str, object] = {
        "rule_id": rule_id,
        "cwe_ids": resolved_cwes,
        "category": category,
        "severity": severity,
        "confidence": confidence,
        "message": message or f"finding reported by {tool}",
        "locations": resolved_locations,
        "sink": sink,
        "fingerprint": fingerprint,
        "root_cause_key": root_cause_key,
        "discovered_by": [tool],
        "source_rules": [rule_id],
    }
    payload.update(evidence)
    return payload


def semantic_candidate(**overrides: object) -> dict[str, object]:
    fields: dict[str, object] = {
        "tool": "semantic-reviewer",
        "rule_id": "CAIRN-SEMANTIC-SQLI",
        "severity": "high",
        "confidence": "medium",
        "call_chain": [dict(entry) for entry in CALL_CHAIN],
        "controllability": (
            "The @PathVariable name reaches Statement.execute unescaped."
        ),
        "existing_defenses": [
            {
                "mechanism": "@PreAuthorize(\"hasRole('ADMIN')\")",
                "effective": False,
                "reasoning": "Authorization does not constrain the SQL string.",
            }
        ],
        "attack_preconditions": "Any authenticated ADMIN principal.",
        "impact": "Arbitrary read of the users table.",
        "recommended_verification": "Replay the route with a quote payload.",
    }
    fields.update(overrides)
    return candidate(**fields)  # type: ignore[arg-type]


def scanner_candidate(**overrides: object) -> dict[str, object]:
    defaults: dict[str, object] = {
        "tool": "semgrep",
        "rule_id": "java.lang.security.audit.sqli",
    }
    defaults.update(overrides)
    return candidate(**defaults)  # type: ignore[arg-type]


def canonical(payload: object) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


# --- identity ---------------------------------------------------------------


def test_candidate_identity_is_byte_identical_across_calls() -> None:
    kwargs = {
        "snapshot_sha256": SNAPSHOT_SHA,
        "rule_id": "java/sql-injection",
        "cwe_ids": ["CWE-89"],
        "category": "sql-injection",
        "primary_location": location(),
        "sink": "Statement.execute",
        "tool_name": "codeql",
    }

    first = candidate_identity(**kwargs)  # type: ignore[arg-type]
    second = candidate_identity(**kwargs)  # type: ignore[arg-type]

    assert first == second
    assert len(first[0]) == 64 and len(first[1]) == 64


def test_root_cause_key_is_tool_agnostic_while_fingerprint_is_not() -> None:
    shared = {
        "snapshot_sha256": SNAPSHOT_SHA,
        "rule_id": "java/sql-injection",
        "cwe_ids": ["CWE-89"],
        "category": "sql-injection",
        "primary_location": location(),
        "sink": "Statement.execute",
    }

    scanner_fingerprint, scanner_root = candidate_identity(
        **shared,  # type: ignore[arg-type]
        tool_name="semgrep",
    )
    semantic_fingerprint, semantic_root = candidate_identity(
        **shared,  # type: ignore[arg-type]
        tool_name="semantic-reviewer",
    )

    assert scanner_root == semantic_root
    assert scanner_fingerprint != semantic_fingerprint


def test_a_different_snapshot_changes_fingerprint_and_root_cause_key() -> None:
    shared = {
        "rule_id": "java/sql-injection",
        "cwe_ids": ["CWE-89"],
        "category": "sql-injection",
        "primary_location": location(),
        "sink": "Statement.execute",
        "tool_name": "semgrep",
    }

    first = candidate_identity(
        **shared,  # type: ignore[arg-type]
        snapshot_sha256=SNAPSHOT_SHA,
    )
    second = candidate_identity(
        **shared,  # type: ignore[arg-type]
        snapshot_sha256=OTHER_SNAPSHOT_SHA,
    )

    assert first[0] != second[0]
    assert first[1] != second[1]


def test_the_rule_identifier_changes_the_fingerprint_but_not_the_root_cause() -> None:
    shared = {
        "snapshot_sha256": SNAPSHOT_SHA,
        "cwe_ids": ["CWE-89"],
        "category": "sql-injection",
        "primary_location": location(),
        "sink": "Statement.execute",
        "tool_name": "semgrep",
    }

    first = candidate_identity(**shared, rule_id="rule-a")  # type: ignore[arg-type]
    second = candidate_identity(**shared, rule_id="rule-b")  # type: ignore[arg-type]

    assert first[1] == second[1]
    assert first[0] != second[0]


# --- the subproject 5 regression -------------------------------------------


def test_semantic_evidence_survives_a_merge_with_a_scanner_candidate() -> None:
    """The whole point of subproject 5: a scanner reporting the same root cause
    must not erase the model's call chain and controllability."""

    semantic = semantic_candidate()
    scanner = scanner_candidate()
    assert semantic["root_cause_key"] == scanner["root_cause_key"]

    merged = merge_candidates([semantic, scanner])

    assert len(merged) == 1
    for field in SEMANTIC_FIELDS:
        assert merged[0][field] == semantic[field], field
    assert merged[0]["discovered_by"] == ["semantic-reviewer", "semgrep"]


def test_semantic_evidence_survives_the_engine_style_incremental_merge() -> None:
    """`engine._persist_candidates` folds one candidate at a time into the
    stored payload. Evidence must survive every fold, in either arrival order."""

    semantic = semantic_candidate()
    first_scanner = scanner_candidate()
    second_scanner = scanner_candidate(tool="codeql", rule_id="java/sql-injection")

    semantic_last = semantic
    for arriving in (first_scanner, second_scanner, semantic):
        semantic_last = merge_candidates([semantic_last, arriving])[0]
    semantic_first = semantic
    for arriving in (semantic, first_scanner, second_scanner):
        semantic_first = merge_candidates([semantic_first, arriving])[0]

    for field in SEMANTIC_FIELDS:
        assert semantic_last[field] == semantic[field], field
        assert semantic_first[field] == semantic[field], field
    assert semantic_last["discovered_by"] == [
        "codeql",
        "semantic-reviewer",
        "semgrep",
    ]


def test_a_single_member_merge_preserves_the_semantic_fields_verbatim() -> None:
    semantic = semantic_candidate()

    merged = merge_candidates([semantic])

    assert len(merged) == 1
    for field in SEMANTIC_FIELDS:
        assert canonical(merged[0][field]) == canonical(semantic[field]), field


def test_a_scanner_only_merge_emits_no_semantic_keys_at_all() -> None:
    """Semantic evidence is additive: a merge over scanner-only members must
    stay byte-identical to the pre-extension payload, so nothing downstream
    sees an empty `call_chain` where it previously saw no key."""

    merged = merge_candidates(
        [
            scanner_candidate(),
            scanner_candidate(tool="codeql", rule_id="java/sql-injection"),
        ]
    )

    assert set(merged[0]) == {
        "rule_id",
        "cwe_ids",
        "category",
        "severity",
        "confidence",
        "message",
        "locations",
        "sink",
        "fingerprint",
        "root_cause_key",
        "discovered_by",
        "source_rules",
    }


# --- order independence and re-merge stability ------------------------------


def test_merge_is_independent_of_member_order() -> None:
    semantic = semantic_candidate()
    scanner = scanner_candidate()

    assert merge_candidates([semantic, scanner]) == merge_candidates(
        [scanner, semantic]
    )


def test_merge_is_independent_of_member_order_across_three_members() -> None:
    members = [
        semantic_candidate(),
        scanner_candidate(),
        scanner_candidate(
            tool="findsecbugs",
            rule_id="SQL_INJECTION_JDBC",
            severity="medium",
            confidence="medium",
        ),
    ]

    forward = merge_candidates(members)
    reverse = merge_candidates(list(reversed(members)))

    assert canonical(forward) == canonical(reverse)


def test_merged_locations_are_order_independent_as_a_set() -> None:
    """Two tools reporting one line with different column precision.

    The merged location *set* does not depend on member order. Byte-order of
    the emitted list can still depend on it, because the location sort key in
    `merge_candidates` omits `start_column`/`end_column` and Python's sort is
    stable — see the report accompanying this suite.
    """

    with_columns = scanner_candidate(
        locations=[location(start_column=9, end_column=73)],
    )
    without_columns = scanner_candidate(tool="codeql", rule_id="java/sql-injection")

    forward = merge_candidates([with_columns, without_columns])[0]
    reverse = merge_candidates([without_columns, with_columns])[0]

    assert sorted(canonical(item) for item in forward["locations"]) == sorted(
        canonical(item) for item in reverse["locations"]
    )
    assert len(forward["locations"]) == 2


def test_merge_is_stable_under_re_merge_with_a_member() -> None:
    semantic = semantic_candidate()
    scanner = scanner_candidate()
    merged = merge_candidates([semantic, scanner])[0]

    assert merge_candidates([merged, scanner])[0] == merged
    assert merge_candidates([merged, semantic])[0] == merged
    assert merge_candidates([scanner, merged])[0] == merged


def test_merge_is_idempotent_on_its_own_output() -> None:
    merged = merge_candidates([semantic_candidate(), scanner_candidate()])[0]

    assert merge_candidates([merged, merged])[0] == merged
    assert merge_candidates([merged])[0] == merged


def test_merge_groups_distinct_root_causes_separately_and_deterministically() -> None:
    same_root = [semantic_candidate(), scanner_candidate()]
    other_root = scanner_candidate(
        tool="trivy",
        rule_id="AVD-SPRING-0001",
        category="config",
        cwe_ids=["CWE-16"],
        locations=[location(path="web/src/main/resources/application.yml", start_line=3, end_line=3, role="related")],
    )

    forward = merge_candidates([*same_root, other_root])
    reverse = merge_candidates([other_root, *reversed(same_root)])

    assert len(forward) == 2
    assert canonical(forward) == canonical(reverse)
    assert [entry["root_cause_key"] for entry in forward] == sorted(
        entry["root_cause_key"] for entry in forward
    )


# --- call chain merge rules -------------------------------------------------


def test_the_longest_call_chain_wins() -> None:
    short = semantic_candidate()
    long_chain = semantic_candidate(
        call_chain=[dict(entry) for entry in LONG_CALL_CHAIN],
    )

    forward = merge_candidates([short, long_chain])[0]
    reverse = merge_candidates([long_chain, short])[0]

    assert forward["call_chain"] == LONG_CALL_CHAIN
    assert reverse["call_chain"] == LONG_CALL_CHAIN


def test_equal_length_call_chains_tie_break_deterministically() -> None:
    """Two chains of the same length resolve on their canonical serialization,
    so the winner never depends on which tool reported first."""

    alternative = [
        step(ENTRY_PATH, 10, "UserController.list", "entrypoint", "@GetMapping"),
        step(SINK_PATH, 7, "UserRepository.find", "sink", "Statement.execute"),
    ]
    left = semantic_candidate()
    right = semantic_candidate(call_chain=alternative)
    assert len(alternative) == len(CALL_CHAIN)

    forward = merge_candidates([left, right])[0]
    reverse = merge_candidates([right, left])[0]

    assert forward["call_chain"] == reverse["call_chain"]
    assert forward["call_chain"] == min(
        (CALL_CHAIN, alternative),
        key=canonical,
    )


def test_a_merged_call_chain_is_one_member_chain_reproduced_verbatim() -> None:
    """The winner is never a splice of two chains: a spliced chain would not
    survive the re-merge `engine._persist_candidates` performs."""

    long_chain = semantic_candidate(
        call_chain=[dict(entry) for entry in LONG_CALL_CHAIN],
    )
    short = semantic_candidate()

    merged = merge_candidates([short, long_chain])[0]

    assert merged["call_chain"] in (CALL_CHAIN, LONG_CALL_CHAIN)
    assert merge_candidates([merged, short])[0]["call_chain"] == merged["call_chain"]


def test_a_scanner_without_a_call_chain_does_not_erase_one() -> None:
    merged = merge_candidates([semantic_candidate(), scanner_candidate()])[0]

    assert merged["call_chain"] == CALL_CHAIN


# --- existing defenses ------------------------------------------------------


def test_existing_defenses_are_unioned_deduplicated_and_ordered() -> None:
    shared = {
        "mechanism": "Zeta output encoder",
        "effective": True,
        "reasoning": "Encodes before rendering.",
    }
    left = semantic_candidate(
        existing_defenses=[
            dict(shared),
            {
                "mechanism": "Middle validator",
                "effective": False,
                "reasoning": "Length check only.",
            },
        ]
    )
    right = semantic_candidate(
        existing_defenses=[
            {
                "mechanism": "Alpha allowlist",
                "effective": True,
                "reasoning": "Rejects unknown identifiers.",
            },
            dict(shared),
        ]
    )

    forward = merge_candidates([left, right])[0]
    reverse = merge_candidates([right, left])[0]

    assert forward["existing_defenses"] == reverse["existing_defenses"]
    assert [entry["mechanism"] for entry in forward["existing_defenses"]] == [
        "Alpha allowlist",
        "Middle validator",
        "Zeta output encoder",
    ]
    assert merge_candidates([forward, left])[0]["existing_defenses"] == (
        forward["existing_defenses"]
    )


def test_defenses_differing_only_in_effectiveness_are_both_recorded() -> None:
    left = semantic_candidate(
        existing_defenses=[
            {"mechanism": "WAF", "effective": True, "reasoning": "Blocks quotes."}
        ]
    )
    right = semantic_candidate(
        existing_defenses=[
            {"mechanism": "WAF", "effective": False, "reasoning": "Blocks quotes."}
        ]
    )

    merged = merge_candidates([left, right])[0]

    assert [entry["effective"] for entry in merged["existing_defenses"]] == [
        False,
        True,
    ]


# --- severity conflict ------------------------------------------------------


def test_severity_conflict_is_absent_when_members_agree() -> None:
    merged = merge_candidates(
        [
            scanner_candidate(),
            scanner_candidate(tool="codeql", rule_id="java/sql-injection"),
        ]
    )[0]

    assert "severity_conflict" not in merged
    assert CandidateFinding.model_validate(merged).severity_conflict == []


def test_severity_conflict_records_disagreement_in_a_deterministic_order() -> None:
    high = scanner_candidate()
    low = scanner_candidate(
        tool="codeql",
        rule_id="java/sql-injection",
        severity="low",
        confidence="low",
    )

    forward = merge_candidates([high, low])[0]
    reverse = merge_candidates([low, high])[0]

    assert forward["severity_conflict"] == reverse["severity_conflict"]
    assert forward["severity_conflict"] == [
        {"severity": "high", "confidence": "high", "discovered_by": ["semgrep"]},
        {"severity": "low", "confidence": "low", "discovered_by": ["codeql"]},
    ]
    # §7.6: a disagreement goes to verification rather than being settled by
    # the most alarming tool. Taking the max would let one scanner's "high"
    # outvote another's "low" and reach a reviewer as fact; the merged
    # candidate keeps the severity nobody disputes and carries the claims.
    assert forward["severity"] == "low"
    assert forward["confidence"] == "low"
    assert reverse["severity"] == "low"


def test_severity_conflict_is_recomputed_rather_than_accumulated() -> None:
    """Re-merging a member back in must not grow the recorded conflict; the
    orchestrator re-merges on every task completion."""

    high = scanner_candidate()
    low = scanner_candidate(
        tool="codeql",
        rule_id="java/sql-injection",
        severity="low",
        confidence="low",
    )
    merged = merge_candidates([high, low])[0]

    once = merge_candidates([merged, low])[0]
    twice = merge_candidates([once, high])[0]

    assert once["severity_conflict"] == merged["severity_conflict"]
    assert twice["severity_conflict"] == merged["severity_conflict"]
    assert len(twice["severity_conflict"]) == 2


def test_a_third_tool_agreeing_with_a_recorded_claim_only_joins_it() -> None:
    high = scanner_candidate()
    low = scanner_candidate(
        tool="codeql",
        rule_id="java/sql-injection",
        severity="low",
        confidence="low",
    )
    merged = merge_candidates([high, low])[0]
    agreeing = scanner_candidate(
        tool="findsecbugs",
        rule_id="SQL_INJECTION_JDBC",
        severity="low",
        confidence="low",
    )

    result = merge_candidates([merged, agreeing])[0]

    assert len(result["severity_conflict"]) == 2
    assert result["severity_conflict"][1]["discovered_by"] == [
        "codeql",
        "findsecbugs",
    ]


def test_a_semantic_candidate_disagreeing_with_a_scanner_is_recorded() -> None:
    semantic = semantic_candidate(severity="critical")
    scanner = scanner_candidate(severity="medium", confidence="low")

    merged = merge_candidates([semantic, scanner])[0]

    assert merged["severity_conflict"] == [
        {
            "severity": "critical",
            "confidence": "medium",
            "discovered_by": ["semantic-reviewer"],
        },
        {"severity": "medium", "confidence": "low", "discovered_by": ["semgrep"]},
    ]
    assert merged["call_chain"] == CALL_CHAIN


# --- contract validation ----------------------------------------------------


def test_a_merged_candidate_validates_as_a_candidate_finding() -> None:
    """`cwe_ids[0]` drives `root_cause_key`, so members that merge necessarily
    agree on it; the second id is what the union has to carry through."""

    merged = merge_candidates(
        [
            semantic_candidate(cwe_ids=["CWE-89"]),
            scanner_candidate(
                tool="codeql",
                rule_id="java/sql-injection",
                cwe_ids=["CWE-89", "CWE-943"],
                severity="low",
                confidence="low",
            ),
        ]
    )[0]

    model = CandidateFinding.model_validate(merged)

    assert model.cwe_ids == ["CWE-89", "CWE-943"]
    assert model.discovered_by == ["codeql", "semantic-reviewer"]
    assert model.fingerprint == model.root_cause_key
    assert [item.model_dump() for item in model.call_chain] == CALL_CHAIN
    assert model.controllability == semantic_candidate()["controllability"]
    assert len(model.severity_conflict) == 2


def test_a_merged_candidate_round_trips_through_the_contract_unchanged() -> None:
    """`engine._persist_candidates` stores `model_dump(mode="json")` and merges
    that back in, so a dumped model must merge to itself."""

    merged = merge_candidates([semantic_candidate(), scanner_candidate()])[0]
    dumped = CandidateFinding.model_validate(merged).model_dump(mode="json")

    assert merge_candidates([dumped, merged])[0] == merged


def test_confidence_has_no_confirmed_member_after_a_merge() -> None:
    """§13.5 acceptance #1 — the AI may not confirm a Finding, and merging must
    not invent a confidence level outside the contract's three."""

    merged = merge_candidates([semantic_candidate(confidence="high"), scanner_candidate()])[0]

    assert merged["confidence"] in {"high", "medium", "low"}
    assert CandidateFinding.model_validate(merged).confidence.value != "confirmed"


# --- defects that predated subproject 5, fixed alongside it -----------------
#
# Both reproduced on HEAD (`983bbe1`) before the candidate contract was
# extended. The first one blocks this increment outright: a semantic finding
# citing CWE-89 and CWE-611 could not validate as a `CandidateFinding` at all.


def test_numerically_sorted_cwe_ids_validate_as_a_candidate_finding() -> None:
    """`normalize_cwe_ids` orders CWE ids numerically, so the contract must
    accept that order — ordering them as plain strings puts CWE-611 before
    CWE-89 and rejects any candidate mixing two- and three-digit weaknesses."""

    merged = merge_candidates(
        [
            scanner_candidate(cwe_ids=["CWE-89", "CWE-611"]),
            scanner_candidate(
                tool="codeql",
                rule_id="java/sql-injection",
                cwe_ids=["CWE-89"],
            ),
        ]
    )[0]

    assert merged["cwe_ids"] == ["CWE-89", "CWE-611"]
    CandidateFinding.model_validate(merged)


def test_cwe_ids_out_of_numeric_order_are_still_rejected() -> None:
    with pytest.raises(ValidationError):
        CandidateFinding.model_validate(
            {**scanner_candidate(), "cwe_ids": ["CWE-611", "CWE-89"]}
        )


def test_duplicate_cwe_ids_are_rejected() -> None:
    with pytest.raises(ValidationError):
        CandidateFinding.model_validate(
            {**scanner_candidate(), "cwe_ids": ["CWE-89", "CWE-89"]}
        )


def test_merge_is_byte_order_independent_for_locations_differing_in_columns() -> None:
    """Columns take part in the location dedup key, so they must take part in
    the sort key too, or the two entries sort equal and emit in member order."""

    with_columns = scanner_candidate(
        locations=[location(start_column=9, end_column=73)],
    )
    without_columns = scanner_candidate(tool="codeql", rule_id="java/sql-injection")

    assert merge_candidates([with_columns, without_columns]) == merge_candidates(
        [without_columns, with_columns]
    )


# --- the existing scanner adapters --------------------------------------


def write_json(path: Path, payload: object) -> Path:
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_semgrep_and_gitleaks_adapters_omit_the_semantic_fields(
    tmp_path: Path,
) -> None:
    """The `CandidateFinding` extension is optional, so the seven existing
    adapters keep validating without emitting any of the new keys."""

    catalog = SourceCatalog(SOURCE_ROOT)
    semgrep_path = write_json(
        tmp_path / "semgrep.json",
        {
            "results": [
                {
                    "check_id": "java.sql.concatenated-query",
                    "path": SINK_PATH,
                    "start": {"line": 7, "col": 9},
                    "end": {"line": 7, "col": 73},
                    "extra": {
                        "message": "Concatenated SQL reaches Statement.execute",
                        "severity": "ERROR",
                        "metadata": {"cwe": ["CWE-89"], "category": "sql-injection"},
                    },
                }
            ]
        },
    )
    gitleaks_path = write_json(
        tmp_path / "gitleaks.json",
        [
            {
                "RuleID": "generic-api-key",
                "Description": "Generic API key",
                "File": "pom.xml",
                "StartLine": 1,
                "EndLine": 1,
            }
        ],
    )

    produced = [
        *normalize_semgrep(
            semgrep_path,
            catalog=catalog,
            snapshot_sha256=SNAPSHOT_SHA,
        ),
        *normalize_gitleaks(
            gitleaks_path,
            catalog=catalog,
            snapshot_sha256=SNAPSHOT_SHA,
        ),
    ]

    assert len(produced) == 2
    for raw in produced:
        assert not set(raw) & set(SEMANTIC_FIELDS)
        model = CandidateFinding.model_validate(raw)
        assert model.call_chain == []
        assert model.existing_defenses == []
        assert model.controllability is None
        assert model.attack_preconditions is None
        assert model.impact is None
        assert model.recommended_verification is None
        assert model.severity_conflict == []


def test_a_real_scanner_candidate_merges_with_a_semantic_candidate(
    tmp_path: Path,
) -> None:
    """Drive a real adapter end to end: CodeQL SARIF and the semantic reviewer
    reach the same `root_cause_key`, and the merge keeps the model's evidence."""

    sarif_path = write_json(
        tmp_path / "codeql.sarif",
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "CodeQL",
                            "rules": [
                                {
                                    "id": "java/sql-injection",
                                    "properties": {
                                        "tags": ["external/cwe/cwe-89"],
                                        "precision": "high",
                                        "problem.severity": "error",
                                    },
                                }
                            ],
                        }
                    },
                    "results": [
                        {
                            "ruleId": "java/sql-injection",
                            "level": "error",
                            "message": {"text": "Query is built from user input"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": SINK_PATH},
                                        "region": {"startLine": 7, "endLine": 7},
                                    }
                                }
                            ],
                        }
                    ],
                }
            ],
        },
    )
    scanner = normalize_sarif(
        sarif_path,
        catalog=SourceCatalog(SOURCE_ROOT),
        snapshot_sha256=SNAPSHOT_SHA,
    )[0]
    semantic = semantic_candidate(
        category=str(scanner["category"]),
        cwe_ids=list(scanner["cwe_ids"]),  # type: ignore[arg-type]
    )
    assert scanner["root_cause_key"] == semantic["root_cause_key"]

    merged = merge_candidates([scanner, semantic])[0]

    CandidateFinding.model_validate(merged)
    assert merged["discovered_by"] == ["codeql", "semantic-reviewer"]
    assert merged["call_chain"] == CALL_CHAIN
    assert merged["controllability"] == semantic["controllability"]
    assert merge_candidates([merged, scanner])[0] == merged
