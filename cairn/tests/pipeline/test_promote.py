"""The Finding Pipeline's data contract and location validation (§6.14).

The pipeline is the only place a model- or scanner-produced candidate becomes
something a report will show a human, so its job is to refuse rather than to
accommodate. These tests are mostly about what it declines to promote.
"""

from __future__ import annotations

from io import BytesIO
from pathlib import Path
import tarfile
from uuid import uuid4

import pytest

from cairn.analysis.bytecode_sinks import _RULES as BYTECODE_SINK_RULES
from cairn.analysis.config_rules import _RULES as CONFIG_RULES
from cairn.analysis.contracts import ProgramIndexV2
from cairn.orchestrator.semantic_tasks import (
    CATEGORY_AUTHORIZATION,
    CATEGORY_SPRING_SECURITY,
    SINK_CATEGORIES,
)
from cairn.pipeline.catalogue import (
    CATEGORY_LABELS,
    GENERIC_REMEDIATION,
    REMEDIATION_BY_CWE,
    category_label,
    owasp_for,
    remediation_for,
)
from cairn.pipeline.promote import (
    REASON_CONTRACT_INVALID,
    REASON_LOCATION_NOT_IN_PROGRAM_INDEX,
    REASON_NO_CWE,
    REASON_PATH_MISSING,
    REASON_PROGRAM_INDEX_REQUIRED,
    promote_candidates,
)
from cairn.pipeline.snippets import (
    BLANK_MARKER,
    MAX_SNIPPET_LINES,
    TRUNCATION_MARKER,
    read_files,
)

SOURCE = "web/src/main/java/dev/cairn/OrderController.java"
OTHER = "core/src/main/java/dev/cairn/OrderRepository.java"
SNAPSHOT_SHA = "c" * 64
CONTAINER = "sample.war"
ENTRY = "WEB-INF/lib/app.jar!/demo/Action.class"
LOGICAL = f"{CONTAINER}!/{ENTRY}"
CLASS_NAME = "demo.Action"
METHOD_NAME = "execute"
METHOD_DESCRIPTOR = "(Ljava/lang/String;)V"
BYTECODE_OFFSET = 18


def write_archive(path: Path, files: dict[str, str]) -> Path:
    with tarfile.open(path, mode="w") as archive:
        for name, body in files.items():
            data = body.encode("utf-8")
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mtime = 0
            archive.addfile(info, BytesIO(data))
    return path


@pytest.fixture
def archive(tmp_path: Path) -> Path:
    body = "\n".join(f"line {index}" for index in range(1, 61)) + "\n"
    return write_archive(
        tmp_path / "snapshot.tar",
        {SOURCE: body, OTHER: body},
    )


def candidate(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "rule_id": "sql-injection-in-order-lookup",
        "cwe_ids": ["CWE-89"],
        "category": "sql-injection",
        "severity": "high",
        "confidence": "medium",
        "message": "A request parameter reaches a concatenated SQL statement.",
        "locations": [
            {
                "path": SOURCE,
                "start_line": 12,
                "end_line": 14,
                "symbol": "OrderController.list",
                "role": "sink",
            }
        ],
        "sink": "Statement.executeQuery",
        "fingerprint": "a" * 64,
        "root_cause_key": "b" * 64,
        "discovered_by": ["semgrep"],
        "source_rules": ["java.lang.security.audit.sqli"],
        "call_chain": [
            {
                "path": SOURCE,
                "start_line": 8,
                "end_line": 9,
                "symbol": "OrderController.list",
                "role": "entrypoint",
            },
            {
                "path": SOURCE,
                "start_line": 12,
                "end_line": 14,
                "symbol": "OrderController.list",
                "role": "sink",
            },
        ],
        "controllability": "The `q` query parameter is concatenated unchanged.",
        "attack_preconditions": "Any authenticated user can reach the endpoint.",
        "impact": "Full read of the orders table.",
        "recommended_verification": "Send q=' OR '1'='1 and compare row counts.",
    }
    payload.update(overrides)
    return payload


def promote(
    candidates: list[dict[str, object]],
    archive: Path,
    *,
    program_index: ProgramIndexV2 | None = None,
):
    return promote_candidates(
        candidates,
        audit_run_id=uuid4(),
        archive_path=archive,
        snapshot_sha256=SNAPSHOT_SHA,
        program_index=program_index,
    )


def bytecode_location(**overrides: object) -> dict[str, object]:
    location: dict[str, object] = {
        "origin_kind": "bytecode",
        "container_path": CONTAINER,
        "entry_path": ENTRY,
        "class_name": CLASS_NAME,
        "method_name": METHOD_NAME,
        "method_descriptor": METHOD_DESCRIPTOR,
        "bytecode_offset": BYTECODE_OFFSET,
        "source_path": None,
        "start_line": None,
        "end_line": None,
        "decompiled_artifact_id": None,
        "decompiled_start_line": None,
        "decompiled_end_line": None,
        "symbol": f"{CLASS_NAME}.{METHOD_NAME}",
        "role": "sink",
    }
    location.update(overrides)
    return location


def program_index(
    *,
    logical_path: str = LOGICAL,
    container_path: str | None = CONTAINER,
    entry_path: str = ENTRY,
    class_name: str = CLASS_NAME,
    method_name: str = METHOD_NAME,
    method_descriptor: str = METHOD_DESCRIPTOR,
    bytecode_offset: int = BYTECODE_OFFSET,
    source_line: int | None = None,
) -> ProgramIndexV2:
    identity = {
        "logical_path": logical_path,
        "container_path": container_path,
        "entry_path": entry_path,
        "class_sha256": "d" * 64,
        "class_name": class_name,
    }
    return ProgramIndexV2.model_validate(
        {
            "contract": "cairn-program-index-v2",
            "asm_version": "9.8",
            "target_java_version": 17,
            "components": [],
            "resources": [],
            "classes": [
                {
                    **identity,
                    "super_name": "java.lang.Object",
                    "interfaces": [],
                    "access": 1,
                    "classfile_major": 61,
                    "signature": None,
                    "source_file": "Action.java" if source_line else None,
                    "annotations": [],
                }
            ],
            "methods": [
                {
                    **identity,
                    "method_name": method_name,
                    "method_descriptor": method_descriptor,
                    "access": 1,
                    "signature": None,
                    "exceptions": [],
                    "annotations": [],
                    "start_line": source_line,
                    "end_line": source_line,
                    "first_bytecode_offset": 0,
                    "last_bytecode_offset": max(bytecode_offset, 24),
                }
            ],
            "fields": [],
            "calls": [
                {
                    **identity,
                    "method_name": method_name,
                    "method_descriptor": method_descriptor,
                    "bytecode_offset": bytecode_offset,
                    "source_line": source_line,
                    "opcode": 184,
                    "edge_kind": "exact",
                    "target_owner": "java.sql.Statement",
                    "target_name": "execute",
                    "target_descriptor": "(Ljava/lang/String;)Z",
                    "interface": False,
                    "callsite_name": None,
                    "callsite_descriptor": None,
                    "bootstrap_owner": None,
                    "bootstrap_name": None,
                    "bootstrap_descriptor": None,
                }
            ],
            "field_accesses": [],
            "decompiled_views": [],
            "coverage_gaps": [],
            "classes_total": 1,
            "classes_parsed": 1,
        }
    )


# --- what the pipeline promotes ----------------------------------------------


def test_a_complete_candidate_becomes_a_finding_command(archive: Path) -> None:
    result = promote([candidate()], archive)

    assert not result.rejections
    command = result.commands[0]
    assert command.cwe_id == "CWE-89"
    assert command.owasp_category == "A03:2021 Injection"
    assert command.severity.value == "high"
    assert command.confidence.value == "medium"
    assert command.remediation == REMEDIATION_BY_CWE["CWE-89"]
    assert command.title == "SQL 注入：OrderController.list"


def test_the_description_frames_the_evidence_in_chinese(archive: Path) -> None:
    """Every label the platform adds is Chinese; the candidate's own prose is not
    touched, so a scanner's rule message stays traceable to the raw output."""

    command = promote(
        [
            candidate(
                existing_defenses=[
                    {
                        "mechanism": "OrderValidator.check",
                        "effective": False,
                        "reasoning": "只校验长度，不影响引号。",
                    }
                ],
            )
        ],
        archive,
    ).commands[0]

    paragraphs = command.description.split("\n\n")
    assert paragraphs[0] == "A request parameter reaches a concatenated SQL statement."
    assert paragraphs[1].startswith("可控性：")
    assert paragraphs[2] == (
        f"调用链：OrderController.list（{SOURCE}:8）经 2 步"
        f"到达 OrderController.list（{SOURCE}:12）。"
    )
    assert paragraphs[3].startswith("已有防护（未生效）：OrderValidator.check —— ")
    assert paragraphs[4].startswith("建议验证方式：")
    assert paragraphs[-1] == "发现来源：semgrep。"


def test_v1_title_without_a_symbol_keeps_the_path_only(archive: Path) -> None:
    command = promote(
        [
            candidate(
                call_chain=[],
                locations=[
                    {
                        "path": SOURCE,
                        "start_line": 12,
                        "end_line": 14,
                        "symbol": None,
                        "role": "sink",
                    }
                ],
            )
        ],
        archive,
    ).commands[0]

    assert command.title == f"SQL 注入：{SOURCE}"


def test_locations_lead_with_the_call_chain_in_order(archive: Path) -> None:
    """The list should read as the path an attacker takes, not as a set."""

    command = promote([candidate()], archive).commands[0]

    assert [(location.role.value, location.start_line) for location in command.locations] == [
        ("entrypoint", 8),
        ("sink", 12),
    ]
    assert [location.ordinal for location in command.locations] == [0, 1]


def test_every_location_is_bound_to_the_snapshot_it_was_read_from(
    archive: Path,
) -> None:
    command = promote([candidate()], archive).commands[0]

    assert all(
        location.snapshot_sha == SNAPSHOT_SHA for location in command.locations
    )
    assert command.locations[0].code_snippet == "line 8\nline 9"


def test_a_scanner_candidate_without_prose_gets_honest_placeholders(
    archive: Path,
) -> None:
    """Missing evidence is reported as missing, not invented."""

    command = promote(
        [
            candidate(
                call_chain=[],
                controllability=None,
                attack_preconditions=None,
                impact=None,
                recommended_verification=None,
            )
        ],
        archive,
    ).commands[0]

    assert "尚未确认" in command.attack_preconditions
    assert "semgrep" in command.attack_preconditions
    assert "尚未确认" in command.impact


# --- bytecode evidence --------------------------------------------------------


def test_bytecode_location_is_promoted_from_index_without_reading_snapshot_as_source(
    tmp_path: Path,
) -> None:
    artifact_id = uuid4()
    not_a_snapshot = tmp_path / "opaque.snapshot"
    not_a_snapshot.write_bytes(b"this is deliberately not a tar archive")
    location = bytecode_location(
        origin_kind="decompiled",
        decompiled_artifact_id=str(artifact_id),
        decompiled_start_line=31,
        decompiled_end_line=34,
    )

    result = promote(
        [
            candidate(
                locations=[location],
                call_chain=[],
                discovered_by=["asm-index"],
                source_rules=["bytecode-sql-sink"],
            )
        ],
        not_a_snapshot,
        program_index=program_index(),
    )

    assert not result.rejections
    promoted = result.commands[0].locations[0]
    assert promoted.origin_kind.value == "decompiled"
    assert promoted.container_path == CONTAINER
    assert promoted.entry_path == ENTRY
    assert promoted.class_name == CLASS_NAME
    assert promoted.method_name == METHOD_NAME
    assert promoted.method_descriptor == METHOD_DESCRIPTOR
    assert promoted.bytecode_offset == BYTECODE_OFFSET
    assert promoted.decompiled_artifact_id == artifact_id
    assert (promoted.decompiled_start_line, promoted.decompiled_end_line) == (31, 34)
    assert promoted.file_path is None
    assert promoted.start_line is None
    assert promoted.end_line is None
    assert promoted.code_snippet is None


def test_bytecode_location_requires_a_program_index(tmp_path: Path) -> None:
    result = promote(
        [candidate(locations=[bytecode_location()], call_chain=[])],
        tmp_path / "unused.snapshot",
    )

    assert not result.commands
    assert result.rejections[0].reason_code == REASON_PROGRAM_INDEX_REQUIRED
    assert "ProgramIndexV2" in result.rejections[0].detail


@pytest.mark.parametrize(
    "index_overrides",
    [
        {"logical_path": "different.war!/WEB-INF/classes/demo/Action.class"},
        {"container_path": "different.war"},
        {"entry_path": "WEB-INF/classes/demo/Other.class"},
        {"class_name": "demo.OtherAction"},
        {"method_name": "run"},
        {"method_descriptor": "()V"},
        {"bytecode_offset": BYTECODE_OFFSET + 1},
    ],
)
def test_bytecode_location_must_exactly_match_the_program_index(
    tmp_path: Path,
    index_overrides: dict[str, object],
) -> None:
    result = promote(
        [candidate(locations=[bytecode_location()], call_chain=[])],
        tmp_path / "unused.snapshot",
        program_index=program_index(**index_overrides),
    )

    assert not result.commands
    assert (
        result.rejections[0].reason_code
        == REASON_LOCATION_NOT_IN_PROGRAM_INDEX
    )
    assert "ProgramIndexV2" in result.rejections[0].detail


def test_bytecode_source_line_is_preserved_only_when_the_index_substantiates_it(
    tmp_path: Path,
) -> None:
    location = bytecode_location(
        source_path=SOURCE,
        start_line=41,
        end_line=41,
    )
    result = promote(
        [candidate(locations=[location], call_chain=[])],
        tmp_path / "not-read.snapshot",
        program_index=program_index(source_line=41),
    )

    assert not result.rejections
    promoted = result.commands[0].locations[0]
    assert promoted.source_path == SOURCE
    assert (promoted.start_line, promoted.end_line) == (41, 41)
    assert promoted.code_snippet is None

    mismatched = promote(
        [
            candidate(
                locations=[
                    bytecode_location(
                        source_path=SOURCE,
                        start_line=42,
                        end_line=42,
                    )
                ],
                call_chain=[],
            )
        ],
        tmp_path / "also-not-read.snapshot",
        program_index=program_index(source_line=41),
    )
    assert not mismatched.commands
    assert (
        mismatched.rejections[0].reason_code
        == REASON_LOCATION_NOT_IN_PROGRAM_INDEX
    )


def test_absent_bytecode_source_line_is_not_synthesized_from_the_index(
    tmp_path: Path,
) -> None:
    result = promote(
        [candidate(locations=[bytecode_location()], call_chain=[])],
        tmp_path / "not-read.snapshot",
        program_index=program_index(source_line=41),
    )

    promoted = result.commands[0].locations[0]
    assert promoted.start_line is None
    assert promoted.end_line is None
    assert promoted.code_snippet is None


def test_mixed_v1_v2_call_chain_is_ordered_and_deduplicated(
    archive: Path,
) -> None:
    binary_sink = bytecode_location()
    result = promote(
        [
            candidate(
                locations=[binary_sink],
                call_chain=[
                    {
                        "path": SOURCE,
                        "start_line": 8,
                        "end_line": 9,
                        "symbol": "OrderController.list",
                        "role": "entrypoint",
                    },
                    binary_sink,
                ],
            )
        ],
        archive,
        program_index=program_index(),
    )

    assert not result.rejections
    locations = result.commands[0].locations
    assert len(locations) == 2
    assert [location.ordinal for location in locations] == [0, 1]
    assert [location.origin_kind.value for location in locations] == [
        "source",
        "bytecode",
    ]
    assert locations[0].code_snippet == "line 8\nline 9"
    assert locations[1].bytecode_offset == BYTECODE_OFFSET
    assert locations[1].code_snippet is None


# --- what the pipeline refuses -----------------------------------------------


def test_a_candidate_naming_no_cwe_is_rejected(archive: Path) -> None:
    """`Finding.cwe_id` is mandatory, and inventing one would put a weakness
    class into a report that no tool claimed."""

    result = promote([candidate(cwe_ids=[])], archive)

    assert not result.commands
    assert [rejection.reason_code for rejection in result.rejections] == [REASON_NO_CWE]


def test_a_location_past_the_end_of_the_file_fails_its_candidate(
    archive: Path,
) -> None:
    result = promote(
        [
            candidate(
                call_chain=[],
                locations=[
                    {
                        "path": SOURCE,
                        "start_line": 900,
                        "end_line": 901,
                        "symbol": None,
                        "role": "sink",
                    }
                ],
            )
        ],
        archive,
    )

    assert not result.commands
    assert result.rejections[0].reason_code == "PIPELINE_LOCATION_OUT_OF_RANGE"


def test_a_location_the_snapshot_does_not_contain_fails_its_candidate(
    archive: Path,
) -> None:
    result = promote(
        [
            candidate(
                call_chain=[],
                locations=[
                    {
                        "path": "web/src/main/java/dev/cairn/Absent.java",
                        "start_line": 1,
                        "end_line": 2,
                        "symbol": None,
                        "role": "sink",
                    }
                ],
            )
        ],
        archive,
    )

    assert not result.commands
    assert result.rejections[0].reason_code == REASON_PATH_MISSING


def test_one_unsubstantiated_location_rejects_the_whole_candidate(
    archive: Path,
) -> None:
    """A Finding showing three of four locations would read as complete."""

    result = promote(
        [
            candidate(
                call_chain=[],
                locations=[
                    {
                        "path": SOURCE,
                        "start_line": 12,
                        "end_line": 14,
                        "symbol": None,
                        "role": "sink",
                    },
                    {
                        "path": "web/src/main/java/dev/cairn/Absent.java",
                        "start_line": 1,
                        "end_line": 1,
                        "symbol": None,
                        "role": "related",
                    },
                ],
            )
        ],
        archive,
    )

    assert not result.commands
    assert result.rejections[0].reason_code == REASON_PATH_MISSING


def test_a_payload_that_is_not_a_candidate_is_recorded_not_raised(
    archive: Path,
) -> None:
    result = promote([{"root_cause_key": "d" * 64, "rule_id": ""}], archive)

    assert not result.commands
    assert result.rejections[0].reason_code == REASON_CONTRACT_INVALID
    assert result.rejections[0].root_cause_key == "d" * 64


def test_an_unreadable_snapshot_rejects_every_candidate_without_raising(
    tmp_path: Path,
) -> None:
    """The other stages' results stay valid; only promotion fails."""

    broken = tmp_path / "broken.tar"
    broken.write_bytes(b"not a tar archive at all")

    result = promote([candidate()], broken)

    assert not result.commands
    assert result.rejections[0].reason_code == "PIPELINE_SNAPSHOT_INVALID"


# --- determinism --------------------------------------------------------------


def test_promotion_is_deterministic_across_runs(archive: Path) -> None:
    """A resumed run must promote the same candidates in the same order."""

    first = candidate(fingerprint="1" * 64, root_cause_key="2" * 64)
    second = candidate(fingerprint="0" * 64, root_cause_key="3" * 64)

    forward = promote([first, second], archive)
    reverse = promote([second, first], archive)

    assert [command.fingerprint for command in forward.commands] == [
        "0" * 64,
        "1" * 64,
    ]
    assert [command.fingerprint for command in reverse.commands] == [
        command.fingerprint for command in forward.commands
    ]


# --- the deterministic catalogue ---------------------------------------------


def test_an_unmapped_cwe_falls_back_to_the_category_then_to_a_stated_gap() -> None:
    assert remediation_for("CWE-9999", "ssrf") == REMEDIATION_BY_CWE["CWE-918"]
    assert remediation_for("CWE-9999", "not-a-category") == GENERIC_REMEDIATION
    # The generic text says there is no specific guidance rather than inventing
    # some, so a reader can tell advice from a gap.
    assert "没有内置的修复建议" in GENERIC_REMEDIATION


def test_an_unmapped_cwe_yields_no_owasp_category_rather_than_a_guess() -> None:
    assert owasp_for("CWE-9999") is None
    assert owasp_for("cwe-918") == "A10:2021 Server-Side Request Forgery"


def test_every_remediation_the_platform_stands_behind_is_written_in_chinese() -> None:
    """A reviewer reading a Chinese workbench must not meet an English paragraph."""

    for cwe_id, text in REMEDIATION_BY_CWE.items():
        assert _has_cjk(text), cwe_id
    assert _has_cjk(GENERIC_REMEDIATION)


def test_every_category_the_platform_itself_assigns_has_a_chinese_label() -> None:
    """Titles are built from these labels.

    Derived from the tables rather than listed by hand: a new sink rule or
    config rule that invents a category would otherwise fall back to its
    English slug in the title and nobody would notice. That fallback is right
    for a scanner's own vocabulary and wrong for ours.
    """

    ours = (
        set(SINK_CATEGORIES.values())
        | {CATEGORY_AUTHORIZATION, CATEGORY_SPRING_SECURITY}
        | {rule.category for rule in BYTECODE_SINK_RULES}
        | {rule[-1] for rule in CONFIG_RULES}
    )

    assert ours <= set(CATEGORY_LABELS)
    assert all(_has_cjk(CATEGORY_LABELS[category]) for category in ours)


def test_the_platforms_own_config_rule_messages_are_written_in_chinese() -> None:
    """A third-party scanner's rule text passes through untranslated because it
    is evidence; these messages are Cairn's own statement and are not."""

    for rule in CONFIG_RULES:
        assert _has_cjk(rule[3]), rule[2]


def test_an_unknown_scanner_category_keeps_its_slug_rather_than_being_guessed() -> None:
    assert category_label("prototype-pollution", "Prototype pollution") == (
        "Prototype pollution"
    )


def _has_cjk(text: str) -> bool:
    return any("一" <= character <= "鿿" for character in text)


# --- snippet extraction -------------------------------------------------------


def test_a_long_range_is_truncated_and_says_so(tmp_path: Path) -> None:
    body = "\n".join(f"line {index}" for index in range(1, 201)) + "\n"
    path = write_archive(tmp_path / "s.tar", {SOURCE: body})

    text = read_files(path, {SOURCE})[SOURCE]
    snippet = text.snippet(1, 200)

    assert snippet.endswith(TRUNCATION_MARKER)
    assert len(snippet.splitlines()) == MAX_SNIPPET_LINES + 1


def test_a_blank_line_still_produces_a_non_empty_snippet(tmp_path: Path) -> None:
    """`code_snippet` requires at least one character."""

    path = write_archive(tmp_path / "s.tar", {SOURCE: "alpha\n\nbeta\n"})

    assert read_files(path, {SOURCE})[SOURCE].snippet(2, 2) == BLANK_MARKER


def test_archive_members_escaping_the_root_are_not_served(tmp_path: Path) -> None:
    path = write_archive(
        tmp_path / "s.tar",
        {"../../etc/passwd": "root:x:0:0\n", "/absolute": "x\n"},
    )

    assert read_files(path, {"../../etc/passwd", "/absolute"}) == {}
