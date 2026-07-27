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

from cairn.pipeline.catalogue import (
    GENERIC_REMEDIATION,
    REMEDIATION_BY_CWE,
    owasp_for,
    remediation_for,
)
from cairn.pipeline.promote import (
    REASON_CONTRACT_INVALID,
    REASON_NO_CWE,
    REASON_PATH_MISSING,
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


def promote(candidates: list[dict[str, object]], archive: Path):
    return promote_candidates(
        candidates,
        audit_run_id=uuid4(),
        archive_path=archive,
        snapshot_sha256=SNAPSHOT_SHA,
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
    assert command.title == "SQL injection in OrderController.list"


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

    assert "Not established" in command.attack_preconditions
    assert "semgrep" in command.attack_preconditions
    assert "Not established" in command.impact


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
    assert "no specific remediation on file" in GENERIC_REMEDIATION


def test_an_unmapped_cwe_yields_no_owasp_category_rather_than_a_guess() -> None:
    assert owasp_for("CWE-9999") is None
    assert owasp_for("cwe-918") == "A10:2021 Server-Side Request Forgery"


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
