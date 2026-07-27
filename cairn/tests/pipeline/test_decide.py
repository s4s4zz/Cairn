"""The §7.8 machine-review decision rule, exercised as a table.

§7.8's two confirmation paths and §7.7's "never rejected" rule interact in ways
that are easy to state and easy to get wrong, so every cell is asserted rather
than sampled.
"""

from __future__ import annotations

import pytest

from cairn.pipeline.decide import (
    WARN_CONFLICT,
    WARN_INCONCLUSIVE,
    WARN_SINGLE_CONCLUSION,
    decide,
    independent_conclusions,
)
from cairn.server.domain.enums import (
    FindingConfidence,
    FindingSeverity,
    FindingStatus,
    RuntimeVerificationStatus,
    VerificationVerdict,
)

CONFIRMED = VerificationVerdict.CONFIRMED
REJECTED = VerificationVerdict.REJECTED
INCONCLUSIVE = VerificationVerdict.INCONCLUSIVE


def judge(
    *,
    severity: FindingSeverity = FindingSeverity.HIGH,
    blind: VerificationVerdict | None = INCONCLUSIVE,
    dynamic: VerificationVerdict = INCONCLUSIVE,
    tools: int = 1,
    cwe_id: str = "CWE-89",
):
    return decide(
        severity=severity,
        blind_verdict=blind,
        dynamic_verdict=dynamic,
        discovered_by_count=tools,
        cwe_id=cwe_id,
    )


# --- counting independent conclusions ----------------------------------------


@pytest.mark.parametrize(
    ("blind", "tools", "expected"),
    [
        # The original discoverer is not a corroboration, hence the -1.
        (None, 1, 0),
        (None, 2, 1),
        (CONFIRMED, 1, 1),
        (CONFIRMED, 2, 2),
        (CONFIRMED, 3, 3),
        (REJECTED, 2, 1),
        (INCONCLUSIVE, 2, 1),
    ],
)
def test_conclusions_count_corroborating_tools_and_the_blind_review(
    blind: VerificationVerdict | None,
    tools: int,
    expected: int,
) -> None:
    assert (
        independent_conclusions(blind_verdict=blind, discovered_by_count=tools)
        == expected
    )


# --- critical and high --------------------------------------------------------


def test_confirmation_plus_a_corroborating_tool_completes_the_static_path() -> None:
    """§7.8 path two: two independent static conclusions, runtime unverified."""

    decision = judge(blind=CONFIRMED, tools=2)

    assert decision.status is FindingStatus.MACHINE_CONFIRMED
    assert decision.confidence is FindingConfidence.CONFIRMED
    assert decision.runtime_verification is RuntimeVerificationStatus.UNVERIFIED
    assert decision.warning_code is None
    assert decision.enters_human_queue


def test_confirmation_plus_runtime_proof_completes_the_dynamic_path() -> None:
    """§7.8 path one, which 6b's real verdicts will start reaching."""

    decision = judge(blind=CONFIRMED, dynamic=CONFIRMED, tools=1)

    assert decision.confidence is FindingConfidence.CONFIRMED
    assert decision.runtime_verification is RuntimeVerificationStatus.VERIFIED
    assert decision.warning_code is None


def test_a_lone_confirmation_does_not_raise_confidence() -> None:
    """One opinion is not two independent static conclusions."""

    decision = judge(blind=CONFIRMED, tools=1)

    assert decision.status is FindingStatus.MACHINE_CONFIRMED
    assert decision.confidence is None
    assert decision.warning_code == WARN_SINGLE_CONCLUSION
    assert decision.enters_human_queue


def test_a_rejection_with_nothing_behind_the_candidate_ends_it() -> None:
    decision = judge(blind=REJECTED, tools=1)

    assert decision.status is FindingStatus.REJECTED
    assert not decision.enters_human_queue


def test_a_rejection_against_corroborating_tools_goes_to_a_human() -> None:
    """A conflict is routed, not settled — the same rule §7.6 sets for severity."""

    decision = judge(blind=REJECTED, tools=2)

    assert decision.status is FindingStatus.MACHINE_CONFIRMED
    assert decision.warning_code == WARN_CONFLICT
    assert decision.confidence is None
    assert decision.enters_human_queue


def test_a_rejection_contradicted_by_runtime_goes_to_a_human() -> None:
    decision = judge(blind=REJECTED, dynamic=CONFIRMED, tools=1)

    assert decision.status is FindingStatus.MACHINE_CONFIRMED
    assert decision.warning_code == WARN_CONFLICT


def test_a_confirmation_contradicted_by_runtime_goes_to_a_human() -> None:
    decision = judge(blind=CONFIRMED, dynamic=REJECTED, tools=3)

    assert decision.status is FindingStatus.MACHINE_CONFIRMED
    assert decision.warning_code == WARN_CONFLICT
    assert decision.confidence is None


def test_an_inconclusive_review_reaches_a_human_without_being_confirmed() -> None:
    """The stage ran, so the §13.6 gate is satisfied; nothing was established,
    so nothing is promoted."""

    decision = judge(blind=INCONCLUSIVE, tools=3)

    assert decision.status is FindingStatus.MACHINE_CONFIRMED
    assert decision.confidence is None
    assert decision.warning_code == WARN_INCONCLUSIVE
    assert decision.enters_human_queue


@pytest.mark.parametrize("severity", [FindingSeverity.CRITICAL, FindingSeverity.HIGH])
def test_nothing_that_went_wrong_can_reject_a_critical_or_high_finding(
    severity: FindingSeverity,
) -> None:
    """§7.7's rule holds for this stage too: only a reasoned rejection rejects."""

    for dynamic in (INCONCLUSIVE, CONFIRMED):
        decision = judge(severity=severity, blind=INCONCLUSIVE, dynamic=dynamic, tools=1)
        assert decision.status is not FindingStatus.REJECTED


# --- medium and below ---------------------------------------------------------


@pytest.mark.parametrize(
    "severity",
    [FindingSeverity.MEDIUM, FindingSeverity.LOW, FindingSeverity.INFO],
)
def test_medium_and_below_settle_without_independent_review(
    severity: FindingSeverity,
) -> None:
    """§7.9 does not force these through human confirmation."""

    decision = judge(severity=severity, blind=None, tools=1)

    assert decision.status is FindingStatus.MACHINE_CONFIRMED
    assert decision.runtime_verification is RuntimeVerificationStatus.UNVERIFIED
    assert not decision.enters_human_queue


def test_medium_findings_runtime_rejected_are_dropped() -> None:
    decision = judge(severity=FindingSeverity.MEDIUM, blind=None, dynamic=REJECTED)

    assert decision.status is FindingStatus.REJECTED


def test_medium_findings_runtime_confirmed_are_marked_verified() -> None:
    decision = judge(severity=FindingSeverity.MEDIUM, blind=None, dynamic=CONFIRMED)

    assert decision.runtime_verification is RuntimeVerificationStatus.VERIFIED
    assert decision.confidence is FindingConfidence.CONFIRMED


# --- runtime applicability ----------------------------------------------------


@pytest.mark.parametrize("cwe_id", ["CWE-798", "CWE-522", "CWE-1104"])
def test_weaknesses_no_request_can_exercise_are_not_applicable(cwe_id: str) -> None:
    """Marking a hardcoded credential `unverified` implies a runtime check is
    still owed. `not_applicable` says plainly that none is possible."""

    decision = judge(blind=CONFIRMED, tools=2, cwe_id=cwe_id)

    assert decision.runtime_verification is RuntimeVerificationStatus.NOT_APPLICABLE


def test_a_runtime_verifiable_weakness_stays_unverified_until_it_is_run() -> None:
    decision = judge(blind=CONFIRMED, tools=2, cwe_id="CWE-89")

    assert decision.runtime_verification is RuntimeVerificationStatus.UNVERIFIED
