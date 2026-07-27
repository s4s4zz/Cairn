"""The §7.8 machine-review decision rule.

A pure function over (severity, blind verdict, dynamic verdict, corroboration
count), separated from persistence so the whole table can be tested as a table.

Spec §7.8 gives two confirmation paths::

    original finding + independent worker confirmation + dynamic verification
    original finding + two independent static conclusions + runtime_verification=unverified

and the second is permitted only when a dynamic environment is objectively
unbuildable. What counts as one "independent static conclusion" was settled
for this platform as: one blind independent-agent review, or one *additional*
deterministic tool that reached the same ``root_cause_key`` on its own. The
merge already records the latter — a candidate's ``discovered_by`` lists every
tool that independently produced it — so ``len(discovered_by) - 1`` is the
corroboration count with no extra bookkeeping.

Two conventions worth stating, because the names mislead otherwise:

``MACHINE_CONFIRMED`` means *the machine stage finished*, not *the machine
decided it is real*. It is the only state the finding state machine offers on
the way to human review, and a finding whose verification was inconclusive
still has to reach a human. The actual verdicts live in the ``Verification``
rows and in ``confidence``; only a finding that cleared a full confirmation
path gets ``confidence=confirmed``.

A conflict is never resolved here. When the blind reviewer rejects something
two independent tools found, or when runtime contradicts static, the finding
goes to a human with both verdicts attached. That is the same rule §7.6 sets
for severity disagreement: route it, do not settle it.
"""

from __future__ import annotations

from dataclasses import dataclass

from cairn.server.domain.enums import (
    FindingConfidence,
    FindingSeverity,
    FindingStatus,
    RuntimeVerificationStatus,
    VerificationVerdict,
)

WARN_SINGLE_CONCLUSION = "VERIFICATION_SINGLE_CONCLUSION"
WARN_CONFLICT = "VERIFICATION_CONFLICT"
WARN_INCONCLUSIVE = "VERIFICATION_INCONCLUSIVE"

# Severities §7.8 requires to enter independent review, and §7.9 requires to
# enter the human queue.
REVIEW_REQUIRED_SEVERITIES = frozenset(
    {FindingSeverity.CRITICAL, FindingSeverity.HIGH}
)

# Weaknesses that are properties of the source or the dependency graph rather
# than of a running request. Marking these `unverified` would imply a runtime
# check is still owed; `not_applicable` says plainly that none is possible.
NOT_RUNTIME_VERIFIABLE_CWES = frozenset({"CWE-522", "CWE-798", "CWE-1104"})


@dataclass(frozen=True, slots=True)
class MachineReviewDecision:
    status: FindingStatus
    runtime_verification: RuntimeVerificationStatus
    # None leaves the candidate's own confidence untouched. It is only ever
    # raised on a completed confirmation path, never by a single opinion.
    confidence: FindingConfidence | None
    warning_code: str | None
    enters_human_queue: bool


def independent_conclusions(
    *,
    blind_verdict: VerificationVerdict | None,
    discovered_by_count: int,
) -> int:
    """How many independent static conclusions back this finding.

    The original discoverer is not one of them, hence the ``- 1``: two tools in
    ``discovered_by`` means one of them corroborated the other.
    """

    corroborations = max(0, discovered_by_count - 1)
    if blind_verdict is VerificationVerdict.CONFIRMED:
        return corroborations + 1
    return corroborations


def decide(
    *,
    severity: FindingSeverity,
    blind_verdict: VerificationVerdict | None,
    dynamic_verdict: VerificationVerdict,
    discovered_by_count: int,
    cwe_id: str,
) -> MachineReviewDecision:
    """Apply §7.8 to one finding.

    ``blind_verdict`` is ``None`` only for severities that do not require
    independent review. For critical and high it is always a real verdict:
    a review that could not run is recorded as ``inconclusive``, which keeps
    the §13.6 gate ("critical and high cannot enter the human queue before
    machine review") satisfiable by the presence of the row rather than by
    remembering to check a flag.
    """

    runtime = _runtime_status(dynamic_verdict, cwe_id)

    if severity not in REVIEW_REQUIRED_SEVERITIES:
        # §7.9: medium and below are not forced through human confirmation.
        # They stop at machine_confirmed with the verification they got.
        if dynamic_verdict is VerificationVerdict.REJECTED:
            return MachineReviewDecision(
                FindingStatus.REJECTED,
                RuntimeVerificationStatus.NOT_APPLICABLE,
                None,
                None,
                False,
            )
        return MachineReviewDecision(
            FindingStatus.MACHINE_CONFIRMED,
            runtime,
            FindingConfidence.CONFIRMED
            if dynamic_verdict is VerificationVerdict.CONFIRMED
            else None,
            None,
            False,
        )

    if blind_verdict is VerificationVerdict.CONFIRMED:
        if dynamic_verdict is VerificationVerdict.CONFIRMED:
            # Path one, complete: independent confirmation plus runtime proof.
            return MachineReviewDecision(
                FindingStatus.MACHINE_CONFIRMED,
                RuntimeVerificationStatus.VERIFIED,
                FindingConfidence.CONFIRMED,
                None,
                True,
            )
        if dynamic_verdict is VerificationVerdict.REJECTED:
            # Runtime contradicts the reviewer. A human decides.
            return MachineReviewDecision(
                FindingStatus.MACHINE_CONFIRMED,
                runtime,
                None,
                WARN_CONFLICT,
                True,
            )
        conclusions = independent_conclusions(
            blind_verdict=blind_verdict,
            discovered_by_count=discovered_by_count,
        )
        if conclusions >= 2:
            # Path two: dynamic verification could not settle it, but two
            # independent static conclusions did.
            return MachineReviewDecision(
                FindingStatus.MACHINE_CONFIRMED,
                runtime,
                FindingConfidence.CONFIRMED,
                None,
                True,
            )
        return MachineReviewDecision(
            FindingStatus.MACHINE_CONFIRMED,
            runtime,
            None,
            WARN_SINGLE_CONCLUSION,
            True,
        )

    if blind_verdict is VerificationVerdict.REJECTED:
        corroborations = max(0, discovered_by_count - 1)
        if corroborations == 0 and dynamic_verdict is not VerificationVerdict.CONFIRMED:
            # One discoverer, one reviewer, and the reviewer disagrees. Nothing
            # else stands behind this candidate.
            return MachineReviewDecision(
                FindingStatus.REJECTED,
                RuntimeVerificationStatus.NOT_APPLICABLE,
                None,
                None,
                False,
            )
        # Either independent tools also found it, or runtime reproduced it.
        # Both are conflicts the reviewer's rejection does not settle.
        return MachineReviewDecision(
            FindingStatus.MACHINE_CONFIRMED,
            runtime,
            None,
            WARN_CONFLICT,
            True,
        )

    # Inconclusive, including a refused, timed-out or failed review. The stage
    # ran, so the gate is satisfied; nothing was established, so nothing is
    # promoted, and a human sees it.
    return MachineReviewDecision(
        FindingStatus.MACHINE_CONFIRMED,
        runtime,
        None,
        WARN_INCONCLUSIVE,
        True,
    )


def _runtime_status(
    dynamic_verdict: VerificationVerdict,
    cwe_id: str,
) -> RuntimeVerificationStatus:
    if dynamic_verdict is VerificationVerdict.CONFIRMED:
        return RuntimeVerificationStatus.VERIFIED
    if cwe_id.strip().upper() in NOT_RUNTIME_VERIFIABLE_CWES:
        return RuntimeVerificationStatus.NOT_APPLICABLE
    return RuntimeVerificationStatus.UNVERIFIED
