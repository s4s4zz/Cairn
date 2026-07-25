import pytest

from cairn.server.domain.enums import (
    ArtifactAccessLevel,
    ArtifactKind,
    AuditFactKind,
    AuditIntentStatus,
    AuditRunStatus,
    AuditStage,
    AuditTaskStatus,
    AuditTaskType,
    BuildStatus,
    BuildSystem,
    DynamicVerificationMode,
    EvidenceType,
    FindingConfidence,
    FindingSeverity,
    FindingStatus,
    LocationRole,
    ReviewVerdict,
    RuntimeVerificationStatus,
    SnapshotStatus,
    SourceType,
    VerificationMethod,
    VerificationVerdict,
)
from cairn.server.domain.state_machines import (
    InvalidTransition,
    transition_audit_run,
    transition_finding,
)


def values(enum_type: type) -> set[str]:
    return {member.value for member in enum_type}


def test_audit_run_follows_fixed_pipeline() -> None:
    pipeline = [
        AuditRunStatus.CREATED,
        AuditRunStatus.INGESTING,
        AuditRunStatus.PREPROCESSING,
        AuditRunStatus.STATIC_SCANNING,
        AuditRunStatus.SEMANTIC_AUDITING,
        AuditRunStatus.DYNAMIC_VERIFYING,
        AuditRunStatus.MACHINE_REVIEW,
        AuditRunStatus.HUMAN_REVIEW,
        AuditRunStatus.REPORTING,
        AuditRunStatus.COMPLETED,
    ]

    for current, target in zip(pipeline[:-1], pipeline[1:], strict=True):
        assert transition_audit_run(current, target) is target


def test_audit_run_cannot_skip_to_completed() -> None:
    with pytest.raises(InvalidTransition):
        transition_audit_run(AuditRunStatus.CREATED, AuditRunStatus.COMPLETED)


def test_dynamic_stage_is_explicit_even_when_execution_is_disabled() -> None:
    with pytest.raises(InvalidTransition):
        transition_audit_run(
            AuditRunStatus.SEMANTIC_AUDITING,
            AuditRunStatus.MACHINE_REVIEW,
        )

    assert (
        transition_audit_run(
            AuditRunStatus.SEMANTIC_AUDITING,
            AuditRunStatus.DYNAMIC_VERIFYING,
        )
        is AuditRunStatus.DYNAMIC_VERIFYING
    )
    assert (
        transition_audit_run(
            AuditRunStatus.DYNAMIC_VERIFYING,
            AuditRunStatus.MACHINE_REVIEW,
        )
        is AuditRunStatus.MACHINE_REVIEW
    )


@pytest.mark.parametrize(
    "status",
    [
        AuditRunStatus.CREATED,
        AuditRunStatus.INGESTING,
        AuditRunStatus.PREPROCESSING,
        AuditRunStatus.STATIC_SCANNING,
        AuditRunStatus.SEMANTIC_AUDITING,
        AuditRunStatus.DYNAMIC_VERIFYING,
        AuditRunStatus.MACHINE_REVIEW,
        AuditRunStatus.HUMAN_REVIEW,
        AuditRunStatus.REPORTING,
    ],
)
def test_active_audit_run_can_be_cancelled_or_failed(
    status: AuditRunStatus,
) -> None:
    assert (
        transition_audit_run(status, AuditRunStatus.CANCELLING)
        is AuditRunStatus.CANCELLING
    )
    assert transition_audit_run(status, AuditRunStatus.FAILED) is AuditRunStatus.FAILED


@pytest.mark.parametrize(
    "status",
    [
        AuditRunStatus.COMPLETED,
        AuditRunStatus.COMPLETED_WITH_WARNINGS,
        AuditRunStatus.CANCELLED,
        AuditRunStatus.FAILED,
    ],
)
def test_terminal_audit_run_cannot_transition(status: AuditRunStatus) -> None:
    with pytest.raises(InvalidTransition):
        transition_audit_run(status, AuditRunStatus.CANCELLING)


def test_high_finding_requires_human_review_state() -> None:
    assert (
        transition_finding(
            FindingStatus.MACHINE_CONFIRMED,
            FindingStatus.AWAITING_HUMAN_REVIEW,
        )
        is FindingStatus.AWAITING_HUMAN_REVIEW
    )


def test_machine_confirmed_finding_cannot_be_directly_accepted_as_risk() -> None:
    with pytest.raises(InvalidTransition):
        transition_finding(
            FindingStatus.MACHINE_CONFIRMED,
            FindingStatus.ACCEPTED_RISK,
        )


def test_reverify_returns_finding_to_validating() -> None:
    assert (
        transition_finding(
            FindingStatus.AWAITING_HUMAN_REVIEW,
            FindingStatus.VALIDATING,
        )
        is FindingStatus.VALIDATING
    )


def test_invalid_transition_error_is_stable() -> None:
    with pytest.raises(InvalidTransition) as captured:
        transition_finding(FindingStatus.CANDIDATE, FindingStatus.CONFIRMED)

    assert str(captured.value) == "invalid finding transition: candidate -> confirmed"


def test_persisted_enum_values_match_the_design() -> None:
    assert values(SourceType) == {"git", "zip", "local_upload"}
    assert values(SnapshotStatus) == {"creating", "ready", "rejected", "failed"}
    assert values(BuildSystem) == {"maven", "gradle", "mixed", "unknown"}
    assert values(DynamicVerificationMode) == {"required", "preferred", "disabled"}
    assert values(AuditStage) == {
        "ingesting",
        "preprocessing",
        "static_scanning",
        "semantic_auditing",
        "dynamic_verifying",
        "machine_review",
        "human_review",
        "reporting",
    }
    assert values(AuditTaskType) == {
        "inventory",
        "build",
        "sast",
        "dependency_scan",
        "secret_scan",
        "config_scan",
        "semantic_review",
        "dynamic_verify",
        "independent_verify",
        "coverage_check",
        "report",
    }
    assert values(AuditTaskStatus) == {
        "queued",
        "claimed",
        "running",
        "succeeded",
        "failed",
        "cancelled",
        "skipped",
    }
    assert values(FindingSeverity) == {"critical", "high", "medium", "low", "info"}
    assert values(FindingConfidence) == {"confirmed", "high", "medium", "low"}
    assert values(FindingStatus) == {
        "candidate",
        "validating",
        "machine_confirmed",
        "awaiting_human_review",
        "confirmed",
        "rejected",
        "accepted_risk",
    }
    assert values(RuntimeVerificationStatus) == {
        "verified",
        "unverified",
        "not_applicable",
    }
    assert values(LocationRole) == {
        "entrypoint",
        "source",
        "propagation",
        "sink",
        "related",
    }
    assert values(ArtifactKind) == {
        "source_snapshot",
        "scan_result",
        "build_log",
        "runtime_log",
        "poc",
        "report",
        "other",
    }
    assert values(ArtifactAccessLevel) == {"normal", "sensitive"}
    assert values(EvidenceType) == {
        "code_snippet",
        "call_trace",
        "tool_result",
        "build_log",
        "unit_test",
        "poc_output",
        "http_exchange",
        "runtime_log",
    }
    assert values(VerificationMethod) == {
        "static_corroboration",
        "independent_agent",
        "build_test",
        "dynamic_poc",
    }
    assert values(VerificationVerdict) == {"confirmed", "rejected", "inconclusive"}
    assert values(BuildStatus) == {"success", "partial", "failed"}
    assert values(ReviewVerdict) == {
        "confirmed",
        "rejected",
        "accepted_risk",
        "reverify",
    }
    assert values(AuditFactKind) == {
        "architecture",
        "entrypoint",
        "trust_boundary",
        "source",
        "sink",
        "candidate_finding",
        "verification_result",
    }
    assert values(AuditIntentStatus) == {
        "pending",
        "claimed",
        "concluded",
        "cancelled",
    }
