from dataclasses import dataclass
from enum import StrEnum
from typing import TypeVar

from cairn.server.domain.enums import AuditRunStatus, FindingStatus


@dataclass(slots=True)
class InvalidTransition(ValueError):
    entity: str
    current: str
    target: str

    def __str__(self) -> str:
        return f"invalid {self.entity} transition: {self.current} -> {self.target}"


_ACTIVE_AUDIT_RUN_STATUSES = {
    AuditRunStatus.CREATED,
    AuditRunStatus.INGESTING,
    AuditRunStatus.PREPROCESSING,
    AuditRunStatus.STATIC_SCANNING,
    AuditRunStatus.SEMANTIC_AUDITING,
    AuditRunStatus.DYNAMIC_VERIFYING,
    AuditRunStatus.MACHINE_REVIEW,
    AuditRunStatus.HUMAN_REVIEW,
    AuditRunStatus.REPORTING,
}

AUDIT_RUN_TRANSITIONS: dict[AuditRunStatus, set[AuditRunStatus]] = {
    AuditRunStatus.CREATED: {AuditRunStatus.INGESTING},
    AuditRunStatus.INGESTING: {AuditRunStatus.PREPROCESSING},
    AuditRunStatus.PREPROCESSING: {AuditRunStatus.STATIC_SCANNING},
    AuditRunStatus.STATIC_SCANNING: {AuditRunStatus.SEMANTIC_AUDITING},
    AuditRunStatus.SEMANTIC_AUDITING: {AuditRunStatus.DYNAMIC_VERIFYING},
    AuditRunStatus.DYNAMIC_VERIFYING: {AuditRunStatus.MACHINE_REVIEW},
    AuditRunStatus.MACHINE_REVIEW: {AuditRunStatus.HUMAN_REVIEW},
    AuditRunStatus.HUMAN_REVIEW: {AuditRunStatus.REPORTING},
    AuditRunStatus.REPORTING: {
        AuditRunStatus.COMPLETED,
        AuditRunStatus.COMPLETED_WITH_WARNINGS,
    },
    AuditRunStatus.CANCELLING: {
        AuditRunStatus.CANCELLED,
        AuditRunStatus.FAILED,
    },
    AuditRunStatus.COMPLETED: set(),
    AuditRunStatus.COMPLETED_WITH_WARNINGS: set(),
    AuditRunStatus.CANCELLED: set(),
    AuditRunStatus.FAILED: set(),
}

for _active_status in _ACTIVE_AUDIT_RUN_STATUSES:
    AUDIT_RUN_TRANSITIONS[_active_status].update(
        {AuditRunStatus.CANCELLING, AuditRunStatus.FAILED}
    )


FINDING_TRANSITIONS: dict[FindingStatus, set[FindingStatus]] = {
    FindingStatus.CANDIDATE: {
        FindingStatus.VALIDATING,
        FindingStatus.REJECTED,
    },
    FindingStatus.VALIDATING: {
        FindingStatus.MACHINE_CONFIRMED,
        FindingStatus.REJECTED,
    },
    FindingStatus.MACHINE_CONFIRMED: {
        FindingStatus.AWAITING_HUMAN_REVIEW,
    },
    FindingStatus.AWAITING_HUMAN_REVIEW: {
        FindingStatus.CONFIRMED,
        FindingStatus.REJECTED,
        FindingStatus.ACCEPTED_RISK,
        FindingStatus.VALIDATING,
    },
    FindingStatus.CONFIRMED: {FindingStatus.ACCEPTED_RISK},
    FindingStatus.REJECTED: set(),
    FindingStatus.ACCEPTED_RISK: set(),
}


StatusT = TypeVar("StatusT", bound=StrEnum)


def _transition(
    entity: str,
    transitions: dict[StatusT, set[StatusT]],
    current: StatusT,
    target: StatusT,
) -> StatusT:
    if target not in transitions[current]:
        raise InvalidTransition(entity, current.value, target.value)
    return target


def transition_audit_run(
    current: AuditRunStatus,
    target: AuditRunStatus,
) -> AuditRunStatus:
    return _transition("audit_run", AUDIT_RUN_TRANSITIONS, current, target)


def transition_finding(
    current: FindingStatus,
    target: FindingStatus,
) -> FindingStatus:
    return _transition("finding", FINDING_TRANSITIONS, current, target)
