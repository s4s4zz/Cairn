"""Planning and budgeting for the independent machine-review stage (§7.8).

Independent review is one model conversation per critical or high Finding, so
it needs the same operator-facing ceiling the semantic stage has. The budget
lives on ``AuditPolicy.verification_budget`` and, like
:class:`~cairn.orchestrator.semantic_tasks.SemanticBudget`, falls back to
defaults rather than failing a run whose policy predates the field.
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from cairn.server.domain.enums import AuditTaskStatus, AuditTaskType
from cairn.server.persistence.models import AuditRun, AuditTask, Finding
from cairn.orchestrator.errors import OrchestratorError

DEFAULT_MAX_FINDINGS = 24
DEFAULT_MAX_TURNS = 16
DEFAULT_MAX_OUTPUT_TOKENS = 16_000

VERIFY_TIMEOUT_SECONDS = 1_200
VERIFY_MAX_ATTEMPTS = 2

TRUNCATION_REASON = "VERIFICATION_BUDGET_EXHAUSTED"


@dataclass(frozen=True, slots=True)
class VerificationBudget:
    """Per-run ceilings, read from ``AuditPolicy.verification_budget``."""

    max_findings: int = DEFAULT_MAX_FINDINGS
    max_turns_per_task: int = DEFAULT_MAX_TURNS
    max_output_tokens_per_task: int = DEFAULT_MAX_OUTPUT_TOKENS

    @classmethod
    def from_policy(cls, payload: object) -> "VerificationBudget":
        if not isinstance(payload, dict):
            return cls()
        return cls(
            max_findings=_positive(payload.get("max_findings"), DEFAULT_MAX_FINDINGS),
            max_turns_per_task=_positive(
                payload.get("max_turns_per_task"), DEFAULT_MAX_TURNS
            ),
            max_output_tokens_per_task=_positive(
                payload.get("max_output_tokens_per_task"),
                DEFAULT_MAX_OUTPUT_TOKENS,
            ),
        )


def _positive(value: object, default: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        return default
    return value


def verify_scope_key(finding: Finding) -> str:
    """The task scope key for one Finding's independent review.

    Keyed on the Finding's own fingerprint, so the existing
    ``uq_audit_tasks_run_scope_key`` constraint makes the review idempotent: a
    resumed run cannot pay for the same conversation twice.
    """

    return f"independent-verify:{finding.fingerprint}"


def get_or_create_verify_task(
    session: Session,
    audit_run: AuditRun,
    finding: Finding,
    *,
    timeout_seconds: int = VERIFY_TIMEOUT_SECONDS,
    max_attempts: int = VERIFY_MAX_ATTEMPTS,
) -> AuditTask:
    scope_key = verify_scope_key(finding)
    task = session.scalar(
        select(AuditTask).where(
            AuditTask.audit_run_id == audit_run.id,
            AuditTask.scope_key == scope_key,
        )
    )
    if task is not None:
        return task
    if audit_run.snapshot is None:
        raise OrchestratorError(
            "ORCHESTRATOR_SNAPSHOT_REQUIRED",
            "A ready Snapshot is required to create verification tasks",
        )
    task = AuditTask(
        audit_run_id=audit_run.id,
        type=AuditTaskType.INDEPENDENT_VERIFY.value,
        scope_key=scope_key,
        # The stored scope carries only what the blind channel carries, so an
        # operator reading the task list sees the same assignment the reviewer
        # saw — not the reporting worker's reasoning.
        scope={
            "finding_id": str(finding.id),
            "fingerprint": finding.fingerprint,
            "category": finding.category,
            "cwe_id": finding.cwe_id,
            "severity": finding.severity,
        },
        required_capabilities=[f"verify:{finding.category}"],
        status=AuditTaskStatus.QUEUED.value,
        worker_name=None,
        attempt=0,
        max_attempts=max_attempts,
        timeout_seconds=timeout_seconds,
        input_artifact_ids=[str(audit_run.snapshot.artifact_id)],
        output_artifact_ids=[],
    )
    session.add(task)
    session.flush()
    return task
