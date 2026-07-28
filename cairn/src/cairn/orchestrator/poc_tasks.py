"""Planning and budgeting for model-authored PoCs (§7.7).

Authoring runs before the environment: each PoC is one model conversation on
the semantic template, and only findings the built-in probes cannot cover are
sent. The plans it produces run inside the one validation environment alongside
the deterministic probes, so this bounds *authoring*, not environments.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from cairn.server.domain.enums import AuditTaskStatus, AuditTaskType
from cairn.server.persistence.models import AuditRun, AuditTask, Finding
from cairn.orchestrator.errors import OrchestratorError

POC_AUTHOR_TOOL = "poc-author"
TRUNCATION_REASON = "POC_BUDGET_EXHAUSTED"

POC_TIMEOUT_SECONDS = 1_200
POC_MAX_ATTEMPTS = 2

# Same mapping the probe planner uses; duplicated rather than imported so the
# two planners do not couple through a private constant.
_METHOD_BY_ANNOTATION = {
    "GetMapping": "GET",
    "PostMapping": "POST",
    "PutMapping": "PUT",
    "PatchMapping": "PATCH",
    "DeleteMapping": "DELETE",
    "RequestMapping": "GET",
}


def poc_scope_key(finding: Finding) -> str:
    return f"author-poc:{finding.fingerprint}"


def get_or_create_poc_task(
    session: Session,
    audit_run: AuditRun,
    finding: Finding,
    *,
    timeout_seconds: int = POC_TIMEOUT_SECONDS,
    max_attempts: int = POC_MAX_ATTEMPTS,
) -> AuditTask:
    """One authoring task per finding, idempotent by scope key."""

    scope_key = poc_scope_key(finding)
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
            "A ready Snapshot is required to create a PoC authoring task",
        )
    task = AuditTask(
        audit_run_id=audit_run.id,
        # There is no dedicated task type; PoC authoring is a step of dynamic
        # verification, and its worker identity (`:poc-author`) is what
        # distinguishes it in the task list.
        type=AuditTaskType.DYNAMIC_VERIFY.value,
        scope_key=scope_key,
        scope={"finding_id": str(finding.id), "category": finding.category},
        required_capabilities=[f"poc:{finding.category}"],
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
