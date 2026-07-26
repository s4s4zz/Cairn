from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from cairn.analysis.contracts import AnalysisOperation
from cairn.sandbox.contracts import SandboxTemplateName
from cairn.server.domain.enums import AuditTaskStatus, AuditTaskType
from cairn.server.persistence.models import AuditRun, AuditTask
from cairn.orchestrator.errors import OrchestratorError


@dataclass(frozen=True, slots=True)
class DeterministicTaskSpec:
    operation: AnalysisOperation
    task_type: AuditTaskType
    template: SandboxTemplateName
    timeout_seconds: int
    max_attempts: int = 3

    @property
    def scope_key(self) -> str:
        return f"deterministic:{self.operation.value}"


TASK_SPECS = {
    AnalysisOperation.INVENTORY: DeterministicTaskSpec(
        AnalysisOperation.INVENTORY,
        AuditTaskType.INVENTORY,
        SandboxTemplateName.ANALYSIS,
        900,
    ),
    AnalysisOperation.BUILD: DeterministicTaskSpec(
        AnalysisOperation.BUILD,
        AuditTaskType.BUILD,
        SandboxTemplateName.BUILD,
        3_600,
    ),
    AnalysisOperation.CODEQL: DeterministicTaskSpec(
        AnalysisOperation.CODEQL,
        AuditTaskType.SAST,
        SandboxTemplateName.BUILD,
        3_600,
    ),
    AnalysisOperation.SEMGREP: DeterministicTaskSpec(
        AnalysisOperation.SEMGREP,
        AuditTaskType.SAST,
        SandboxTemplateName.ANALYSIS,
        1_800,
    ),
    AnalysisOperation.FINDSECBUGS: DeterministicTaskSpec(
        AnalysisOperation.FINDSECBUGS,
        AuditTaskType.SAST,
        SandboxTemplateName.BUILD,
        3_600,
    ),
    AnalysisOperation.DEPENDENCY_CHECK: DeterministicTaskSpec(
        AnalysisOperation.DEPENDENCY_CHECK,
        AuditTaskType.DEPENDENCY_SCAN,
        SandboxTemplateName.ANALYSIS,
        1_800,
    ),
    AnalysisOperation.TRIVY: DeterministicTaskSpec(
        AnalysisOperation.TRIVY,
        AuditTaskType.DEPENDENCY_SCAN,
        SandboxTemplateName.ANALYSIS,
        1_800,
    ),
    AnalysisOperation.GITLEAKS: DeterministicTaskSpec(
        AnalysisOperation.GITLEAKS,
        AuditTaskType.SECRET_SCAN,
        SandboxTemplateName.ANALYSIS,
        1_800,
    ),
    AnalysisOperation.CONFIG_RULES: DeterministicTaskSpec(
        AnalysisOperation.CONFIG_RULES,
        AuditTaskType.CONFIG_SCAN,
        SandboxTemplateName.ANALYSIS,
        900,
    ),
}


def get_or_create_task(
    session: Session,
    audit_run: AuditRun,
    operation: AnalysisOperation,
) -> AuditTask:
    spec = TASK_SPECS[operation]
    task = session.scalar(
        select(AuditTask).where(
            AuditTask.audit_run_id == audit_run.id,
            AuditTask.scope_key == spec.scope_key,
        )
    )
    if task is not None:
        return task
    if audit_run.snapshot is None:
        raise OrchestratorError(
            "ORCHESTRATOR_SNAPSHOT_REQUIRED",
            "A ready Snapshot is required to create deterministic tasks",
        )
    task = AuditTask(
        audit_run_id=audit_run.id,
        type=spec.task_type.value,
        scope_key=spec.scope_key,
        scope={
            "operation": operation.value,
            "template": spec.template.value,
        },
        required_capabilities=[f"deterministic:{operation.value}"],
        status=AuditTaskStatus.QUEUED.value,
        worker_name=None,
        attempt=0,
        max_attempts=spec.max_attempts,
        timeout_seconds=spec.timeout_seconds,
        input_artifact_ids=[str(audit_run.snapshot.artifact_id)],
        output_artifact_ids=[],
    )
    session.add(task)
    session.flush()
    return task
