from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from cairn.server.domain.enums import (
    AuditRunStatus,
    AuditStage,
    AuditTaskStatus,
    SnapshotStatus,
    SourceUploadStatus,
    SourceType,
)
from cairn.server.domain.state_machines import InvalidTransition, transition_audit_run
from cairn.server.errors import (
    ConflictError,
    InvalidStateError,
    NotFoundError,
)
from cairn.server.persistence.models import (
    AuditCoverage,
    AuditPolicy,
    AuditRun,
    AuditRunStageEvent,
    AuditTask,
    Finding,
    Repository,
    SourceSnapshot,
    SourceUpload,
)
from cairn.server.persistence.base import is_expired
from cairn.server.schemas.audit_runs import (
    AuditRunCreate,
    AuditRunFilters,
    ExistingSnapshotSource,
    GitRefSource,
    UploadSource,
)


_TERMINAL_RUN_STATUSES = {
    AuditRunStatus.COMPLETED,
    AuditRunStatus.COMPLETED_WITH_WARNINGS,
    AuditRunStatus.CANCELLED,
    AuditRunStatus.FAILED,
}

_DELETABLE_RUN_STATUSES = {
    *_TERMINAL_RUN_STATUSES,
    AuditRunStatus.HUMAN_REVIEW,
}

_ACTIVE_TASK_STATUSES = {
    AuditTaskStatus.QUEUED.value,
    AuditTaskStatus.CLAIMED.value,
    AuditTaskStatus.RUNNING.value,
}

# (stage, entered_at, exited_at); the exit is open while the stage is current.
StageWindow = tuple[str, datetime, datetime | None]


class AuditRunService:
    def __init__(self, session: Session) -> None:
        self.session = session

    def create(self, request: AuditRunCreate, actor: str) -> AuditRun:
        repository = self.session.get(Repository, request.repository_id)
        if repository is None:
            raise NotFoundError("repository", request.repository_id)
        policy = self.session.get(AuditPolicy, request.policy_id)
        if policy is None:
            raise NotFoundError("audit_policy", request.policy_id)
        if not policy.active:
            raise InvalidStateError(
                "new audit runs require an active policy version",
                error_code="audit_policy_inactive",
            )

        snapshot_id: UUID | None = None
        source_request = request.source_request
        if isinstance(source_request, ExistingSnapshotSource):
            snapshot = self._ready_snapshot(
                source_request.snapshot_id,
                repository_id=repository.id,
            )
            snapshot_id = snapshot.id
        elif isinstance(source_request, GitRefSource):
            if repository.source_type != SourceType.GIT.value:
                raise InvalidStateError(
                    "git_ref source requires a Git repository",
                    error_code="source_type_mismatch",
                )
        elif isinstance(source_request, UploadSource):
            if repository.source_type == SourceType.GIT.value:
                raise InvalidStateError(
                    "upload source requires a ZIP or directory-upload repository",
                    error_code="source_type_mismatch",
                )
            upload = self.session.scalar(
                select(SourceUpload)
                .where(SourceUpload.id == source_request.upload_id)
                .with_for_update()
            )
            if upload is None:
                raise NotFoundError("source_upload", source_request.upload_id)
            if upload.source_type != repository.source_type:
                raise InvalidStateError(
                    "upload source type does not match the repository",
                    error_code="source_type_mismatch",
                )
            if upload.status != SourceUploadStatus.READY.value:
                raise InvalidStateError(
                    "source upload is not ready",
                    error_code="source_upload_not_ready",
                )
            if (
                upload.expires_at is not None
                and is_expired(upload.expires_at)
            ):
                upload.status = SourceUploadStatus.EXPIRED.value
                self.session.commit()
                raise InvalidStateError(
                    "source upload has expired",
                    error_code="source_upload_expired",
                )
            if (
                upload.repository_id is not None
                and upload.repository_id != repository.id
            ):
                raise InvalidStateError(
                    "source upload belongs to a different repository",
                    error_code="source_upload_repository_mismatch",
                )
            if upload.repository_id is None:
                upload.repository_id = repository.id

        audit_run = AuditRun(
            repository_id=repository.id,
            source_request=source_request.model_dump(mode="json"),
            snapshot_id=snapshot_id,
            policy_id=policy.id,
            policy_version=policy.version,
            status=AuditRunStatus.CREATED.value,
            current_stage=None,
            progress=0,
            warning_count=0,
            created_by=actor,
        )
        self.session.add(audit_run)
        try:
            self.session.flush()
        except IntegrityError as exc:
            self.session.rollback()
            raise ConflictError(
                "audit run could not be created because referenced data changed",
                error_code="audit_run_create_conflict",
            ) from exc
        self.session.refresh(audit_run)
        return audit_run

    def get(self, run_id: UUID) -> AuditRun:
        audit_run = self.session.get(AuditRun, run_id)
        if audit_run is None:
            raise NotFoundError("audit_run", run_id)
        return audit_run

    def get_coverage(self, run_id: UUID) -> AuditCoverage:
        if self.session.get(AuditRun, run_id) is None:
            raise NotFoundError("audit_run", run_id)
        coverage = self.session.get(AuditCoverage, run_id)
        if coverage is None:
            raise NotFoundError("audit_coverage", run_id)
        return coverage

    def list_tasks(
        self,
        run_id: UUID,
        *,
        limit: int,
        offset: int,
    ) -> tuple[list[AuditTask], int]:
        self.get(run_id)
        condition = AuditTask.audit_run_id == run_id
        total = self.session.scalar(
            select(func.count()).select_from(AuditTask).where(condition)
        ) or 0
        tasks = list(
            self.session.scalars(
                select(AuditTask)
                .where(condition)
                .order_by(AuditTask.created_at, AuditTask.id)
                .limit(limit)
                .offset(offset)
            )
        )
        return tasks, total

    def event_snapshot(self, run_id: UUID) -> dict[str, object]:
        """Return one self-contained SSE snapshot for reconnect-safe clients."""

        audit_run = self.get(run_id)
        task_counts = {
            str(task_status): int(count)
            for task_status, count in self.session.execute(
                select(AuditTask.status, func.count())
                .where(AuditTask.audit_run_id == run_id)
                .group_by(AuditTask.status)
            )
        }
        finding_counts = {
            str(finding_status): int(count)
            for finding_status, count in self.session.execute(
                select(Finding.status, func.count())
                .where(Finding.audit_run_id == run_id)
                .group_by(Finding.status)
            )
        }
        coverage = self.session.get(AuditCoverage, run_id)
        return {
            "audit_run_id": str(audit_run.id),
            "status": audit_run.status,
            "current_stage": audit_run.current_stage,
            "progress": float(audit_run.progress),
            "warning_count": audit_run.warning_count,
            "failure_code": audit_run.failure_code,
            "failure_reason": audit_run.failure_reason,
            "task_counts": task_counts,
            "finding_counts": finding_counts,
            "coverage_warning_count": (
                len(coverage.coverage_warnings) if coverage is not None else 0
            ),
            "completed_at": (
                audit_run.completed_at.isoformat()
                if audit_run.completed_at is not None
                else None
            ),
        }

    def list(self, filters: AuditRunFilters) -> tuple[list[AuditRun], int]:
        conditions = []
        if filters.repository_id is not None:
            conditions.append(AuditRun.repository_id == filters.repository_id)
        if filters.status is not None:
            conditions.append(AuditRun.status == filters.status.value)

        count_statement = select(func.count()).select_from(AuditRun)
        statement = select(AuditRun)
        if conditions:
            count_statement = count_statement.where(*conditions)
            statement = statement.where(*conditions)
        total = self.session.scalar(count_statement) or 0
        runs = list(
            self.session.scalars(
                statement.order_by(AuditRun.created_at.desc(), AuditRun.id)
                .limit(filters.limit)
                .offset(filters.offset)
            )
        )
        return runs, total

    def request_cancel(self, run_id: UUID, actor: str) -> AuditRun:
        audit_run = self._get_locked(run_id)
        current = AuditRunStatus(audit_run.status)
        if current in {AuditRunStatus.CANCELLING, AuditRunStatus.CANCELLED}:
            return audit_run
        if current in _TERMINAL_RUN_STATUSES:
            raise InvalidStateError(
                f"audit run in {current.value} cannot be cancelled",
                error_code="audit_run_not_cancellable",
            )

        audit_run.status = transition_audit_run(
            current,
            AuditRunStatus.CANCELLING,
        ).value
        self.session.flush()
        self.session.refresh(audit_run)
        return audit_run

    def retry(self, run_id: UUID, actor: str) -> AuditRun:
        """Start a fresh run over the same source (§11.2).

        A new AuditRun rather than a rewind of the old one. The state machine
        has no edge out of ``failed`` or ``cancelled`` on purpose: a run is the
        record of one attempt, and letting an attempt resume after failure
        would make its findings, coverage and timings describe two different
        executions at once.

        The retry is pinned to the original's Snapshot when it had one, so
        "retry" means the same bytes and not whatever the branch points at now.
        """

        original = self.get(run_id)
        current = AuditRunStatus(original.status)
        if current not in {AuditRunStatus.FAILED, AuditRunStatus.CANCELLED}:
            raise InvalidStateError(
                f"audit run in {current.value} cannot be retried",
                error_code="audit_run_not_retryable",
            )
        policy = self.session.get(AuditPolicy, original.policy_id)
        if policy is None:
            raise NotFoundError("audit_policy", original.policy_id)

        source_request = dict(original.source_request)
        if original.snapshot_id is not None:
            snapshot = self._ready_snapshot(
                original.snapshot_id,
                repository_id=original.repository_id,
            )
            source_request = {
                "type": "snapshot",
                "snapshot_id": str(snapshot.id),
            }

        audit_run = AuditRun(
            repository_id=original.repository_id,
            source_request=source_request,
            snapshot_id=original.snapshot_id,
            policy_id=original.policy_id,
            policy_version=original.policy_version,
            status=AuditRunStatus.CREATED.value,
            current_stage=None,
            progress=0,
            warning_count=0,
            created_by=actor,
        )
        self.session.add(audit_run)
        self.session.flush()
        self.session.refresh(audit_run)
        return audit_run

    def delete(self, run_id: UUID) -> AuditRun:
        """Delete one settled AuditRun and its run-owned records.

        A running pipeline may still own a live sandbox or a leased task, so
        deletion is deliberately unavailable until the run reaches a settled
        status. ``human_review`` is also settled from the worker's perspective:
        no background task remains and the operator may choose to discard the
        review set instead of generating a report.

        The pinned SourceSnapshot is retained. It belongs to the Repository,
        not to this execution, and can safely be reused by another AuditRun.
        """

        audit_run = self._get_locked(run_id)
        current = AuditRunStatus(audit_run.status)
        if current not in _DELETABLE_RUN_STATUSES:
            raise InvalidStateError(
                f"audit run in {current.value} must be cancelled before deletion",
                error_code="audit_run_not_deletable",
            )
        # Only `human_review` can hold work that is genuinely still owed: a
        # queued reverify task there is waiting for the orchestrator to claim
        # it. A run in a terminal status is not executing, so a task still
        # marked active is a stale row — refusing on it would lock the run out
        # of deletion permanently.
        if current is AuditRunStatus.HUMAN_REVIEW:
            active_task = self.session.scalar(
                select(AuditTask.id)
                .where(
                    AuditTask.audit_run_id == run_id,
                    AuditTask.status.in_(_ACTIVE_TASK_STATUSES),
                )
                .limit(1)
            )
            if active_task is not None:
                raise ConflictError(
                    "audit run still has an active task",
                    error_code="audit_run_has_active_tasks",
                )

        self.session.delete(audit_run)
        try:
            self.session.flush()
        except IntegrityError as exc:
            self.session.rollback()
            raise ConflictError(
                "audit run data is still referenced",
                error_code="audit_run_delete_conflict",
            ) from exc
        return audit_run

    def transition(
        self,
        run_id: UUID,
        target: AuditRunStatus,
        *,
        snapshot_id: UUID | None = None,
    ) -> AuditRun:
        audit_run = self._get_locked(run_id)
        current = AuditRunStatus(audit_run.status)

        if snapshot_id is not None and target is not AuditRunStatus.PREPROCESSING:
            raise InvalidStateError(
                "snapshot can only be attached while entering preprocessing",
                error_code="snapshot_attachment_not_allowed",
            )
        try:
            next_status = transition_audit_run(current, target)
        except InvalidTransition as exc:
            raise InvalidStateError(
                str(exc),
                error_code="audit_run_invalid_transition",
            ) from exc
        if target is AuditRunStatus.PREPROCESSING:
            self._prepare_snapshot(audit_run, snapshot_id)

        now = datetime.now(UTC)
        audit_run.status = next_status.value
        if next_status is AuditRunStatus.INGESTING and audit_run.started_at is None:
            audit_run.started_at = now
        try:
            entered_stage = AuditStage(next_status.value)
        except ValueError:
            # Terminal and pre-start statuses have no matching stage; the run
            # keeps whichever stage it was in, which is what a failed run needs
            # to report where it stopped.
            pass
        else:
            if audit_run.current_stage != entered_stage.value:
                self.session.add(
                    AuditRunStageEvent(
                        audit_run_id=audit_run.id,
                        stage=entered_stage.value,
                        entered_at=now,
                    )
                )
            audit_run.current_stage = entered_stage.value
        if next_status in _TERMINAL_RUN_STATUSES:
            audit_run.completed_at = now

        self.session.commit()
        self.session.refresh(audit_run)
        return audit_run

    # The annotation is quoted because this class defines its own `list`
    # method, which shadows the builtin in class body scope.
    def stage_events(self, run_id: UUID) -> "list[StageWindow]":
        """Recorded stage entries with the exit each one is closed by.

        A stage runs until the next one is entered; the last one is closed by
        the run's own `completed_at`, and stays open while the run is live.
        """

        audit_run = self.get(run_id)
        entries = list(
            self.session.scalars(
                select(AuditRunStageEvent)
                .where(AuditRunStageEvent.audit_run_id == run_id)
                .order_by(AuditRunStageEvent.entered_at, AuditRunStageEvent.id)
            )
        )
        resolved: "list[StageWindow]" = []
        for index, entry in enumerate(entries):
            following = entries[index + 1] if index + 1 < len(entries) else None
            exited_at = following.entered_at if following else audit_run.completed_at
            resolved.append((entry.stage, entry.entered_at, exited_at))
        return resolved

    def _get_locked(self, run_id: UUID) -> AuditRun:
        audit_run = self.session.scalar(
            select(AuditRun).where(AuditRun.id == run_id).with_for_update()
        )
        if audit_run is None:
            raise NotFoundError("audit_run", run_id)
        return audit_run

    def _prepare_snapshot(
        self,
        audit_run: AuditRun,
        snapshot_id: UUID | None,
    ) -> None:
        if (
            audit_run.snapshot_id is not None
            and snapshot_id is not None
            and audit_run.snapshot_id != snapshot_id
        ):
            raise InvalidStateError(
                "audit run snapshot is immutable",
                error_code="snapshot_immutable",
            )
        effective_snapshot_id = audit_run.snapshot_id or snapshot_id
        if effective_snapshot_id is None:
            raise InvalidStateError(
                "a ready snapshot is required before preprocessing",
                error_code="snapshot_required",
            )
        snapshot = self._ready_snapshot(
            effective_snapshot_id,
            repository_id=audit_run.repository_id,
        )
        if audit_run.snapshot_id is None:
            audit_run.snapshot_id = snapshot.id

    def _ready_snapshot(
        self,
        snapshot_id: UUID,
        *,
        repository_id: UUID,
    ) -> SourceSnapshot:
        snapshot = self.session.get(SourceSnapshot, snapshot_id)
        if snapshot is None:
            raise NotFoundError("source_snapshot", snapshot_id)
        if snapshot.repository_id != repository_id:
            raise InvalidStateError(
                "snapshot belongs to a different repository",
                error_code="snapshot_repository_mismatch",
            )
        if snapshot.status != SnapshotStatus.READY.value:
            raise InvalidStateError(
                "source snapshot is not ready",
                error_code="snapshot_not_ready",
            )
        return snapshot
