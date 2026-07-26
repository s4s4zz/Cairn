from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from cairn.server.domain.enums import (
    AuditRunStatus,
    AuditStage,
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
    AuditPolicy,
    AuditRun,
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
            self.session.commit()
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
        self.session.commit()
        self.session.refresh(audit_run)
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
            audit_run.current_stage = AuditStage(next_status.value).value
        except ValueError:
            pass
        if next_status in _TERMINAL_RUN_STATUSES:
            audit_run.completed_at = now

        self.session.commit()
        self.session.refresh(audit_run)
        return audit_run

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
