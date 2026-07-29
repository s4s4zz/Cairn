from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request, status
from sqlalchemy.orm import Session

from cairn.server.artifacts.dependencies import ArtifactStoreDependency
from cairn.server.artifacts.base import ArtifactStore
from cairn.server.auth.audit_log import AuditLogService, Principal
from cairn.server.auth.dependencies import (
    RequireAnyRole,
    RequireAuditor,
    client_ip,
    require_roles,
)
from cairn.server.domain.enums import AuditLogAction, SnapshotStatus, UserRole
from cairn.server.errors import ensure_request_id
from cairn.server.ingestion import GitFetcher, IngestionLimits
from cairn.server.persistence.session import get_db_session
from cairn.server.schemas.common import PageMeta
from cairn.server.schemas.ingestion import (
    GitSnapshotRequest,
    SnapshotCreateRequest,
    SnapshotSourceResponse,
    SourceSnapshotPage,
    SourceSnapshotResponse,
    UploadSnapshotRequest,
)
from cairn.server.services.snapshots import SnapshotService


router = APIRouter(tags=["source-ingestion"])
DatabaseSession = Annotated[Session, Depends(get_db_session)]
SourceReader = Annotated[
    Principal,
    Depends(require_roles(UserRole.ADMIN, UserRole.AUDITOR, UserRole.REVIEWER)),
]


def _service(
    request: Request,
    session: Session,
    artifact_store: ArtifactStore,
) -> SnapshotService:
    settings = request.app.state.settings
    return SnapshotService(
        session,
        artifact_store,
        IngestionLimits.from_settings(settings),
        git_fetcher=GitFetcher(
            allowed_hosts=settings.git_allowed_hosts,
            timeout_seconds=settings.git_clone_timeout_seconds,
            max_checkout_bytes=settings.snapshot_max_total_bytes,
        ),
        secret_key_file=settings.secret_key_file,
        work_root=settings.ingestion_work_root,
    )


@router.post(
    "/repositories/{repository_id}/snapshots",
    response_model=SourceSnapshotResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_snapshot(
    repository_id: UUID,
    snapshot_request: SnapshotCreateRequest,
    request: Request,
    session: DatabaseSession,
    artifact_store: ArtifactStoreDependency,
    principal: RequireAuditor,
) -> SourceSnapshotResponse:
    service = _service(request, session, artifact_store)
    if isinstance(snapshot_request, UploadSnapshotRequest):
        snapshot = service.create_from_upload(
            repository_id,
            snapshot_request.upload_id,
        )
    elif isinstance(snapshot_request, GitSnapshotRequest):
        snapshot = service.create_from_git(repository_id, snapshot_request.ref)
    else:
        raise AssertionError("unsupported snapshot request")
    AuditLogService(session).record(
        AuditLogAction.SNAPSHOT_CREATED,
        actor=principal,
        target_type="source_snapshot",
        target_id=snapshot.id,
        request_id=ensure_request_id(request),
        client_ip=client_ip(request),
        detail={
            "repository_id": str(repository_id),
            "content_sha256": snapshot.content_sha256,
            "input_kind": snapshot.input_kind,
        },
    )
    session.commit()
    return SourceSnapshotResponse.model_validate(snapshot)


@router.get(
    "/repositories/{repository_id}/snapshots",
    response_model=SourceSnapshotPage,
)
def list_snapshots(
    repository_id: UUID,
    request: Request,
    session: DatabaseSession,
    artifact_store: ArtifactStoreDependency,
    principal: RequireAnyRole,
    snapshot_status: Annotated[SnapshotStatus | None, Query(alias="status")] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> SourceSnapshotPage:
    del principal
    snapshots, total = _service(request, session, artifact_store).list(
        repository_id,
        status=snapshot_status,
        limit=limit,
        offset=offset,
    )
    return SourceSnapshotPage(
        items=[SourceSnapshotResponse.model_validate(item) for item in snapshots],
        meta=PageMeta(limit=limit, offset=offset, total=total),
    )


@router.get(
    "/snapshots/{snapshot_id}",
    response_model=SourceSnapshotResponse,
)
def get_snapshot(
    snapshot_id: UUID,
    request: Request,
    session: DatabaseSession,
    artifact_store: ArtifactStoreDependency,
    principal: RequireAnyRole,
) -> SourceSnapshotResponse:
    del principal
    snapshot = _service(request, session, artifact_store).get(snapshot_id)
    return SourceSnapshotResponse.model_validate(snapshot)


@router.get(
    "/snapshots/{snapshot_id}/source",
    response_model=SnapshotSourceResponse,
)
def get_snapshot_source(
    snapshot_id: UUID,
    request: Request,
    session: DatabaseSession,
    artifact_store: ArtifactStoreDependency,
    principal: SourceReader,
    path: Annotated[str, Query(min_length=1, max_length=4096)],
    start_line: Annotated[int, Query(ge=1)] = 1,
    end_line: Annotated[int | None, Query(ge=1)] = None,
) -> SnapshotSourceResponse:
    settings = request.app.state.settings
    service = _service(request, session, artifact_store)
    source = service.read_source(
        snapshot_id,
        path,
        start_line=start_line,
        end_line=end_line,
        max_file_bytes=settings.source_view_max_file_bytes,
        max_lines=settings.source_view_max_lines,
    )
    snapshot = service.get(snapshot_id)
    AuditLogService(session).record(
        AuditLogAction.ARTIFACT_DOWNLOADED,
        actor=principal,
        target_type="artifact",
        target_id=snapshot.artifact_id,
        request_id=ensure_request_id(request),
        client_ip=client_ip(request),
        detail={
            "kind": "source_snapshot",
            "snapshot_id": str(snapshot.id),
            "path": source.path,
            "start_line": source.start_line,
            "end_line": source.end_line,
        },
    )
    session.commit()
    return source
