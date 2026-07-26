from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Request, status
from sqlalchemy.orm import Session

from cairn.server.artifacts.dependencies import ArtifactStoreDependency
from cairn.server.artifacts.base import ArtifactStore
from cairn.server.ingestion import GitFetcher, IngestionLimits
from cairn.server.persistence.session import get_db_session
from cairn.server.schemas.ingestion import (
    GitSnapshotRequest,
    SnapshotCreateRequest,
    SourceSnapshotResponse,
    UploadSnapshotRequest,
)
from cairn.server.services.snapshots import SnapshotService


router = APIRouter(tags=["source-ingestion"])
DatabaseSession = Annotated[Session, Depends(get_db_session)]


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
    return SourceSnapshotResponse.model_validate(snapshot)


@router.get(
    "/snapshots/{snapshot_id}",
    response_model=SourceSnapshotResponse,
)
def get_snapshot(
    snapshot_id: UUID,
    request: Request,
    session: DatabaseSession,
    artifact_store: ArtifactStoreDependency,
) -> SourceSnapshotResponse:
    snapshot = _service(request, session, artifact_store).get(snapshot_id)
    return SourceSnapshotResponse.model_validate(snapshot)
