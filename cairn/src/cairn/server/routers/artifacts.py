from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from cairn.server.artifacts.dependencies import ArtifactStoreDependency
from cairn.server.persistence.session import get_db_session
from cairn.server.services.artifacts import ArtifactService


router = APIRouter(prefix="/artifacts", tags=["artifacts"])
DatabaseSession = Annotated[Session, Depends(get_db_session)]


@router.get("/{artifact_id}", response_class=FileResponse)
def download_artifact(
    artifact_id: UUID,
    session: DatabaseSession,
    artifact_store: ArtifactStoreDependency,
) -> FileResponse:
    artifact, path = ArtifactService(session, artifact_store).resolve(artifact_id)
    return FileResponse(
        path,
        media_type=artifact.media_type,
        filename=f"{artifact.id}",
        headers={
            "ETag": f'"sha256:{artifact.sha256}"',
            "X-Content-SHA256": artifact.sha256,
            "X-Artifact-Kind": artifact.kind,
        },
    )
