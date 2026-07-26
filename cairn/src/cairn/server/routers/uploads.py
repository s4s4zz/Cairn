from __future__ import annotations

import os
from pathlib import Path
import tempfile
from typing import Annotated

from fastapi import APIRouter, Depends, Header, Query, Request, status
from sqlalchemy.orm import Session

from cairn.server.artifacts.dependencies import ArtifactStoreDependency
from cairn.server.domain.enums import SourceType
from cairn.server.errors import IngestionError
from cairn.server.persistence.session import get_db_session
from cairn.server.schemas.ingestion import SourceUploadResponse
from cairn.server.services.uploads import UploadService


router = APIRouter(prefix="/uploads", tags=["source-ingestion"])
DatabaseSession = Annotated[Session, Depends(get_db_session)]


def _safe_filename(value: str | None) -> str:
    if value is None:
        return "source.zip"
    if (
        not value
        or len(value) > 255
        or Path(value).name != value
        or any(ord(character) < 32 for character in value)
    ):
        raise IngestionError(
            "UPLOAD_FILENAME_INVALID",
            "Upload filename must be a plain filename of at most 255 characters",
        )
    return value


@router.post(
    "",
    response_model=SourceUploadResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_upload(
    request: Request,
    session: DatabaseSession,
    artifact_store: ArtifactStoreDependency,
    source_type: Annotated[SourceType, Query()],
    filename: Annotated[str | None, Header(alias="X-Filename")] = None,
) -> SourceUploadResponse:
    settings = request.app.state.settings
    safe_filename = _safe_filename(filename)
    if source_type is SourceType.GIT:
        raise IngestionError(
            "UPLOAD_SOURCE_TYPE_INVALID",
            "Git repositories do not accept source uploads",
        )
    content_length = request.headers.get("content-length")
    if content_length is not None:
        try:
            declared_size = int(content_length)
        except ValueError as exc:
            raise IngestionError(
                "UPLOAD_CONTENT_LENGTH_INVALID",
                "Content-Length must be an integer",
            ) from exc
        if declared_size < 0:
            raise IngestionError(
                "UPLOAD_CONTENT_LENGTH_INVALID",
                "Content-Length must not be negative",
            )
        if declared_size > settings.upload_max_bytes:
            raise IngestionError(
                "UPLOAD_TOO_LARGE",
                "Upload exceeds the configured size limit",
                http_status=413,
            )

    file_descriptor, temporary_name = tempfile.mkstemp(
        prefix="cairn-upload-",
        dir=settings.ingestion_work_root,
    )
    temporary_path = Path(temporary_name)
    size = 0
    try:
        with os.fdopen(file_descriptor, "wb") as output:
            async for chunk in request.stream():
                size += len(chunk)
                if size > settings.upload_max_bytes:
                    raise IngestionError(
                        "UPLOAD_TOO_LARGE",
                        "Upload exceeds the configured size limit",
                        http_status=413,
                    )
                output.write(chunk)
        upload = UploadService(session, artifact_store).create(
            temporary_path,
            source_type=source_type,
            original_filename=safe_filename,
            actor="system",
            max_bytes=settings.upload_max_bytes,
        )
    finally:
        temporary_path.unlink(missing_ok=True)
    return SourceUploadResponse.model_validate(upload)
