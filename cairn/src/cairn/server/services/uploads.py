from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from cairn.server.artifacts import ArtifactStore
from cairn.server.domain.enums import (
    ArtifactAccessLevel,
    ArtifactKind,
    SourceType,
    SourceUploadStatus,
)
from cairn.server.errors import ConflictError, IngestionError
from cairn.server.persistence.models import Artifact, SourceUpload


class UploadService:
    def __init__(self, session: Session, artifact_store: ArtifactStore) -> None:
        self.session = session
        self.artifact_store = artifact_store

    def create(
        self,
        source_path: Path,
        *,
        source_type: SourceType,
        original_filename: str,
        actor: str,
        max_bytes: int,
    ) -> SourceUpload:
        if source_type is SourceType.GIT:
            raise IngestionError(
                "UPLOAD_SOURCE_TYPE_INVALID",
                "Git repositories must be ingested from a configured remote",
            )
        if source_path.stat().st_size == 0:
            raise IngestionError(
                "UPLOAD_EMPTY",
                "Uploaded archive must not be empty",
            )

        stored = self.artifact_store.put_file(source_path, max_bytes=max_bytes)
        expires_at = datetime.now(UTC) + timedelta(hours=24)
        artifact = Artifact(
            audit_run_id=None,
            kind=ArtifactKind.SOURCE_UPLOAD.value,
            storage_key=stored.storage_key,
            sha256=stored.sha256,
            size_bytes=stored.size_bytes,
            media_type="application/zip",
            access_level=ArtifactAccessLevel.SENSITIVE.value,
            expires_at=expires_at,
        )
        upload = SourceUpload(
            artifact=artifact,
            repository_id=None,
            source_type=source_type.value,
            original_filename=original_filename,
            status=SourceUploadStatus.READY.value,
            failure_code=None,
            created_by=actor,
            expires_at=expires_at,
        )
        self.session.add(upload)
        try:
            self.session.commit()
        except IntegrityError as exc:
            self.session.rollback()
            raise ConflictError(
                "source upload metadata could not be stored",
                error_code="source_upload_conflict",
            ) from exc
        self.session.refresh(upload)
        return upload
