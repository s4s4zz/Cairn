from pathlib import Path
from uuid import UUID

from sqlalchemy.orm import Session

from cairn.server.artifacts import (
    ArtifactIntegrityError,
    ArtifactNotFoundError,
    ArtifactStore,
)
from cairn.server.errors import DomainError, NotFoundError
from cairn.server.persistence.models import Artifact
from cairn.server.persistence.base import is_expired


class ArtifactService:
    def __init__(self, session: Session, artifact_store: ArtifactStore) -> None:
        self.session = session
        self.artifact_store = artifact_store

    def get(self, artifact_id: UUID) -> Artifact:
        artifact = self.session.get(Artifact, artifact_id)
        if artifact is None:
            raise NotFoundError("artifact", artifact_id)
        if artifact.expires_at is not None and is_expired(artifact.expires_at):
            raise DomainError(
                "artifact_expired",
                f"artifact {artifact_id} has expired",
                410,
            )
        return artifact

    def resolve_bytes(self, artifact: Artifact) -> Path:
        try:
            path = self.artifact_store.resolve(
                artifact.storage_key,
                expected_sha256=artifact.sha256,
                expected_size=artifact.size_bytes,
            )
        except ArtifactNotFoundError as exc:
            raise NotFoundError("artifact_bytes", artifact.id) from exc
        except ArtifactIntegrityError as exc:
            raise DomainError(
                "artifact_integrity_failure",
                "artifact bytes failed integrity verification",
                500,
            ) from exc
        return path

    def resolve(self, artifact_id: UUID) -> tuple[Artifact, Path]:
        artifact = self.get(artifact_id)
        return artifact, self.resolve_bytes(artifact)
