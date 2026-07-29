from __future__ import annotations

import logging
from pathlib import Path
from pathlib import PurePosixPath
import shutil
import tarfile
import tempfile
import unicodedata
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from cairn.server.artifacts import (
    ArtifactIntegrityError,
    ArtifactNotFoundError,
    ArtifactStore,
)
from cairn.server.domain.enums import (
    ArtifactAccessLevel,
    ArtifactKind,
    SnapshotStatus,
    SourceType,
    SourceUploadStatus,
)
from cairn.server.errors import (
    ConflictError,
    DomainError,
    IngestionError,
    InvalidStateError,
    NotFoundError,
)
from cairn.server.schemas.ingestion import SnapshotSourceResponse
from cairn.server.ingestion import (
    GitFetcher,
    IngestionFailure,
    IngestionLimits,
    collect_snapshot_tree,
    extract_zip_archive,
    write_snapshot_archive,
)
from cairn.server.persistence.models import (
    Artifact,
    Repository,
    SourceSnapshot,
    SourceUpload,
)
from cairn.server.persistence.base import is_expired
from cairn.server.secret_store import DatabaseSecretStore


LOG = logging.getLogger(__name__)


class SnapshotService:
    def __init__(
        self,
        session: Session,
        artifact_store: ArtifactStore,
        limits: IngestionLimits,
        *,
        git_fetcher: GitFetcher | None = None,
        secret_key_file: Path | None = None,
        work_root: Path | None = None,
    ) -> None:
        self.session = session
        self.artifact_store = artifact_store
        self.limits = limits
        self.git_fetcher = git_fetcher
        self.secret_key_file = secret_key_file
        self.work_root = work_root

    def get(self, snapshot_id: UUID) -> SourceSnapshot:
        snapshot = self.session.get(SourceSnapshot, snapshot_id)
        if snapshot is None:
            raise NotFoundError("source_snapshot", snapshot_id)
        return snapshot

    def list(
        self,
        repository_id: UUID,
        *,
        status: SnapshotStatus | None,
        limit: int,
        offset: int,
    ) -> tuple[list[SourceSnapshot], int]:
        self._repository(repository_id)
        conditions = [SourceSnapshot.repository_id == repository_id]
        if status is not None:
            conditions.append(SourceSnapshot.status == status.value)
        total = self.session.scalar(
            select(func.count()).select_from(SourceSnapshot).where(*conditions)
        ) or 0
        snapshots = list(
            self.session.scalars(
                select(SourceSnapshot)
                .where(*conditions)
                .order_by(SourceSnapshot.created_at.desc(), SourceSnapshot.id)
                .limit(limit)
                .offset(offset)
            )
        )
        return snapshots, total

    def read_source(
        self,
        snapshot_id: UUID,
        source_path: str,
        *,
        start_line: int,
        end_line: int | None,
        max_file_bytes: int,
        max_lines: int,
    ) -> SnapshotSourceResponse:
        """Read one exact regular member from an immutable Snapshot archive."""

        normalized_path = self._source_path(source_path)
        if end_line is not None and end_line < start_line:
            raise DomainError(
                "source_line_range_invalid",
                "end_line must be greater than or equal to start_line",
                422,
            )
        snapshot = self.get(snapshot_id)
        if snapshot.status != SnapshotStatus.READY.value:
            raise InvalidStateError(
                "source can only be viewed from a ready snapshot",
                error_code="snapshot_not_ready",
            )
        artifact = snapshot.artifact
        try:
            archive_path = self.artifact_store.resolve(
                artifact.storage_key,
                expected_sha256=artifact.sha256,
                expected_size=artifact.size_bytes,
            )
            with tarfile.open(archive_path, mode="r:") as archive:
                matches = [
                    member for member in archive if member.name == normalized_path
                ]
                if len(matches) != 1:
                    raise NotFoundError("snapshot_source", normalized_path)
                member = matches[0]
                if not member.isreg():
                    raise DomainError(
                        "snapshot_source_not_regular",
                        "snapshot source member is not a regular file",
                        422,
                    )
                if member.size > max_file_bytes:
                    raise DomainError(
                        "snapshot_source_too_large",
                        "snapshot source exceeds the browser viewing limit",
                        413,
                    )
                stream = archive.extractfile(member)
                if stream is None:
                    raise NotFoundError("snapshot_source", normalized_path)
                raw = stream.read(max_file_bytes + 1)
        except (ArtifactIntegrityError, ArtifactNotFoundError) as exc:
            raise DomainError(
                "artifact_integrity_failure",
                "snapshot Artifact failed integrity verification",
                500,
            ) from exc
        except (OSError, tarfile.TarError) as exc:
            raise DomainError(
                "snapshot_archive_invalid",
                "snapshot Artifact is not a valid tar archive",
                500,
            ) from exc

        if len(raw) > max_file_bytes:
            raise DomainError(
                "snapshot_source_too_large",
                "snapshot source exceeds the browser viewing limit",
                413,
            )
        if b"\0" in raw:
            raise DomainError(
                "snapshot_source_not_text",
                "snapshot source is not a text file",
                415,
            )
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise DomainError(
                "snapshot_source_encoding_unsupported",
                "snapshot source is not valid UTF-8",
                415,
            ) from exc

        lines = text.splitlines(keepends=True)
        total_lines = len(lines)
        if total_lines and start_line > total_lines:
            raise DomainError(
                "source_line_range_invalid",
                "start_line is past the end of the source file",
                416,
            )
        requested_end = total_lines if end_line is None else min(end_line, total_lines)
        maximum_end = start_line + max_lines - 1
        selected_end = min(requested_end, maximum_end)
        content = "".join(lines[start_line - 1 : selected_end])
        return SnapshotSourceResponse(
            snapshot_id=snapshot.id,
            snapshot_sha=snapshot.content_sha256,
            path=normalized_path,
            start_line=start_line,
            end_line=selected_end,
            total_lines=total_lines,
            content=content,
            truncated=selected_end < requested_end,
        )

    def create_from_upload(
        self,
        repository_id: UUID,
        upload_id: UUID,
    ) -> SourceSnapshot:
        repository = self._repository(repository_id)
        if repository.source_type == SourceType.GIT.value:
            raise InvalidStateError(
                "upload snapshots require a ZIP or directory-upload repository",
                error_code="source_type_mismatch",
            )
        upload = self.session.scalar(
            select(SourceUpload)
            .where(SourceUpload.id == upload_id)
            .with_for_update()
        )
        if upload is None:
            raise NotFoundError("source_upload", upload_id)
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
        if upload.expires_at is not None and is_expired(upload.expires_at):
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
            raise ConflictError(
                "source upload is already bound to another repository",
                error_code="source_upload_repository_conflict",
            )

        try:
            upload_artifact = upload.artifact
            archive_path = self.artifact_store.resolve(
                upload_artifact.storage_key,
                expected_sha256=upload_artifact.sha256,
                expected_size=upload_artifact.size_bytes,
            )
            with tempfile.TemporaryDirectory(
                prefix="cairn-snapshot-",
                dir=self.work_root,
            ) as temporary:
                temporary_root = Path(temporary)
                source_root = temporary_root / "source"
                if upload.source_type == SourceType.BINARY_UPLOAD.value:
                    source_root.mkdir()
                    shutil.copyfile(
                        archive_path,
                        source_root / upload.original_filename,
                    )
                else:
                    extract_zip_archive(archive_path, source_root, self.limits)
                tree = collect_snapshot_tree(source_root, self.limits)
                snapshot_archive = temporary_root / "snapshot.tar"
                write_snapshot_archive(tree, snapshot_archive)
                stored_snapshot = self.artifact_store.put_file(snapshot_archive)
        except IngestionFailure as exc:
            self._reject_upload(upload, exc.error_code)
            raise IngestionError(
                exc.error_code,
                exc.message,
                http_status=exc.http_status,
            ) from exc
        except (ArtifactIntegrityError, ArtifactNotFoundError) as exc:
            raise IngestionError(
                "ARTIFACT_INTEGRITY_FAILURE",
                "Uploaded Artifact failed integrity verification",
                http_status=500,
            ) from exc
        except OSError as exc:
            LOG.exception(
                "source ingestion storage is unavailable",
                extra={"work_root": str(self.work_root)},
            )
            raise IngestionError(
                "INGESTION_STORAGE_UNAVAILABLE",
                "Source ingestion storage is temporarily unavailable",
                http_status=503,
            ) from exc

        upload.repository_id = repository.id
        artifact = Artifact(
            audit_run_id=None,
            kind=ArtifactKind.SOURCE_SNAPSHOT.value,
            storage_key=stored_snapshot.storage_key,
            sha256=stored_snapshot.sha256,
            size_bytes=stored_snapshot.size_bytes,
            media_type="application/x-tar",
            access_level=ArtifactAccessLevel.SENSITIVE.value,
        )
        snapshot = SourceSnapshot(
            repository_id=repository.id,
            commit_sha=None,
            content_sha256=tree.content_sha256,
            branch_or_tag=None,
            artifact=artifact,
            file_count=tree.file_count,
            total_bytes=tree.total_bytes,
            java_file_count=tree.java_file_count,
            jvm_artifact_count=tree.jvm_artifact_count,
            input_kind=tree.input_kind.value,
            java_version=None,
            build_system=tree.build_system.value,
            status=SnapshotStatus.READY.value,
            failure_code=None,
        )
        upload.repository_id = repository.id
        self.session.add(snapshot)
        try:
            self.session.flush()
        except IntegrityError as exc:
            self.session.rollback()
            raise ConflictError(
                "source snapshot could not be stored",
                error_code="source_snapshot_conflict",
            ) from exc
        self.session.refresh(snapshot)
        return snapshot

    def create_from_git(
        self,
        repository_id: UUID,
        ref: str,
    ) -> SourceSnapshot:
        repository = self._repository(repository_id)
        if repository.source_type != SourceType.GIT.value:
            raise InvalidStateError(
                "Git snapshots require a Git repository",
                error_code="source_type_mismatch",
            )
        if repository.remote_url is None:
            raise InvalidStateError(
                "Git repository does not have a remote URL",
                error_code="git_remote_missing",
            )
        if self.git_fetcher is None:
            raise IngestionError(
                "GIT_INGESTION_UNAVAILABLE",
                "Git ingestion is not configured",
                http_status=503,
            )

        credential = None
        if repository.credential_ref is not None:
            credential = DatabaseSecretStore(
                self.session,
                self._master_key(),
            ).read(repository.credential_ref)
        try:
            with tempfile.TemporaryDirectory(
                prefix="cairn-git-snapshot-",
                dir=self.work_root,
            ) as temporary:
                temporary_root = Path(temporary)
                source_root = temporary_root / "source"
                commit_sha = self.git_fetcher.fetch_into(
                    repository.remote_url,
                    ref,
                    source_root,
                    credential,
                )
                tree = collect_snapshot_tree(source_root, self.limits)
                snapshot_archive = temporary_root / "snapshot.tar"
                write_snapshot_archive(tree, snapshot_archive)
                stored_snapshot = self.artifact_store.put_file(snapshot_archive)
        except IngestionFailure as exc:
            raise IngestionError(
                exc.error_code,
                exc.message,
                http_status=exc.http_status,
            ) from exc
        except OSError as exc:
            LOG.exception(
                "source ingestion storage is unavailable",
                extra={"work_root": str(self.work_root)},
            )
            raise IngestionError(
                "INGESTION_STORAGE_UNAVAILABLE",
                "Source ingestion storage is temporarily unavailable",
                http_status=503,
            ) from exc

        artifact = Artifact(
            audit_run_id=None,
            kind=ArtifactKind.SOURCE_SNAPSHOT.value,
            storage_key=stored_snapshot.storage_key,
            sha256=stored_snapshot.sha256,
            size_bytes=stored_snapshot.size_bytes,
            media_type="application/x-tar",
            access_level=ArtifactAccessLevel.SENSITIVE.value,
        )
        snapshot = SourceSnapshot(
            repository_id=repository.id,
            commit_sha=commit_sha,
            content_sha256=tree.content_sha256,
            branch_or_tag=ref,
            artifact=artifact,
            file_count=tree.file_count,
            total_bytes=tree.total_bytes,
            java_file_count=tree.java_file_count,
            jvm_artifact_count=tree.jvm_artifact_count,
            input_kind=tree.input_kind.value,
            java_version=None,
            build_system=tree.build_system.value,
            status=SnapshotStatus.READY.value,
            failure_code=None,
        )
        self.session.add(snapshot)
        try:
            self.session.flush()
        except IntegrityError as exc:
            self.session.rollback()
            raise ConflictError(
                "Git source snapshot could not be stored",
                error_code="source_snapshot_conflict",
            ) from exc
        self.session.refresh(snapshot)
        return snapshot

    def _repository(self, repository_id: UUID) -> Repository:
        repository = self.session.get(Repository, repository_id)
        if repository is None:
            raise NotFoundError("repository", repository_id)
        return repository

    def _reject_upload(self, upload: SourceUpload, failure_code: str) -> None:
        upload.status = SourceUploadStatus.REJECTED.value
        upload.failure_code = failure_code
        self.session.commit()

    def _master_key(self) -> bytes:
        from cairn.server.secret_store import load_master_key

        return load_master_key(self.secret_key_file)

    @staticmethod
    def _source_path(value: str) -> str:
        normalized = unicodedata.normalize("NFC", value)
        path = PurePosixPath(normalized)
        if (
            not normalized
            or normalized != value
            or normalized.startswith("/")
            or "\\" in normalized
            or any(part in {"", ".", ".."} for part in path.parts)
            or (path.parts and ":" in path.parts[0])
            or any(ord(character) < 32 for character in normalized)
            or path.as_posix() != normalized
        ):
            raise DomainError(
                "snapshot_source_path_invalid",
                "source path must be a normalized relative snapshot path",
                422,
            )
        return path.as_posix()
