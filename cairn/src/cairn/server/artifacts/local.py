from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import tempfile
from typing import BinaryIO

from cairn.server.artifacts.base import (
    ArtifactIntegrityError,
    ArtifactNotFoundError,
    ArtifactTooLargeError,
    StoredObject,
)


_STORAGE_KEY = re.compile(r"sha256/([0-9a-f]{2})/([0-9a-f]{64})")
_COPY_CHUNK_SIZE = 1024 * 1024


class LocalArtifactStore:
    """Content-addressed, immutable local Artifact byte storage."""

    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        if self.root == Path(self.root.anchor):
            raise ValueError("Artifact root must be a dedicated subdirectory")
        self.objects_root = self.root / "objects"
        self.temporary_root = self.root / "tmp"
        self.objects_root.mkdir(parents=True, exist_ok=True)
        self.temporary_root.mkdir(parents=True, exist_ok=True)
        os.chmod(self.objects_root, 0o700)
        os.chmod(self.temporary_root, 0o700)

    def put_file(
        self,
        source: Path,
        *,
        max_bytes: int | None = None,
    ) -> StoredObject:
        if source.is_symlink() or not source.is_file():
            raise ArtifactIntegrityError("artifact source must be a regular file")
        with source.open("rb") as stream:
            return self.put_stream(stream, max_bytes=max_bytes)

    def put_stream(
        self,
        source: BinaryIO,
        *,
        max_bytes: int | None = None,
    ) -> StoredObject:
        digest = hashlib.sha256()
        size = 0
        file_descriptor, temporary_name = tempfile.mkstemp(
            prefix="artifact-",
            dir=self.temporary_root,
        )
        temporary_path = Path(temporary_name)
        try:
            with os.fdopen(file_descriptor, "wb") as destination:
                while chunk := source.read(_COPY_CHUNK_SIZE):
                    size += len(chunk)
                    if max_bytes is not None and size > max_bytes:
                        raise ArtifactTooLargeError(
                            f"artifact exceeds the {max_bytes} byte limit"
                        )
                    digest.update(chunk)
                    destination.write(chunk)
                destination.flush()
                os.fsync(destination.fileno())

            sha256 = digest.hexdigest()
            storage_key = f"sha256/{sha256[:2]}/{sha256}"
            destination_path = self._path_for_key(storage_key)
            destination_path.parent.mkdir(parents=True, exist_ok=True)
            os.chmod(destination_path.parent, 0o700)
            if destination_path.exists():
                if destination_path.is_symlink() or not destination_path.is_file():
                    raise ArtifactIntegrityError(
                        "existing artifact object is not a regular file"
                    )
                self._verify_path(destination_path, sha256, size)
                temporary_path.unlink()
            else:
                os.chmod(temporary_path, 0o400)
                os.replace(temporary_path, destination_path)
            return StoredObject(
                storage_key=storage_key,
                sha256=sha256,
                size_bytes=size,
            )
        except Exception:
            temporary_path.unlink(missing_ok=True)
            raise

    def resolve(
        self,
        storage_key: str,
        *,
        expected_sha256: str | None = None,
        expected_size: int | None = None,
    ) -> Path:
        path = self._path_for_key(storage_key)
        if not path.exists():
            raise ArtifactNotFoundError(storage_key)
        if path.is_symlink() or not path.is_file():
            raise ArtifactIntegrityError(
                f"artifact object is not a regular file: {storage_key}"
            )
        match = _STORAGE_KEY.fullmatch(storage_key)
        assert match is not None
        key_sha256 = match.group(2)
        if expected_sha256 is not None and key_sha256 != expected_sha256:
            raise ArtifactIntegrityError(
                "artifact metadata hash does not match its storage key"
            )
        self._verify_path(
            path,
            expected_sha256 or key_sha256,
            expected_size,
        )
        return path

    def delete(self, storage_key: str) -> None:
        path = self._path_for_key(storage_key)
        path.unlink(missing_ok=True)

    def _path_for_key(self, storage_key: str) -> Path:
        match = _STORAGE_KEY.fullmatch(storage_key)
        if match is None or match.group(1) != match.group(2)[:2]:
            raise ArtifactIntegrityError("invalid content-addressed storage key")
        path = self.objects_root / match.group(1) / match.group(2)
        if not path.is_relative_to(self.objects_root):
            raise ArtifactIntegrityError("artifact key escapes storage root")
        return path

    @staticmethod
    def _verify_path(
        path: Path,
        expected_sha256: str,
        expected_size: int | None,
    ) -> None:
        digest = hashlib.sha256()
        size = 0
        with path.open("rb") as stream:
            while chunk := stream.read(_COPY_CHUNK_SIZE):
                size += len(chunk)
                digest.update(chunk)
        if expected_size is not None and size != expected_size:
            raise ArtifactIntegrityError("artifact size verification failed")
        if digest.hexdigest() != expected_sha256:
            raise ArtifactIntegrityError("artifact SHA-256 verification failed")
