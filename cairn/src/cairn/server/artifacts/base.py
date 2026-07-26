from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Protocol


class ArtifactStoreError(Exception):
    """Base class for byte-store failures."""


class ArtifactNotFoundError(ArtifactStoreError):
    pass


class ArtifactIntegrityError(ArtifactStoreError):
    pass


class ArtifactTooLargeError(ArtifactStoreError):
    pass


@dataclass(frozen=True, slots=True)
class StoredObject:
    storage_key: str
    sha256: str
    size_bytes: int


class ArtifactStore(Protocol):
    def put_file(
        self,
        source: Path,
        *,
        max_bytes: int | None = None,
    ) -> StoredObject: ...

    def put_stream(
        self,
        source: BinaryIO,
        *,
        max_bytes: int | None = None,
    ) -> StoredObject: ...

    def resolve(
        self,
        storage_key: str,
        *,
        expected_sha256: str | None = None,
        expected_size: int | None = None,
    ) -> Path: ...

    def delete(self, storage_key: str) -> None: ...
