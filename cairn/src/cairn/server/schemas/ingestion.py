from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from pydantic import Field

from cairn.server.domain.enums import (
    BuildSystem,
    SnapshotStatus,
    SourceType,
    SourceUploadStatus,
)
from cairn.server.schemas.common import StrictModel


class SourceUploadResponse(StrictModel):
    id: UUID
    artifact_id: UUID
    repository_id: UUID | None
    source_type: SourceType
    original_filename: str
    status: SourceUploadStatus
    failure_code: str | None
    created_by: str
    created_at: datetime
    expires_at: datetime | None


class GitSnapshotRequest(StrictModel):
    type: Literal["git_ref"]
    ref: str = Field(min_length=1, max_length=255)


class UploadSnapshotRequest(StrictModel):
    type: Literal["upload"]
    upload_id: UUID


SnapshotCreateRequest = Annotated[
    GitSnapshotRequest | UploadSnapshotRequest,
    Field(discriminator="type"),
]


class SourceSnapshotResponse(StrictModel):
    id: UUID
    repository_id: UUID
    commit_sha: str | None
    content_sha256: str
    branch_or_tag: str | None
    artifact_id: UUID
    file_count: int
    total_bytes: int
    java_file_count: int
    java_version: str | None
    build_system: BuildSystem
    status: SnapshotStatus
    failure_code: str | None
    created_at: datetime
