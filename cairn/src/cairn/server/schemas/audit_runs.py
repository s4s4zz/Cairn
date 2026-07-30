from datetime import datetime
from decimal import Decimal
from typing import Annotated, Literal
from uuid import UUID

from pydantic import Field

from cairn.server.domain.enums import (
    AuditRunStatus,
    AuditStage,
    AuditTaskStatus,
    AuditTaskType,
    BuildStatus,
)
from cairn.server.schemas.common import Page, StrictModel


class ExistingSnapshotSource(StrictModel):
    type: Literal["snapshot"]
    snapshot_id: UUID


class GitRefSource(StrictModel):
    type: Literal["git_ref"]
    ref: str = Field(min_length=1, max_length=255)


class UploadSource(StrictModel):
    type: Literal["upload"]
    upload_id: UUID


SourceRequest = Annotated[
    ExistingSnapshotSource | GitRefSource | UploadSource,
    Field(discriminator="type"),
]


class AuditRunCreate(StrictModel):
    repository_id: UUID
    policy_id: UUID
    source_request: SourceRequest


class AuditRunResponse(StrictModel):
    id: UUID
    repository_id: UUID
    source_request: dict[str, object]
    snapshot_id: UUID | None
    policy_id: UUID
    policy_version: int
    status: AuditRunStatus
    current_stage: AuditStage | None
    progress: Decimal
    warning_count: int
    failure_code: str | None
    failure_reason: str | None
    created_by: str
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None


class AuditRunFilters(StrictModel):
    repository_id: UUID | None = None
    status: AuditRunStatus | None = None
    limit: int = Field(default=50, ge=1, le=100)
    offset: int = Field(default=0, ge=0)


AuditRunPage = Page[AuditRunResponse]


class AuditTaskResponse(StrictModel):
    id: UUID
    audit_run_id: UUID
    type: AuditTaskType
    scope_key: str
    scope: dict[str, object]
    status: AuditTaskStatus
    worker_name: str | None
    attempt: int
    max_attempts: int
    timeout_seconds: int
    error_code: str | None
    error_detail: str | None
    started_at: datetime | None
    finished_at: datetime | None
    output_artifact_ids: list[str]
    created_at: datetime


AuditTaskPage = Page[AuditTaskResponse]


class AuditRunStageEventResponse(StrictModel):
    """One stage entry, closed by the next entry or by the run's completion."""

    stage: AuditStage
    entered_at: datetime
    exited_at: datetime | None


class AuditCoverageResponse(StrictModel):
    audit_run_id: UUID
    modules_total: int
    modules_analyzed: int
    java_files_total: int
    java_files_analyzed: int
    entrypoints_total: int
    entrypoints_analyzed: int
    sensitive_sinks_total: int
    sensitive_sinks_analyzed: int
    build_status: BuildStatus
    static_tools_completed: dict[str, object]
    skipped_paths: list[str]
    unsupported_components: list[dict[str, object]]
    coverage_warnings: list[dict[str, object]]
    updated_at: datetime
