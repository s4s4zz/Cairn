from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Annotated
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator


Sha256 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
StorageKey = Annotated[
    str,
    StringConstraints(pattern=r"^sha256/[0-9a-f]{2}/[0-9a-f]{64}$"),
]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class SandboxTemplateName(StrEnum):
    ANALYSIS = "analysis"
    BUILD = "build"
    VALIDATION = "validation"


class SandboxOperation(StrEnum):
    DEFAULT = "default"
    INVENTORY = "inventory"
    BUILD = "build"
    CODEQL = "codeql"
    SEMGREP = "semgrep"
    FINDSECBUGS = "findsecbugs"
    DEPENDENCY_CHECK = "dependency-check"
    TRIVY = "trivy"
    GITLEAKS = "gitleaks"
    CONFIG_RULES = "config-rules"


class SandboxStatus(StrEnum):
    CREATED = "created"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMED_OUT = "timed_out"
    RESOURCE_EXCEEDED = "resource_exceeded"


ACTIVE_SANDBOX_STATUSES = frozenset(
    {
        SandboxStatus.CREATED,
        SandboxStatus.RUNNING,
    }
)
TERMINAL_SANDBOX_STATUSES = frozenset(set(SandboxStatus) - ACTIVE_SANDBOX_STATUSES)


class SnapshotArtifact(StrictModel):
    storage_key: StorageKey
    sha256: Sha256
    size_bytes: int = Field(gt=0, le=4 * 1024 * 1024 * 1024)

    @model_validator(mode="after")
    def validate_content_address(self) -> "SnapshotArtifact":
        expected = f"sha256/{self.sha256[:2]}/{self.sha256}"
        if self.storage_key != expected:
            raise ValueError("storage_key must address the declared SHA-256")
        return self


class SandboxLimitsOverride(StrictModel):
    cpu_millis: int | None = Field(default=None, ge=100, le=16_000)
    memory_bytes: int | None = Field(
        default=None,
        ge=64 * 1024 * 1024,
        le=32 * 1024 * 1024 * 1024,
    )
    pids: int | None = Field(default=None, ge=16, le=4096)
    disk_bytes: int | None = Field(
        default=None,
        ge=16 * 1024 * 1024,
        le=64 * 1024 * 1024 * 1024,
    )
    output_bytes: int | None = Field(
        default=None,
        ge=1024 * 1024,
        le=16 * 1024 * 1024 * 1024,
    )
    tmpfs_bytes: int | None = Field(
        default=None,
        ge=1024 * 1024,
        le=4 * 1024 * 1024 * 1024,
    )
    timeout_seconds: int | None = Field(default=None, ge=1, le=24 * 60 * 60)


class SandboxLimits(StrictModel):
    cpu_millis: int = Field(ge=100, le=16_000)
    memory_bytes: int = Field(
        ge=64 * 1024 * 1024,
        le=32 * 1024 * 1024 * 1024,
    )
    pids: int = Field(ge=16, le=4096)
    disk_bytes: int = Field(
        ge=16 * 1024 * 1024,
        le=64 * 1024 * 1024 * 1024,
    )
    output_bytes: int = Field(
        ge=1024 * 1024,
        le=16 * 1024 * 1024 * 1024,
    )
    tmpfs_bytes: int = Field(
        ge=1024 * 1024,
        le=4 * 1024 * 1024 * 1024,
    )
    timeout_seconds: int = Field(ge=1, le=24 * 60 * 60)

    @model_validator(mode="after")
    def validate_related_limits(self) -> "SandboxLimits":
        if self.output_bytes > self.disk_bytes:
            raise ValueError("output_bytes must not exceed disk_bytes")
        if self.tmpfs_bytes > self.memory_bytes:
            raise ValueError("tmpfs_bytes must not exceed memory_bytes")
        return self


class SandboxCreateRequest(StrictModel):
    template: SandboxTemplateName
    operation: SandboxOperation = SandboxOperation.DEFAULT
    snapshot: SnapshotArtifact
    task_id: UUID | None = None
    limits: SandboxLimitsOverride = Field(default_factory=SandboxLimitsOverride)


class SandboxWaitRequest(StrictModel):
    timeout_seconds: float = Field(default=0, ge=0, le=30)


class SandboxArtifact(StrictModel):
    storage_key: StorageKey
    sha256: Sha256
    size_bytes: int = Field(ge=0)
    media_type: str = Field(min_length=1, max_length=255)


class SandboxRecord(StrictModel):
    id: UUID
    task_id: UUID | None = None
    template: SandboxTemplateName
    operation: SandboxOperation = SandboxOperation.DEFAULT
    snapshot: SnapshotArtifact
    limits: SandboxLimits
    status: SandboxStatus
    created_at: datetime
    deadline_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None
    exit_code: int | None = None
    failure_code: str | None = Field(default=None, max_length=128)
    artifacts: list[SandboxArtifact] = Field(default_factory=list)
    resources_destroyed: bool = False
