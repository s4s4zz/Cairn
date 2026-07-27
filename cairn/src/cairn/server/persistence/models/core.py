from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from uuid import UUID, uuid4

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    Numeric,
    String,
    Text,
    UniqueConstraint,
    event,
    inspect,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from cairn.server.domain.enums import (
    AuditRunStatus,
    AuditStage,
    AuditTaskStatus,
    AuditTaskType,
    BuildSystem,
    DynamicVerificationMode,
    SnapshotStatus,
    SourceType,
)
from cairn.server.persistence.base import (
    Base,
    TimestampMixin,
    UUIDPrimaryKeyMixin,
    UpdatedTimestampMixin,
    enum_check,
)


class Repository(
    UUIDPrimaryKeyMixin,
    TimestampMixin,
    UpdatedTimestampMixin,
    Base,
):
    __tablename__ = "repositories"
    __table_args__ = (
        UniqueConstraint("name", name="name_unique"),
        Index("ix_repositories_name", "name"),
        enum_check("source_type", SourceType),
    )

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    source_type: Mapped[str] = mapped_column(String(32), nullable=False)
    remote_url: Mapped[str | None] = mapped_column(Text)
    credential_ref: Mapped[str | None] = mapped_column(String(255))
    default_branch: Mapped[str | None] = mapped_column(String(255))
    created_by: Mapped[str] = mapped_column(String(255), nullable=False)

    snapshots: Mapped[list[SourceSnapshot]] = relationship(
        back_populates="repository",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    audit_runs: Mapped[list[AuditRun]] = relationship(back_populates="repository")


class SourceSnapshot(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "source_snapshots"
    __table_args__ = (
        Index("ix_source_snapshots_content_sha256", "content_sha256"),
        enum_check("build_system", BuildSystem),
        enum_check("status", SnapshotStatus),
        CheckConstraint("file_count >= 0", name="file_count_nonnegative"),
        CheckConstraint("total_bytes >= 0", name="total_bytes_nonnegative"),
        CheckConstraint("java_file_count >= 0", name="java_file_count_nonnegative"),
    )

    repository_id: Mapped[UUID] = mapped_column(
        ForeignKey("repositories.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    commit_sha: Mapped[str | None] = mapped_column(String(128))
    content_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    branch_or_tag: Mapped[str | None] = mapped_column(String(255))
    artifact_id: Mapped[UUID] = mapped_column(
        ForeignKey("artifacts.id", ondelete="RESTRICT"),
        nullable=False,
        unique=True,
    )
    file_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    total_bytes: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    java_file_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    java_version: Mapped[str | None] = mapped_column(String(64))
    build_system: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        default=BuildSystem.UNKNOWN.value,
    )
    status: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        default=SnapshotStatus.CREATING.value,
    )
    failure_code: Mapped[str | None] = mapped_column(String(128))

    repository: Mapped[Repository] = relationship(back_populates="snapshots")
    artifact: Mapped[Artifact] = relationship(foreign_keys=[artifact_id])


class SnapshotImmutableError(ValueError):
    """Raised when persisted data in a ready Snapshot is changed."""


@event.listens_for(SourceSnapshot, "before_update")
def prevent_ready_snapshot_update(mapper, connection, target: SourceSnapshot) -> None:
    del connection
    state = inspect(target)
    changed = any(
        state.attrs[column.key].history.has_changes()
        for column in mapper.column_attrs
    )
    if not changed:
        return
    status_history = state.attrs.status.history
    previous_status = (
        status_history.deleted[0] if status_history.deleted else target.status
    )
    if previous_status == SnapshotStatus.READY.value:
        raise SnapshotImmutableError("ready source snapshots are immutable")


class AuditPolicy(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "audit_policies"
    __table_args__ = (
        UniqueConstraint("name", "version", name="name_version_unique"),
        Index("ix_audit_policies_name", "name"),
        Index(
            "uq_audit_policies_active_name",
            "name",
            unique=True,
            postgresql_where=text("active"),
            sqlite_where=text("active = 1"),
        ),
        enum_check("dynamic_verification", DynamicVerificationMode),
        CheckConstraint("version > 0", name="version_positive"),
    )

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    include_paths: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    exclude_paths: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    enabled_scanners: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    dynamic_verification: Mapped[str] = mapped_column(String(16), nullable=False)
    severity_thresholds: Mapped[dict[str, object]] = mapped_column(
        JSON,
        nullable=False,
        default=dict,
    )
    resource_budget: Mapped[dict[str, object]] = mapped_column(
        JSON,
        nullable=False,
        default=dict,
    )
    # Per-run ceilings for the AI semantic stage: max_tasks,
    # max_turns_per_task, max_output_tokens_per_task and an optional
    # `categories` allowlist. Each semantic task is one model conversation, so
    # this is the operator's cost control. See
    # cairn.orchestrator.semantic_tasks.SemanticBudget.
    semantic_budget: Mapped[dict[str, object]] = mapped_column(
        JSON,
        nullable=False,
        default=dict,
    )
    # Per-run ceilings for the independent machine-review stage: max_findings,
    # max_turns_per_task and max_output_tokens_per_task. Independent review is
    # one model conversation per critical or high Finding, so it needs its own
    # ceiling rather than sharing the semantic one — the two stages are sized by
    # different things (scopes planned vs findings promoted). See
    # cairn.orchestrator.verification.VerificationBudget.
    verification_budget: Mapped[dict[str, object]] = mapped_column(
        JSON,
        nullable=False,
        default=dict,
    )
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    audit_runs: Mapped[list[AuditRun]] = relationship(back_populates="policy")


class AuditRun(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "audit_runs"
    __table_args__ = (
        Index("ix_audit_runs_repository_id", "repository_id"),
        Index("ix_audit_runs_status", "status"),
        enum_check("status", AuditRunStatus),
        enum_check("current_stage", AuditStage),
        CheckConstraint("policy_version > 0", name="policy_version_positive"),
        CheckConstraint(
            "progress >= 0 AND progress <= 100",
            name="progress_percentage",
        ),
        CheckConstraint("warning_count >= 0", name="warning_count_nonnegative"),
    )

    repository_id: Mapped[UUID] = mapped_column(
        ForeignKey("repositories.id", ondelete="RESTRICT"),
        nullable=False,
    )
    source_request: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False)
    snapshot_id: Mapped[UUID | None] = mapped_column(
        ForeignKey(
            "source_snapshots.id",
            name="fk_audit_runs_snapshot_id_source_snapshots",
            ondelete="RESTRICT",
            use_alter=True,
        )
    )
    policy_id: Mapped[UUID] = mapped_column(
        ForeignKey("audit_policies.id", ondelete="RESTRICT"),
        nullable=False,
    )
    policy_version: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default=AuditRunStatus.CREATED.value,
    )
    current_stage: Mapped[str | None] = mapped_column(String(32))
    progress: Mapped[Decimal] = mapped_column(
        Numeric(5, 2),
        nullable=False,
        default=Decimal("0"),
    )
    warning_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    failure_code: Mapped[str | None] = mapped_column(String(128))
    failure_reason: Mapped[str | None] = mapped_column(Text)
    created_by: Mapped[str] = mapped_column(String(255), nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    repository: Mapped[Repository] = relationship(back_populates="audit_runs")
    snapshot: Mapped[SourceSnapshot | None] = relationship(foreign_keys=[snapshot_id])
    policy: Mapped[AuditPolicy] = relationship(back_populates="audit_runs")
    tasks: Mapped[list[AuditTask]] = relationship(
        back_populates="audit_run",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    artifacts: Mapped[list[Artifact]] = relationship(
        back_populates="audit_run",
        cascade="all, delete-orphan",
        passive_deletes=True,
        foreign_keys="Artifact.audit_run_id",
    )
    findings: Mapped[list[Finding]] = relationship(
        back_populates="audit_run",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    coverage: Mapped[AuditCoverage | None] = relationship(
        back_populates="audit_run",
        cascade="all, delete-orphan",
        passive_deletes=True,
        uselist=False,
    )
    reports: Mapped[list[Report]] = relationship(
        back_populates="audit_run",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    facts: Mapped[list[AuditFact]] = relationship(
        back_populates="audit_run",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    intents: Mapped[list[AuditIntent]] = relationship(
        back_populates="audit_run",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )


class AuditTask(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "audit_tasks"
    __table_args__ = (
        Index("ix_audit_tasks_run_status", "audit_run_id", "status"),
        Index("ix_audit_tasks_status_lease", "status", "lease_expires_at"),
        UniqueConstraint(
            "audit_run_id",
            "scope_key",
            name="uq_audit_tasks_run_scope_key",
        ),
        enum_check("type", AuditTaskType),
        enum_check("status", AuditTaskStatus),
        CheckConstraint("attempt >= 0", name="attempt_nonnegative"),
        CheckConstraint("max_attempts > 0", name="max_attempts_positive"),
        CheckConstraint("timeout_seconds > 0", name="timeout_seconds_positive"),
    )

    audit_run_id: Mapped[UUID] = mapped_column(
        ForeignKey("audit_runs.id", ondelete="CASCADE"),
        nullable=False,
    )
    parent_task_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("audit_tasks.id", ondelete="CASCADE")
    )
    type: Mapped[str] = mapped_column(String(32), nullable=False)
    scope_key: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
        default=lambda: f"task:{uuid4()}",
    )
    scope: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)
    required_capabilities: Mapped[list[str]] = mapped_column(
        JSON,
        nullable=False,
        default=list,
    )
    status: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        default=AuditTaskStatus.QUEUED.value,
    )
    worker_name: Mapped[str | None] = mapped_column(String(255))
    sandbox_id: Mapped[UUID | None] = mapped_column(unique=True)
    attempt: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    max_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=3)
    timeout_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=900)
    input_artifact_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    output_artifact_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    error_code: Mapped[str | None] = mapped_column(String(128))
    error_detail: Mapped[str | None] = mapped_column(Text)
    lease_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    audit_run: Mapped[AuditRun] = relationship(back_populates="tasks")
    parent: Mapped[AuditTask | None] = relationship(
        remote_side="AuditTask.id",
        back_populates="children",
    )
    children: Mapped[list[AuditTask]] = relationship(back_populates="parent")
