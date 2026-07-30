from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import (
    JSON,
    BigInteger,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from cairn.server.domain.enums import ArtifactAccessLevel, ArtifactKind, BuildStatus
from cairn.server.persistence.base import (
    Base,
    TimestampMixin,
    UUIDPrimaryKeyMixin,
    enum_check,
    utcnow,
)


class Artifact(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "artifacts"
    __table_args__ = (
        Index("ix_artifacts_sha256", "sha256"),
        UniqueConstraint(
            "produced_by_task_id",
            "sha256",
            "kind",
            name="uq_artifacts_task_sha_kind",
        ),
        enum_check("kind", ArtifactKind),
        enum_check("access_level", ArtifactAccessLevel),
        CheckConstraint("size_bytes >= 0", name="size_bytes_nonnegative"),
    )

    audit_run_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("audit_runs.id", ondelete="CASCADE"),
        nullable=True,
    )
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    storage_key: Mapped[str] = mapped_column(String(1024), nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    media_type: Mapped[str] = mapped_column(String(255), nullable=False)
    access_level: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        default=ArtifactAccessLevel.NORMAL.value,
    )
    produced_by_task_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("audit_tasks.id", ondelete="RESTRICT")
    )
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    audit_run: Mapped[AuditRun | None] = relationship(
        back_populates="artifacts",
        foreign_keys=[audit_run_id],
    )
    produced_by_task: Mapped[AuditTask | None] = relationship(
        foreign_keys=[produced_by_task_id]
    )


class AuditCoverage(Base):
    __tablename__ = "audit_coverage"
    __table_args__ = (
        enum_check("build_status", BuildStatus),
        CheckConstraint("modules_total >= 0", name="modules_total_nonnegative"),
        CheckConstraint("modules_analyzed >= 0", name="modules_analyzed_nonnegative"),
        CheckConstraint("modules_analyzed <= modules_total", name="modules_within_total"),
        CheckConstraint("java_files_total >= 0", name="java_files_total_nonnegative"),
        CheckConstraint(
            "java_files_analyzed >= 0",
            name="java_files_analyzed_nonnegative",
        ),
        CheckConstraint(
            "java_files_analyzed <= java_files_total",
            name="java_files_within_total",
        ),
        CheckConstraint("entrypoints_total >= 0", name="entrypoints_total_nonnegative"),
        CheckConstraint(
            "entrypoints_analyzed >= 0",
            name="entrypoints_analyzed_nonnegative",
        ),
        CheckConstraint(
            "entrypoints_analyzed <= entrypoints_total",
            name="entrypoints_within_total",
        ),
        CheckConstraint(
            "sensitive_sinks_total >= 0",
            name="sensitive_sinks_total_nonnegative",
        ),
        CheckConstraint(
            "sensitive_sinks_analyzed >= 0",
            name="sensitive_sinks_analyzed_nonnegative",
        ),
        CheckConstraint(
            "sensitive_sinks_analyzed <= sensitive_sinks_total",
            name="sensitive_sinks_within_total",
        ),
    )

    audit_run_id: Mapped[UUID] = mapped_column(
        ForeignKey("audit_runs.id", ondelete="CASCADE"),
        primary_key=True,
    )
    modules_total: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    modules_analyzed: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    java_files_total: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    java_files_analyzed: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    entrypoints_total: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    entrypoints_analyzed: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    entrypoints_auth_covered: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0
    )
    entrypoints_auth_unprotected: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0
    )
    sensitive_sinks_total: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    sensitive_sinks_analyzed: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
    )
    build_status: Mapped[str] = mapped_column(String(16), nullable=False)
    static_tools_completed: Mapped[dict[str, object]] = mapped_column(
        JSON,
        nullable=False,
        default=dict,
    )
    skipped_paths: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    unsupported_components: Mapped[list[dict[str, object]]] = mapped_column(
        JSON,
        nullable=False,
        default=list,
    )
    coverage_warnings: Mapped[list[dict[str, object]]] = mapped_column(
        JSON,
        nullable=False,
        default=list,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        onupdate=utcnow,
    )

    audit_run: Mapped[AuditRun] = relationship(back_populates="coverage")


class Report(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "reports"
    __table_args__ = (
        UniqueConstraint("audit_run_id", "version", name="run_version_unique"),
        CheckConstraint("version > 0", name="version_positive"),
    )

    audit_run_id: Mapped[UUID] = mapped_column(
        ForeignKey("audit_runs.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    summary_json: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False)
    html_artifact_id: Mapped[UUID] = mapped_column(
        ForeignKey("artifacts.id", ondelete="RESTRICT"),
        nullable=False,
    )
    json_artifact_id: Mapped[UUID] = mapped_column(
        ForeignKey("artifacts.id", ondelete="RESTRICT"),
        nullable=False,
    )
    sarif_artifact_id: Mapped[UUID] = mapped_column(
        ForeignKey("artifacts.id", ondelete="RESTRICT"),
        nullable=False,
    )
    generated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
    )

    audit_run: Mapped[AuditRun] = relationship(back_populates="reports")
    html_artifact: Mapped[Artifact] = relationship(foreign_keys=[html_artifact_id])
    json_artifact: Mapped[Artifact] = relationship(foreign_keys=[json_artifact_id])
    sarif_artifact: Mapped[Artifact] = relationship(foreign_keys=[sarif_artifact_id])
