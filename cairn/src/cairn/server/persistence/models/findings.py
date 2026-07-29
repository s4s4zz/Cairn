from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import (
    JSON,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from cairn.server.domain.enums import (
    EvidenceType,
    FindingConfidence,
    FindingSeverity,
    FindingStatus,
    LocationOriginKind,
    LocationRole,
    ReviewVerdict,
    RuntimeVerificationStatus,
    VerificationMethod,
    VerificationVerdict,
)
from cairn.server.persistence.base import (
    Base,
    UUIDPrimaryKeyMixin,
    enum_check,
    utcnow,
)


class Finding(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "findings"
    __table_args__ = (
        UniqueConstraint(
            "audit_run_id",
            "fingerprint",
            name="run_fingerprint_unique",
        ),
        Index("ix_findings_fingerprint", "fingerprint"),
        Index("ix_findings_run_severity_status", "audit_run_id", "severity", "status"),
        enum_check("severity", FindingSeverity),
        enum_check("confidence", FindingConfidence),
        enum_check("status", FindingStatus),
        enum_check("runtime_verification", RuntimeVerificationStatus),
    )

    audit_run_id: Mapped[UUID] = mapped_column(
        ForeignKey("audit_runs.id", ondelete="CASCADE"),
        nullable=False,
    )
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    category: Mapped[str] = mapped_column(String(255), nullable=False)
    cwe_id: Mapped[str] = mapped_column(String(32), nullable=False)
    owasp_category: Mapped[str | None] = mapped_column(String(128))
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    confidence: Mapped[str] = mapped_column(String(16), nullable=False)
    status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default=FindingStatus.CANDIDATE.value,
    )
    attack_preconditions: Mapped[str] = mapped_column(Text, nullable=False)
    impact: Mapped[str] = mapped_column(Text, nullable=False)
    remediation: Mapped[str] = mapped_column(Text, nullable=False)
    runtime_verification: Mapped[str] = mapped_column(
        String(24),
        nullable=False,
        default=RuntimeVerificationStatus.UNVERIFIED.value,
    )
    discovered_by: Mapped[str] = mapped_column(String(255), nullable=False)
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        onupdate=utcnow,
    )

    audit_run: Mapped[AuditRun] = relationship(back_populates="findings")
    locations: Mapped[list[FindingLocation]] = relationship(
        back_populates="finding",
        cascade="all, delete-orphan",
        passive_deletes=True,
        order_by="FindingLocation.ordinal",
    )
    evidence: Mapped[list[Evidence]] = relationship(
        back_populates="finding",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    verifications: Mapped[list[Verification]] = relationship(
        back_populates="finding",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    human_reviews: Mapped[list[HumanReview]] = relationship(
        back_populates="finding",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )


class FindingLocation(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "finding_locations"
    __table_args__ = (
        UniqueConstraint("finding_id", "ordinal", name="finding_ordinal_unique"),
        enum_check("role", LocationRole),
        enum_check("origin_kind", LocationOriginKind),
        CheckConstraint(
            "(start_line IS NULL AND end_line IS NULL) OR "
            "(start_line > 0 AND end_line >= start_line)",
            name="source_line_range_valid",
        ),
        CheckConstraint(
            "(decompiled_start_line IS NULL AND decompiled_end_line IS NULL) OR "
            "(decompiled_start_line > 0 AND "
            "decompiled_end_line >= decompiled_start_line)",
            name="decompiled_line_range_valid",
        ),
        CheckConstraint(
            "bytecode_offset IS NULL OR bytecode_offset >= 0",
            name="bytecode_offset_nonnegative",
        ),
        CheckConstraint(
            "(method_name IS NULL AND method_descriptor IS NULL) OR "
            "(method_name IS NOT NULL AND method_descriptor IS NOT NULL)",
            name="method_identity_complete",
        ),
        CheckConstraint(
            "bytecode_offset IS NULL OR method_name IS NOT NULL",
            name="bytecode_offset_has_method",
        ),
        CheckConstraint(
            "origin_kind NOT IN ('bytecode', 'decompiled') OR "
            "(entry_path IS NOT NULL AND class_name IS NOT NULL)",
            name="bytecode_identity_complete",
        ),
        CheckConstraint(
            "origin_kind != 'source' OR "
            "(file_path IS NOT NULL AND start_line IS NOT NULL "
            "AND code_snippet IS NOT NULL)",
            name="source_evidence_complete",
        ),
        CheckConstraint(
            "origin_kind != 'config' OR "
            "(file_path IS NOT NULL OR entry_path IS NOT NULL)",
            name="config_path_present",
        ),
        CheckConstraint(
            "origin_kind != 'decompiled' OR decompiled_artifact_id IS NOT NULL",
            name="decompiled_artifact_present",
        ),
        CheckConstraint(
            "decompiled_start_line IS NULL OR "
            "decompiled_artifact_id IS NOT NULL",
            name="decompiled_lines_have_artifact",
        ),
        CheckConstraint("ordinal >= 0", name="ordinal_nonnegative"),
    )

    finding_id: Mapped[UUID] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    role: Mapped[str] = mapped_column(String(16), nullable=False)
    origin_kind: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        default=LocationOriginKind.SOURCE.value,
    )
    file_path: Mapped[str | None] = mapped_column(Text)
    start_line: Mapped[int | None] = mapped_column(Integer)
    end_line: Mapped[int | None] = mapped_column(Integer)
    symbol: Mapped[str | None] = mapped_column(Text)
    code_snippet: Mapped[str | None] = mapped_column(Text)
    container_path: Mapped[str | None] = mapped_column(Text)
    entry_path: Mapped[str | None] = mapped_column(Text)
    class_name: Mapped[str | None] = mapped_column(Text)
    method_name: Mapped[str | None] = mapped_column(Text)
    method_descriptor: Mapped[str | None] = mapped_column(Text)
    bytecode_offset: Mapped[int | None] = mapped_column(Integer)
    decompiled_artifact_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("artifacts.id", ondelete="RESTRICT")
    )
    decompiled_start_line: Mapped[int | None] = mapped_column(Integer)
    decompiled_end_line: Mapped[int | None] = mapped_column(Integer)
    snapshot_sha: Mapped[str] = mapped_column(String(128), nullable=False)
    ordinal: Mapped[int] = mapped_column(Integer, nullable=False)

    finding: Mapped[Finding] = relationship(back_populates="locations")
    decompiled_artifact: Mapped[Artifact | None] = relationship(
        foreign_keys=[decompiled_artifact_id]
    )

    @property
    def source_path(self) -> str | None:
        """CodeLocationV2 name for the legacy file_path storage column."""

        return self.file_path


class Evidence(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "evidence"
    __table_args__ = (enum_check("type", EvidenceType),)

    finding_id: Mapped[UUID] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    type: Mapped[str] = mapped_column(String(32), nullable=False)
    artifact_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("artifacts.id", ondelete="RESTRICT")
    )
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    sha256: Mapped[str | None] = mapped_column(String(64))
    produced_by_task_id: Mapped[UUID] = mapped_column(
        ForeignKey("audit_tasks.id", ondelete="RESTRICT"),
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
    )

    finding: Mapped[Finding] = relationship(back_populates="evidence")
    artifact: Mapped[Artifact | None] = relationship(foreign_keys=[artifact_id])
    produced_by_task: Mapped[AuditTask] = relationship(
        foreign_keys=[produced_by_task_id]
    )


class Verification(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "verifications"
    __table_args__ = (
        enum_check("method", VerificationMethod),
        enum_check("verdict", VerificationVerdict),
    )

    finding_id: Mapped[UUID] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    method: Mapped[str] = mapped_column(String(32), nullable=False)
    verdict: Mapped[str] = mapped_column(String(16), nullable=False)
    verifier: Mapped[str] = mapped_column(String(255), nullable=False)
    evidence_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    reasoning: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
    )

    finding: Mapped[Finding] = relationship(back_populates="verifications")


class HumanReview(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "human_reviews"
    __table_args__ = (
        enum_check("verdict", ReviewVerdict),
        enum_check("original_severity", FindingSeverity),
        enum_check("final_severity", FindingSeverity),
    )

    finding_id: Mapped[UUID] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    verdict: Mapped[str] = mapped_column(String(16), nullable=False)
    original_severity: Mapped[str] = mapped_column(String(16), nullable=False)
    final_severity: Mapped[str] = mapped_column(String(16), nullable=False)
    reviewer_id: Mapped[str] = mapped_column(String(255), nullable=False)
    comment: Mapped[str] = mapped_column(Text, nullable=False)
    reviewed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
    )

    finding: Mapped[Finding] = relationship(back_populates="human_reviews")
