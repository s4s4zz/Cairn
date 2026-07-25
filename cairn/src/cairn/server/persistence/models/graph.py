from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import JSON, DateTime, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from cairn.server.domain.enums import AuditFactKind, AuditIntentStatus
from cairn.server.persistence.base import (
    Base,
    TimestampMixin,
    UUIDPrimaryKeyMixin,
    enum_check,
)


class AuditFact(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "audit_facts"
    __table_args__ = (enum_check("kind", AuditFactKind),)

    audit_run_id: Mapped[UUID] = mapped_column(
        ForeignKey("audit_runs.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    structured_payload: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False)
    evidence_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    created_by_task_id: Mapped[UUID] = mapped_column(
        ForeignKey("audit_tasks.id", ondelete="RESTRICT"),
        nullable=False,
    )

    audit_run: Mapped[AuditRun] = relationship(back_populates="facts")
    created_by_task: Mapped[AuditTask] = relationship(
        foreign_keys=[created_by_task_id]
    )
    intent_sources: Mapped[list[AuditIntentSource]] = relationship(
        back_populates="fact",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )


class AuditIntent(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "audit_intents"
    __table_args__ = (enum_check("status", AuditIntentStatus),)

    audit_run_id: Mapped[UUID] = mapped_column(
        ForeignKey("audit_runs.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    category: Mapped[str] = mapped_column(String(255), nullable=False)
    scope: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False)
    required_capabilities: Mapped[list[str]] = mapped_column(
        JSON,
        nullable=False,
        default=list,
    )
    status: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        default=AuditIntentStatus.PENDING.value,
    )
    created_by_task_id: Mapped[UUID] = mapped_column(
        ForeignKey("audit_tasks.id", ondelete="RESTRICT"),
        nullable=False,
    )
    claimed_by_task_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("audit_tasks.id", ondelete="RESTRICT")
    )
    concluded_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    audit_run: Mapped[AuditRun] = relationship(back_populates="intents")
    created_by_task: Mapped[AuditTask] = relationship(
        foreign_keys=[created_by_task_id]
    )
    claimed_by_task: Mapped[AuditTask | None] = relationship(
        foreign_keys=[claimed_by_task_id]
    )
    source_links: Mapped[list[AuditIntentSource]] = relationship(
        back_populates="intent",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )


class AuditIntentSource(Base):
    __tablename__ = "audit_intent_sources"

    audit_intent_id: Mapped[UUID] = mapped_column(
        ForeignKey("audit_intents.id", ondelete="CASCADE"),
        primary_key=True,
    )
    audit_fact_id: Mapped[UUID] = mapped_column(
        ForeignKey("audit_facts.id", ondelete="CASCADE"),
        primary_key=True,
    )

    intent: Mapped[AuditIntent] = relationship(back_populates="source_links")
    fact: Mapped[AuditFact] = relationship(back_populates="intent_sources")
