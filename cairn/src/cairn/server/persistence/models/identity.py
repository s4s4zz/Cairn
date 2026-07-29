"""Local accounts, sessions and the operator audit log (§9.8).

Single-tenant means these tables answer "who did this", not "whose data is
this": every row in the rest of the schema belongs to the one tenant, and the
role a user holds decides what they may do to it, never what they may see of
someone else's.
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    JSON,
    LargeBinary,
    String,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from cairn.server.domain.enums import UserRole
from cairn.server.persistence.base import (
    Base,
    TimestampMixin,
    UUIDPrimaryKeyMixin,
    enum_check,
    utcnow,
)


class User(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "users"
    __table_args__ = (
        UniqueConstraint("username", name="username_unique"),
        enum_check("role", UserRole),
    )

    username: Mapped[str] = mapped_column(String(64), nullable=False)
    # PHC-encoded Argon2id, produced by cairn.server.auth.passwords. Stored as
    # text rather than split into columns so a parameter change is a rehash of
    # one field instead of a migration.
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(16), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        onupdate=utcnow,
    )

    sessions: Mapped[list[UserSession]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )


class UserSession(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """One browser session.

    The cookie value never reaches the database: only its SHA-256 does, so a
    database read — a backup, a support dump, a SQL injection in some future
    feature — cannot be replayed as a login. The CSRF token is stored the same
    way, because the double-submit check compares the request header against
    this row, not against the second cookie alone.
    """

    __tablename__ = "user_sessions"
    __table_args__ = (
        UniqueConstraint("token_sha256", name="token_sha256_unique"),
        Index("ix_user_sessions_user_id", "user_id"),
    )

    user_id: Mapped[UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    token_sha256: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    csrf_sha256: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
    )
    client_ip: Mapped[str | None] = mapped_column(String(45))
    user_agent: Mapped[str | None] = mapped_column(String(255))

    user: Mapped[User] = relationship(back_populates="sessions")


class AuditLogEntry(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """An append-only record of one privileged operation.

    ``actor_username`` is denormalised on purpose: the log has to stay readable
    after the account is renamed or deleted, and a foreign key that nulls out
    would erase exactly the fact the log exists to keep.
    """

    __tablename__ = "audit_log_entries"
    __table_args__ = (
        Index("ix_audit_log_entries_created_at", "created_at"),
        Index("ix_audit_log_entries_action", "action"),
        Index("ix_audit_log_entries_target", "target_type", "target_id"),
    )

    actor_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
    )
    actor_username: Mapped[str] = mapped_column(String(64), nullable=False)
    actor_role: Mapped[str | None] = mapped_column(String(16))
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    target_type: Mapped[str | None] = mapped_column(String(64))
    target_id: Mapped[str | None] = mapped_column(String(128))
    outcome: Mapped[str] = mapped_column(String(16), nullable=False, default="success")
    http_status: Mapped[int | None] = mapped_column(Integer)
    request_id: Mapped[str | None] = mapped_column(String(128))
    client_ip: Mapped[str | None] = mapped_column(String(45))
    detail: Mapped[dict[str, object]] = mapped_column(
        JSON,
        nullable=False,
        default=dict,
    )
