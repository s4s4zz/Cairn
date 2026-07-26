from datetime import UTC, datetime
from enum import StrEnum
from uuid import UUID, uuid4

from sqlalchemy import CheckConstraint, DateTime, MetaData, Uuid
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


def utcnow() -> datetime:
    return datetime.now(UTC)


def is_expired(value: datetime, *, now: datetime | None = None) -> bool:
    """Compare persisted timestamps consistently across PostgreSQL and SQLite."""
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    comparison_time = now or utcnow()
    if comparison_time.tzinfo is None:
        comparison_time = comparison_time.replace(tzinfo=UTC)
    return value <= comparison_time


def enum_check(
    column_name: str,
    enum_type: type[StrEnum],
    *,
    name: str | None = None,
) -> CheckConstraint:
    values = ", ".join(f"'{member.value}'" for member in enum_type)
    return CheckConstraint(
        f"{column_name} IN ({values})",
        name=name or f"{column_name}_values",
    )


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)


class UUIDPrimaryKeyMixin:
    id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        default=uuid4,
    )


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utcnow,
        nullable=False,
    )


class UpdatedTimestampMixin:
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utcnow,
        onupdate=utcnow,
        nullable=False,
    )
