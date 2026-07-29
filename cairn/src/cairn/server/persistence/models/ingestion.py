from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING
from uuid import UUID

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from cairn.server.domain.enums import (
    GitCredentialKind,
    SourceUploadStatus,
)
from cairn.server.persistence.base import (
    Base,
    TimestampMixin,
    UUIDPrimaryKeyMixin,
    enum_check,
)

if TYPE_CHECKING:
    from cairn.server.persistence.models.artifacts import Artifact
    from cairn.server.persistence.models.core import Repository


class SourceUpload(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "source_uploads"
    __table_args__ = (
        Index("ix_source_uploads_status_expires", "status", "expires_at"),
        CheckConstraint(
            "source_type IN ('zip', 'local_upload', 'binary_upload')",
            name="source_type_values",
        ),
        enum_check("status", SourceUploadStatus),
    )

    artifact_id: Mapped[UUID] = mapped_column(
        ForeignKey("artifacts.id", ondelete="RESTRICT"),
        nullable=False,
        unique=True,
    )
    repository_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("repositories.id", ondelete="RESTRICT"),
        index=True,
    )
    source_type: Mapped[str] = mapped_column(String(32), nullable=False)
    original_filename: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    failure_code: Mapped[str | None] = mapped_column(String(128))
    created_by: Mapped[str] = mapped_column(String(255), nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    artifact: Mapped[Artifact] = relationship(foreign_keys=[artifact_id])
    repository: Mapped[Repository | None] = relationship()


class EncryptedSecret(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "encrypted_secrets"
    __table_args__ = (
        UniqueConstraint("reference", name="reference_unique"),
        enum_check("kind", GitCredentialKind),
        CheckConstraint("length(nonce) = 12", name="nonce_length"),
        CheckConstraint("key_version > 0", name="key_version_positive"),
    )

    reference: Mapped[str] = mapped_column(String(80), nullable=False)
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    nonce: Mapped[bytes] = mapped_column(LargeBinary(12), nullable=False)
    ciphertext: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    key_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
