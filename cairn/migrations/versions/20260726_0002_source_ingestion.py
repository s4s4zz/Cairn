"""Add source ingestion, encrypted credentials, and pre-run Artifacts.

Revision ID: 20260726_0002
Revises: 20260725_0001
Create Date: 2026-07-26
"""
from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "20260726_0002"
down_revision: str | None = "20260725_0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.alter_column(
        "artifacts",
        "audit_run_id",
        existing_type=sa.Uuid(),
        nullable=True,
    )
    op.drop_constraint(
        op.f("uq_artifacts_storage_key"),
        "artifacts",
        type_="unique",
    )
    op.drop_constraint(
        op.f("ck_artifacts_kind_values"),
        "artifacts",
        type_="check",
    )
    op.create_check_constraint(
        op.f("ck_artifacts_kind_values"),
        "artifacts",
        "kind IN ('source_upload', 'source_snapshot', 'scan_result', "
        "'build_log', 'runtime_log', 'poc', 'report', 'other')",
    )
    op.create_table(
        "encrypted_secrets",
        sa.Column("reference", sa.String(length=80), nullable=False),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("nonce", sa.LargeBinary(length=12), nullable=False),
        sa.Column("ciphertext", sa.LargeBinary(), nullable=False),
        sa.Column("key_version", sa.Integer(), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "kind IN ('https_token', 'ssh_key')",
            name=op.f("ck_encrypted_secrets_kind_values"),
        ),
        sa.CheckConstraint(
            "key_version > 0",
            name=op.f("ck_encrypted_secrets_key_version_positive"),
        ),
        sa.CheckConstraint(
            "length(nonce) = 12",
            name=op.f("ck_encrypted_secrets_nonce_length"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_encrypted_secrets")),
        sa.UniqueConstraint("reference", name="reference_unique"),
    )
    op.create_table(
        "source_uploads",
        sa.Column("artifact_id", sa.Uuid(), nullable=False),
        sa.Column("repository_id", sa.Uuid(), nullable=True),
        sa.Column("source_type", sa.String(length=32), nullable=False),
        sa.Column("original_filename", sa.String(length=255), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("failure_code", sa.String(length=128), nullable=True),
        sa.Column("created_by", sa.String(length=255), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "source_type IN ('zip', 'local_upload')",
            name=op.f("ck_source_uploads_source_type_values"),
        ),
        sa.CheckConstraint(
            "status IN ('ready', 'rejected', 'expired')",
            name=op.f("ck_source_uploads_status_values"),
        ),
        sa.ForeignKeyConstraint(
            ["artifact_id"],
            ["artifacts.id"],
            name=op.f("fk_source_uploads_artifact_id_artifacts"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["repository_id"],
            ["repositories.id"],
            name=op.f("fk_source_uploads_repository_id_repositories"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_source_uploads")),
        sa.UniqueConstraint(
            "artifact_id",
            name=op.f("uq_source_uploads_artifact_id"),
        ),
    )
    op.create_index(
        op.f("ix_source_uploads_repository_id"),
        "source_uploads",
        ["repository_id"],
        unique=False,
    )
    op.create_index(
        "ix_source_uploads_status_expires",
        "source_uploads",
        ["status", "expires_at"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        "ix_source_uploads_status_expires",
        table_name="source_uploads",
    )
    op.drop_index(
        op.f("ix_source_uploads_repository_id"),
        table_name="source_uploads",
    )
    op.drop_table("source_uploads")
    op.drop_table("encrypted_secrets")
    op.drop_constraint(
        op.f("ck_artifacts_kind_values"),
        "artifacts",
        type_="check",
    )
    op.create_check_constraint(
        op.f("ck_artifacts_kind_values"),
        "artifacts",
        "kind IN ('source_snapshot', 'scan_result', 'build_log', "
        "'runtime_log', 'poc', 'report', 'other')",
    )
    op.create_unique_constraint(
        op.f("uq_artifacts_storage_key"),
        "artifacts",
        ["storage_key"],
    )
    op.alter_column(
        "artifacts",
        "audit_run_id",
        existing_type=sa.Uuid(),
        nullable=False,
    )
