"""Add binary uploads and classify immutable audit snapshots.

Revision ID: 20260729_0008
Revises: 20260728_0007
Create Date: 2026-07-29
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "20260729_0008"
down_revision: str | None = "20260728_0007"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("repositories") as batch_op:
        batch_op.drop_constraint(
            op.f("ck_repositories_source_type_values"),
            type_="check",
        )
        batch_op.create_check_constraint(
            op.f("ck_repositories_source_type_values"),
            "source_type IN ('git', 'zip', 'local_upload', 'binary_upload')",
        )

    with op.batch_alter_table("source_uploads") as batch_op:
        batch_op.drop_constraint(
            op.f("ck_source_uploads_source_type_values"),
            type_="check",
        )
        batch_op.create_check_constraint(
            op.f("ck_source_uploads_source_type_values"),
            "source_type IN ('zip', 'local_upload', 'binary_upload')",
        )

    with op.batch_alter_table("source_snapshots") as batch_op:
        batch_op.add_column(
            sa.Column(
                "jvm_artifact_count",
                sa.Integer(),
                nullable=False,
                server_default=sa.text("0"),
            )
        )
        batch_op.add_column(
            sa.Column(
                "input_kind",
                sa.String(length=16),
                nullable=False,
                server_default="source",
            )
        )
        batch_op.create_check_constraint(
            op.f("ck_source_snapshots_input_kind_values"),
            "input_kind IN ('source', 'bytecode', 'hybrid')",
        )
        batch_op.create_check_constraint(
            op.f("ck_source_snapshots_jvm_artifact_count_nonnegative"),
            "jvm_artifact_count >= 0",
        )


def downgrade() -> None:
    with op.batch_alter_table("source_uploads") as batch_op:
        batch_op.drop_constraint(
            op.f("ck_source_uploads_source_type_values"),
            type_="check",
        )
        batch_op.create_check_constraint(
            op.f("ck_source_uploads_source_type_values"),
            "source_type IN ('zip', 'local_upload')",
        )

    with op.batch_alter_table("repositories") as batch_op:
        batch_op.drop_constraint(
            op.f("ck_repositories_source_type_values"),
            type_="check",
        )
        batch_op.create_check_constraint(
            op.f("ck_repositories_source_type_values"),
            "source_type IN ('git', 'zip', 'local_upload')",
        )

    with op.batch_alter_table("source_snapshots") as batch_op:
        batch_op.drop_constraint(
            op.f("ck_source_snapshots_jvm_artifact_count_nonnegative"),
            type_="check",
        )
        batch_op.drop_constraint(
            op.f("ck_source_snapshots_input_kind_values"),
            type_="check",
        )
        batch_op.drop_column("input_kind")
        batch_op.drop_column("jvm_artifact_count")
