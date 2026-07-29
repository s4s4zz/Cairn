"""Persist source-independent CodeLocationV2 evidence.

Revision ID: 20260729_0009
Revises: 20260729_0008
Create Date: 2026-07-29
"""

from collections.abc import Sequence

from alembic import context, op
import sqlalchemy as sa


revision: str = "20260729_0009"
down_revision: str | None = "20260729_0008"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("finding_locations") as batch_op:
        batch_op.drop_constraint(
            op.f("ck_finding_locations_start_line_positive"),
            type_="check",
        )
        batch_op.drop_constraint(
            op.f("ck_finding_locations_line_range_valid"),
            type_="check",
        )
        batch_op.add_column(
            sa.Column(
                "origin_kind",
                sa.String(length=16),
                nullable=False,
                server_default="source",
            )
        )
        batch_op.add_column(sa.Column("container_path", sa.Text(), nullable=True))
        batch_op.add_column(sa.Column("entry_path", sa.Text(), nullable=True))
        batch_op.add_column(sa.Column("class_name", sa.Text(), nullable=True))
        batch_op.add_column(sa.Column("method_name", sa.Text(), nullable=True))
        batch_op.add_column(sa.Column("method_descriptor", sa.Text(), nullable=True))
        batch_op.add_column(sa.Column("bytecode_offset", sa.Integer(), nullable=True))
        batch_op.add_column(
            sa.Column("decompiled_artifact_id", sa.Uuid(), nullable=True)
        )
        batch_op.add_column(
            sa.Column("decompiled_start_line", sa.Integer(), nullable=True)
        )
        batch_op.add_column(
            sa.Column("decompiled_end_line", sa.Integer(), nullable=True)
        )
        batch_op.alter_column(
            "file_path",
            existing_type=sa.Text(),
            nullable=True,
        )
        batch_op.alter_column(
            "start_line",
            existing_type=sa.Integer(),
            nullable=True,
        )
        batch_op.alter_column(
            "end_line",
            existing_type=sa.Integer(),
            nullable=True,
        )
        batch_op.alter_column(
            "code_snippet",
            existing_type=sa.Text(),
            nullable=True,
        )
        batch_op.create_foreign_key(
            op.f("fk_finding_locations_decompiled_artifact_id_artifacts"),
            "artifacts",
            ["decompiled_artifact_id"],
            ["id"],
            ondelete="RESTRICT",
        )
        batch_op.create_check_constraint(
            op.f("ck_finding_locations_origin_kind_values"),
            "origin_kind IN ('source', 'bytecode', 'config', 'decompiled')",
        )
        batch_op.create_check_constraint(
            op.f("ck_finding_locations_source_line_range_valid"),
            "(start_line IS NULL AND end_line IS NULL) OR "
            "(start_line > 0 AND end_line >= start_line)",
        )
        batch_op.create_check_constraint(
            op.f("ck_finding_locations_decompiled_line_range_valid"),
            "(decompiled_start_line IS NULL AND decompiled_end_line IS NULL) OR "
            "(decompiled_start_line > 0 AND "
            "decompiled_end_line >= decompiled_start_line)",
        )
        batch_op.create_check_constraint(
            op.f("ck_finding_locations_bytecode_offset_nonnegative"),
            "bytecode_offset IS NULL OR bytecode_offset >= 0",
        )
        batch_op.create_check_constraint(
            op.f("ck_finding_locations_method_identity_complete"),
            "(method_name IS NULL AND method_descriptor IS NULL) OR "
            "(method_name IS NOT NULL AND method_descriptor IS NOT NULL)",
        )
        batch_op.create_check_constraint(
            op.f("ck_finding_locations_bytecode_offset_has_method"),
            "bytecode_offset IS NULL OR method_name IS NOT NULL",
        )
        batch_op.create_check_constraint(
            op.f("ck_finding_locations_bytecode_identity_complete"),
            "origin_kind NOT IN ('bytecode', 'decompiled') OR "
            "(entry_path IS NOT NULL AND class_name IS NOT NULL)",
        )
        batch_op.create_check_constraint(
            op.f("ck_finding_locations_source_evidence_complete"),
            "origin_kind != 'source' OR "
            "(file_path IS NOT NULL AND start_line IS NOT NULL "
            "AND code_snippet IS NOT NULL)",
        )
        batch_op.create_check_constraint(
            op.f("ck_finding_locations_config_path_present"),
            "origin_kind != 'config' OR "
            "(file_path IS NOT NULL OR entry_path IS NOT NULL)",
        )
        batch_op.create_check_constraint(
            op.f("ck_finding_locations_decompiled_artifact_present"),
            "origin_kind != 'decompiled' OR decompiled_artifact_id IS NOT NULL",
        )
        batch_op.create_check_constraint(
            op.f("ck_finding_locations_decompiled_lines_have_artifact"),
            "decompiled_start_line IS NULL OR decompiled_artifact_id IS NOT NULL",
        )


def downgrade() -> None:
    if not context.is_offline_mode():
        incompatible = op.get_bind().execute(
            sa.text(
                "SELECT EXISTS ("
                "SELECT 1 FROM finding_locations "
                "WHERE origin_kind != 'source' OR file_path IS NULL "
                "OR start_line IS NULL OR end_line IS NULL "
                "OR code_snippet IS NULL "
                "OR container_path IS NOT NULL OR entry_path IS NOT NULL "
                "OR class_name IS NOT NULL OR method_name IS NOT NULL "
                "OR method_descriptor IS NOT NULL OR bytecode_offset IS NOT NULL "
                "OR decompiled_artifact_id IS NOT NULL "
                "OR decompiled_start_line IS NOT NULL "
                "OR decompiled_end_line IS NOT NULL"
                ")"
            )
        ).scalar_one()
        if incompatible:
            raise RuntimeError(
                "cannot downgrade CodeLocationV2 while binary locations exist"
            )

    with op.batch_alter_table("finding_locations") as batch_op:
        for name in (
            "decompiled_lines_have_artifact",
            "decompiled_artifact_present",
            "config_path_present",
            "source_evidence_complete",
            "bytecode_identity_complete",
            "bytecode_offset_has_method",
            "method_identity_complete",
            "bytecode_offset_nonnegative",
            "decompiled_line_range_valid",
            "source_line_range_valid",
            "origin_kind_values",
        ):
            batch_op.drop_constraint(
                op.f(f"ck_finding_locations_{name}"),
                type_="check",
            )
        batch_op.drop_constraint(
            op.f("fk_finding_locations_decompiled_artifact_id_artifacts"),
            type_="foreignkey",
        )
        for column in (
            "decompiled_end_line",
            "decompiled_start_line",
            "decompiled_artifact_id",
            "bytecode_offset",
            "method_descriptor",
            "method_name",
            "class_name",
            "entry_path",
            "container_path",
            "origin_kind",
        ):
            batch_op.drop_column(column)
        batch_op.alter_column(
            "code_snippet",
            existing_type=sa.Text(),
            nullable=False,
        )
        batch_op.alter_column(
            "end_line",
            existing_type=sa.Integer(),
            nullable=False,
        )
        batch_op.alter_column(
            "start_line",
            existing_type=sa.Integer(),
            nullable=False,
        )
        batch_op.alter_column(
            "file_path",
            existing_type=sa.Text(),
            nullable=False,
        )
        batch_op.create_check_constraint(
            op.f("ck_finding_locations_start_line_positive"),
            "start_line > 0",
        )
        batch_op.create_check_constraint(
            op.f("ck_finding_locations_line_range_valid"),
            "end_line >= start_line",
        )
