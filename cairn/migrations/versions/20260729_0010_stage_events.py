"""Record when an audit run entered each stage.

Revision ID: 20260729_0010
Revises: 20260729_0009
Create Date: 2026-07-29
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "20260729_0010"
down_revision: str | None = "20260729_0009"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


_STAGES = (
    "ingesting",
    "preprocessing",
    "building",
    "static_scanning",
    "semantic_auditing",
    "dynamic_verifying",
    "machine_review",
    "human_review",
    "coverage_check",
    "reporting",
)


def upgrade() -> None:
    op.create_table(
        "audit_run_stage_events",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("audit_run_id", sa.Uuid(), nullable=False),
        sa.Column("stage", sa.String(length=32), nullable=False),
        sa.Column("entered_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["audit_run_id"],
            ["audit_runs.id"],
            name=op.f("fk_audit_run_stage_events_audit_run_id_audit_runs"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_audit_run_stage_events")),
        sa.UniqueConstraint(
            "audit_run_id",
            "stage",
            "entered_at",
            name="uq_audit_run_stage_events_entry",
        ),
        sa.CheckConstraint(
            "stage IN (%s)" % ", ".join(f"'{stage}'" for stage in _STAGES),
            name=op.f("ck_audit_run_stage_events_stage_values"),
        ),
    )
    op.create_index(
        "ix_audit_run_stage_events_run",
        "audit_run_stage_events",
        ["audit_run_id", "entered_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_audit_run_stage_events_run", table_name="audit_run_stage_events")
    op.drop_table("audit_run_stage_events")
