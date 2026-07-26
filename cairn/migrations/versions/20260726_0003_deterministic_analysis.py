"""Add deterministic orchestration task and Artifact ownership keys.

Revision ID: 20260726_0003
Revises: 20260726_0002
Create Date: 2026-07-26
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "20260726_0003"
down_revision: str | None = "20260726_0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "audit_tasks",
        sa.Column("scope_key", sa.String(length=128), nullable=True),
    )
    op.add_column(
        "audit_tasks",
        sa.Column("sandbox_id", sa.Uuid(), nullable=True),
    )
    op.execute(
        "UPDATE audit_tasks "
        "SET scope_key = 'legacy:' || CAST(id AS VARCHAR) "
        "WHERE scope_key IS NULL"
    )
    op.alter_column(
        "audit_tasks",
        "scope_key",
        existing_type=sa.String(length=128),
        nullable=False,
    )
    op.create_unique_constraint(
        op.f("uq_audit_tasks_sandbox_id"),
        "audit_tasks",
        ["sandbox_id"],
    )
    op.create_unique_constraint(
        "uq_audit_tasks_run_scope_key",
        "audit_tasks",
        ["audit_run_id", "scope_key"],
    )
    op.create_unique_constraint(
        "uq_artifacts_task_sha_kind",
        "artifacts",
        ["produced_by_task_id", "sha256", "kind"],
    )


def downgrade() -> None:
    op.drop_constraint(
        "uq_artifacts_task_sha_kind",
        "artifacts",
        type_="unique",
    )
    op.drop_constraint(
        "uq_audit_tasks_run_scope_key",
        "audit_tasks",
        type_="unique",
    )
    op.drop_constraint(
        op.f("uq_audit_tasks_sandbox_id"),
        "audit_tasks",
        type_="unique",
    )
    op.drop_column("audit_tasks", "sandbox_id")
    op.drop_column("audit_tasks", "scope_key")
