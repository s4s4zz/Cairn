"""Add the semantic-audit budget to AuditPolicy.

Revision ID: 20260727_0004
Revises: 20260726_0003
Create Date: 2026-07-27
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "20260727_0004"
down_revision: str | None = "20260726_0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Added nullable, backfilled, then made NOT NULL: existing policy rows
    # predate the semantic stage and an empty object means "use the defaults in
    # SemanticBudget", which is what a policy written before this column
    # intended.
    op.add_column(
        "audit_policies",
        sa.Column("semantic_budget", sa.JSON(), nullable=True),
    )
    op.execute(
        "UPDATE audit_policies SET semantic_budget = '{}' "
        "WHERE semantic_budget IS NULL"
    )
    op.alter_column(
        "audit_policies",
        "semantic_budget",
        existing_type=sa.JSON(),
        nullable=False,
    )


def downgrade() -> None:
    op.drop_column("audit_policies", "semantic_budget")
