"""Add the dynamic verification budget to AuditPolicy.

Revision ID: 20260727_0006
Revises: 20260727_0005
Create Date: 2026-07-27
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "20260727_0006"
down_revision: str | None = "20260727_0005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Added nullable, backfilled, then made NOT NULL, as for the two budgets
    # before it: an empty object means "use the defaults in DynamicBudget",
    # which is what a policy written before this column intended.
    op.add_column(
        "audit_policies",
        sa.Column("dynamic_budget", sa.JSON(), nullable=True),
    )
    op.execute(
        "UPDATE audit_policies SET dynamic_budget = '{}' "
        "WHERE dynamic_budget IS NULL"
    )
    op.alter_column(
        "audit_policies",
        "dynamic_budget",
        existing_type=sa.JSON(),
        nullable=False,
    )


def downgrade() -> None:
    op.drop_column("audit_policies", "dynamic_budget")
