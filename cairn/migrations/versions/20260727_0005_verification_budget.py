"""Add the independent machine-review budget to AuditPolicy.

Revision ID: 20260727_0005
Revises: 20260727_0004
Create Date: 2026-07-27
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "20260727_0005"
down_revision: str | None = "20260727_0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Added nullable, backfilled, then made NOT NULL, for the same reason as
    # `semantic_budget` in 0004: existing policy rows predate the stage, and an
    # empty object means "use the defaults in VerificationBudget", which is what
    # a policy written before this column intended.
    op.add_column(
        "audit_policies",
        sa.Column("verification_budget", sa.JSON(), nullable=True),
    )
    op.execute(
        "UPDATE audit_policies SET verification_budget = '{}' "
        "WHERE verification_budget IS NULL"
    )
    op.alter_column(
        "audit_policies",
        "verification_budget",
        existing_type=sa.JSON(),
        nullable=False,
    )


def downgrade() -> None:
    op.drop_column("audit_policies", "verification_budget")
