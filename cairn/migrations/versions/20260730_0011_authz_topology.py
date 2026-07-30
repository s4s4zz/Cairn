"""Record authorization-topology coverage on audit runs (图二).

Revision ID: 20260730_0011
Revises: 20260729_0010
Create Date: 2026-07-30
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "20260730_0011"
down_revision: str | None = "20260729_0010"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "audit_coverage",
        sa.Column(
            "entrypoints_auth_covered",
            sa.Integer(),
            nullable=False,
            server_default="0",
        ),
    )
    op.add_column(
        "audit_coverage",
        sa.Column(
            "entrypoints_auth_unprotected",
            sa.Integer(),
            nullable=False,
            server_default="0",
        ),
    )


def downgrade() -> None:
    op.drop_column("audit_coverage", "entrypoints_auth_unprotected")
    op.drop_column("audit_coverage", "entrypoints_auth_covered")
