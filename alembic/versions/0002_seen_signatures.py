"""seen_signatures: durable replay protection for signed requests (XE-0033)

Revision ID: 0002
Revises: 0001
Create Date: 2026-10-18
"""
from alembic import op
import sqlalchemy as sa

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "seen_signatures",
        sa.Column("sig", sa.String(128), primary_key=True),
        sa.Column("timestamp", sa.BigInteger, nullable=False),
        sa.Column("account", sa.String(64), nullable=False, server_default=""),
    )
    op.create_index("ix_seen_signatures_timestamp", "seen_signatures", ["timestamp"])


def downgrade() -> None:
    op.drop_index("ix_seen_signatures_timestamp", table_name="seen_signatures")
    op.drop_table("seen_signatures")
