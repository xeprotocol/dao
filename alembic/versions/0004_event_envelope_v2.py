"""events.v: which hash envelope a row was written under. Existing rows are v1 (public and ref outside the
hash); rows from now on are v2 (XE-0494).

Revision ID: 0004
Revises: 0003
Create Date: 2026-11-05
"""
from alembic import op
import sqlalchemy as sa

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("events", sa.Column("v", sa.SmallInteger(), nullable=False, server_default="1"))


def downgrade() -> None:
    op.drop_column("events", "v")
