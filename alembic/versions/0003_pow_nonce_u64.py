"""inbox_messages.pow_nonce: BIGINT -> NUMERIC(20,0), since PoW nonces are unsigned 64-bit

Revision ID: 0003
Revises: 0002
Create Date: 2026-10-30
"""
from alembic import op
import sqlalchemy as sa

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.alter_column("inbox_messages", "pow_nonce", type_=sa.Numeric(20, 0), existing_type=sa.BigInteger,
                    existing_nullable=False, existing_server_default="0")


def downgrade() -> None:
    op.alter_column("inbox_messages", "pow_nonce", type_=sa.BigInteger, existing_type=sa.Numeric(20, 0),
                    existing_nullable=False, existing_server_default="0")
