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
    # The wider column holds nonces the narrower one cannot. Postgres would refuse the cast with an
    # overflow of its own; say which rows and why first (XE-4169).
    wide = op.get_bind().execute(sa.text("SELECT 1 FROM inbox_messages WHERE pow_nonce > 9223372036854775807 LIMIT 1")).first()
    if wide is not None:
        raise RuntimeError("refusing to downgrade past 0003: inbox_messages holds a proof-of-work nonce of 2^63 or "
                           "more, which a BIGINT column cannot keep.")
    op.alter_column("inbox_messages", "pow_nonce", type_=sa.BigInteger, existing_type=sa.Numeric(20, 0),
                    existing_nullable=False, existing_server_default="0")
