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
    # Dropping `v` forgets which envelope each row was hashed under, and the upgrade above brings every row
    # back as v1, under which a v2 row's stored hash no longer verifies. So there is no going back past this
    # revision once a v2 row exists: a downgrade does not discard what the upgrade cannot restore (XE-4169).
    if op.get_bind().execute(sa.text("SELECT 1 FROM events WHERE v >= 2 LIMIT 1")).first() is not None:
        raise RuntimeError("refusing to downgrade past 0004: the log holds v2 events, and without events.v "
                           "they cannot be verified. Restore from a backup taken before 0004 instead.")
    op.drop_column("events", "v")
