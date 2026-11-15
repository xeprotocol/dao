"""seen_signatures: durable replay protection for signed requests (XE-0033)

Revision ID: 0002
Revises: 0001
Create Date: 2026-10-18
"""
import time

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


REPLAY_WINDOW_NS = 10 * 60 * 1_000_000_000   # dao.auth.MAX_SKEW_NS: how long after its timestamp a request is taken


def downgrade() -> None:
    # A claim is what stops its request being taken a second time while its timestamp is still fresh. The
    # upgrade recreates the table empty, so the table is not dropped while it holds such a claim (XE-4169):
    # stop the service, wait out the window, then downgrade.
    live = op.get_bind().execute(sa.text("SELECT 1 FROM seen_signatures WHERE timestamp > :cutoff LIMIT 1"),
                                 {"cutoff": time.time_ns() - REPLAY_WINDOW_NS}).first()
    if live is not None:
        raise RuntimeError("refusing to downgrade past 0002: seen_signatures holds claims on requests that could "
                           "still be replayed. Stop the service and retry once the newest claim is ten minutes old "
                           "(twenty minutes at most: a request may be dated ten minutes ahead).")
    op.drop_index("ix_seen_signatures_timestamp", table_name="seen_signatures")
    op.drop_table("seen_signatures")
