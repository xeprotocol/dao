"""The schema the migrations build is the one the models declare.

0001 created nine `server_default now()` timestamp columns without NOT NULL, where the models type each as
a datetime that is always there; a database built by the migrations took a NULL the code never expects
(XE-10697). Nothing in the service writes one, so the backfill below is expected to touch no rows.

The inbox, the outbox and the signing sessions are read by status and by time on every worker pass and
every inbox page, and had no index on either (XE-8172).

Revision ID: 0007
Revises: 0006
Create Date: 2026-11-15
"""
from alembic import op
import sqlalchemy as sa

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None

# table and column names are literals of this file, never input
TIMESTAMPS = (
    ("resolutions", "created_at"),
    ("signing_sessions", "created_at"),
    ("signing_sessions", "updated_at"),
    ("proposals", "created_at"),
    ("votes", "received_at"),
    ("fee_ledger", "updated_at"),
    ("inbox_messages", "received_at"),
    ("outbox_messages", "created_at"),
    ("anchors", "created_at"),
)
INDEXES = (
    ("ix_inbox_timestamp", "inbox_messages", ("timestamp", "id")),
    ("ix_outbox_status", "outbox_messages", ("status", "created_at")),
    ("ix_sessions_status", "signing_sessions", ("status", "created_at")),
)


def upgrade() -> None:
    for table, column in TIMESTAMPS:
        op.execute(sa.text(f"UPDATE {table} SET {column} = now() WHERE {column} IS NULL"))
        op.alter_column(table, column, existing_type=sa.DateTime(timezone=True), nullable=False,
                        existing_server_default=sa.func.now())
    for name, table, columns in INDEXES:
        op.create_index(name, table, list(columns))


def downgrade() -> None:
    for name, table, _ in reversed(INDEXES):
        op.drop_index(name, table_name=table)
    for table, column in reversed(TIMESTAMPS):
        op.alter_column(table, column, existing_type=sa.DateTime(timezone=True), nullable=True,
                        existing_server_default=sa.func.now())
