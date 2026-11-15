"""Inbox messages carry whether their text is on the public log, instead of the status standing in for it:
a status returns to `new` when a reply is given up, and a published message is not unpublished by that
(XE-4593). Existing rows take the flag from the log itself: an `inbox.published` entry names each one, and
so does a public `inbox.received` entry from before 2026-10-30, when every HTTP message's text went onto
the public log on arrival.

The register row of an anchor is now filled when its session is recorded submitted, not by a later worker
pass (XE-6256). Rows whose session was submitted before this release and that the old pass had not reached
are filled here, from the session.

Revision ID: 0006
Revises: 0005
Create Date: 2026-11-15
"""
from alembic import op
import sqlalchemy as sa

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("inbox_messages", sa.Column("published", sa.Boolean(), nullable=False, server_default=sa.text("false")))
    op.execute(sa.text(
        "UPDATE inbox_messages m SET published = true WHERE m.channel = 'http' AND EXISTS "
        "(SELECT 1 FROM events e WHERE e.ref = 'inbox:' || m.id AND "
        "(e.kind = 'inbox.published' OR (e.kind = 'inbox.received' AND e.public)))"))
    op.execute(sa.text(
        "UPDATE anchors a SET statechain_index = s.submitted_index, statechain_hash = s.submitted_hash "
        "FROM signing_sessions s WHERE s.id = a.session_id AND s.status = 'submitted' "
        "AND s.submitted_index IS NOT NULL AND a.statechain_index IS NULL"))


def downgrade() -> None:
    op.drop_column("inbox_messages", "published")
