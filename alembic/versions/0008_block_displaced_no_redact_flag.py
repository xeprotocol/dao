"""An ended signing session is watched until the chain settles it, and the row says when the chain has:
`block_displaced` is set once another block holds the index the session's block was built for, which is the
one thing short of landing that ends the watch (XE-14215). Every ended session already in the table starts
unmarked, so the first passes after this release look each of them up once, the ones that ended more than
seven days ago included, and record any whose block landed after the old watch had stopped looking.

`inbox_messages.redact_sender` goes. No code ever set it and the public log never read it; the brief and
the community seat's prompt no longer offer the redaction it stood for (XE-3894). The inbox list did read
it, so a row someone set by hand is shown without its sender until this runs and with it after: the
upgrade refuses while there is such a row, and whoever set it decides what becomes of the message.

Revision ID: 0008
Revises: 0007
Create Date: 2026-11-15
"""
from alembic import op
import sqlalchemy as sa

revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None


def upgrade() -> None:
    if op.get_bind().execute(sa.text("SELECT 1 FROM inbox_messages WHERE redact_sender LIMIT 1")).first():
        raise RuntimeError(
            "an inbox message has redact_sender set, which no code does: it was set by hand, and the inbox list "
            "hides that sender until this migration drops the flag. Decide what becomes of the message, clear "
            "the flag (UPDATE inbox_messages SET redact_sender = false), and run the upgrade again")
    op.add_column("signing_sessions",
                  sa.Column("block_displaced", sa.Boolean(), nullable=False, server_default=sa.text("false")))
    op.drop_column("inbox_messages", "redact_sender")


def downgrade() -> None:
    op.add_column("inbox_messages",
                  sa.Column("redact_sender", sa.Boolean(), nullable=False, server_default=sa.text("false")))
    op.drop_column("signing_sessions", "block_displaced")
