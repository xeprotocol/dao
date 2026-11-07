"""One active pause: the singleton every pause consumer assumes is enforced by the database, so two members
pausing in the same instant are serialised by the index rather than by a read each can pass (XE-1176).

Revision ID: 0005
Revises: 0004
Create Date: 2026-11-08
"""
from alembic import op
import sqlalchemy as sa

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Any second active row left by the race is expired first, keeping the newest.
    op.execute(sa.text(
        "UPDATE pause_records SET status = 'expired' WHERE status = 'active' AND id <> "
        "(SELECT id FROM pause_records WHERE status = 'active' ORDER BY started_at DESC LIMIT 1)"))
    op.create_index("ux_pause_one_active", "pause_records", ["status"], unique=True,
                    postgresql_where=sa.text("status = 'active'"))


def downgrade() -> None:
    op.drop_index("ux_pause_one_active", table_name="pause_records")
