"""initial schema

Revision ID: 0001
Revises:
Create Date: 2026-10-12
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql as pg

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("CREATE EXTENSION IF NOT EXISTS vector")

    op.create_table(
        "events",
        sa.Column("index", sa.BigInteger, primary_key=True, autoincrement=False),
        sa.Column("ts", sa.BigInteger, nullable=False),
        sa.Column("kind", sa.String(64), nullable=False),
        sa.Column("actor", sa.String(128), nullable=False),
        sa.Column("payload", pg.JSONB, nullable=False),
        sa.Column("prev_hash", sa.String(64), nullable=False),
        sa.Column("hash", sa.String(64), nullable=False, unique=True),
        sa.Column("signer", sa.String(64), nullable=False, server_default=""),
        sa.Column("signature", sa.String(128), nullable=False, server_default=""),
        sa.Column("public", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.Column("ref", sa.String(128), nullable=False, server_default=""),
    )
    op.create_index("ix_events_kind", "events", ["kind"])
    op.create_index("ix_events_ref", "events", ["ref"])
    op.create_index("ix_events_kind_index", "events", ["kind", "index"])

    op.create_table(
        "log_head",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("index", sa.BigInteger, nullable=False),
        sa.Column("hash", sa.String(64), nullable=False),
    )
    op.execute("INSERT INTO log_head (id, index, hash) VALUES (1, -1, repeat('0', 64))")

    op.create_table(
        "resolutions",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("number", sa.Integer, nullable=False, unique=True),
        sa.Column("title", sa.String(256), nullable=False),
        sa.Column("body", sa.Text, nullable=False),
        sa.Column("matter", sa.String(64), nullable=False),
        sa.Column("ops", pg.JSONB, nullable=True),
        sa.Column("proposed_by", sa.String(64), nullable=False),
        sa.Column("status", sa.String(32), nullable=False, server_default="open"),
        sa.Column("signatures", pg.JSONB, nullable=False, server_default="[]"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("related_proposal", sa.String(64), nullable=False, server_default=""),
        sa.Column("session_id", sa.String(64), nullable=False, server_default=""),
    )

    op.create_table(
        "pause_records",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("determined_by", sa.String(64), nullable=False),
        sa.Column("ground", sa.String(64), nullable=False),
        sa.Column("determination", sa.Text, nullable=False),
        sa.Column("started_at", sa.BigInteger, nullable=False),
        sa.Column("expires_at", sa.BigInteger, nullable=False),
        sa.Column("indefinite", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("extensions", pg.JSONB, nullable=False, server_default="[]"),
        sa.Column("lifted_at", sa.BigInteger, nullable=True),
        sa.Column("lifted_by", pg.JSONB, nullable=False, server_default="[]"),
        sa.Column("post_text", sa.Text, nullable=False, server_default=""),
        sa.Column("posted_at", sa.BigInteger, nullable=True),
        sa.Column("status", sa.String(16), nullable=False, server_default="active"),
    )

    op.create_table(
        "signing_sessions",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("kind", sa.String(32), nullable=False),
        sa.Column("title", sa.String(256), nullable=False),
        sa.Column("ops", pg.JSONB, nullable=False),
        sa.Column("ops_digest", sa.String(64), nullable=False),
        sa.Column("status", sa.String(32), nullable=False, server_default="approving"),
        sa.Column("approvals", pg.JSONB, nullable=False, server_default="[]"),
        sa.Column("required_approvals", sa.Integer, nullable=False, server_default="2"),
        sa.Column("block", pg.JSONB, nullable=True),
        sa.Column("block_hash", sa.String(64), nullable=False, server_default=""),
        sa.Column("block_signatures", pg.JSONB, nullable=False, server_default="[]"),
        sa.Column("rebuilds", sa.Integer, nullable=False, server_default="0"),
        sa.Column("submitted_index", sa.BigInteger, nullable=True),
        sa.Column("submitted_hash", sa.String(64), nullable=False, server_default=""),
        sa.Column("error", sa.Text, nullable=False, server_default=""),
        sa.Column("resolution_id", sa.String(64), nullable=False, server_default=""),
        sa.Column("not_before", sa.BigInteger, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    op.create_table(
        "proposals",
        sa.Column("hash", sa.String(64), primary_key=True),
        sa.Column("title", sa.String(256), nullable=False),
        sa.Column("body", sa.Text, nullable=False),
        sa.Column("ops", pg.JSONB, nullable=True),
        sa.Column("author_account", sa.String(64), nullable=False),
        sa.Column("author_pub_key", sa.String(64), nullable=False),
        sa.Column("author_signature", sa.String(128), nullable=False),
        sa.Column("author_timestamp", sa.BigInteger, nullable=False),
        sa.Column("fee_block_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("status", sa.String(16), nullable=False, server_default="open"),
        sa.Column("opened_at", sa.BigInteger, nullable=False),
        sa.Column("closes_at", sa.BigInteger, nullable=False),
        sa.Column("rules", pg.JSONB, nullable=False),
        sa.Column("result", pg.JSONB, nullable=True),
        sa.Column("decision", pg.JSONB, nullable=True),
        sa.Column("analysis", pg.JSONB, nullable=False, server_default="[]"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_proposals_author", "proposals", ["author_account"])
    op.create_index("ix_proposals_status", "proposals", ["status"])
    op.create_index("ix_proposals_closes_at", "proposals", ["closes_at"])

    op.create_table(
        "votes",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("proposal_hash", sa.String(64), sa.ForeignKey("proposals.hash"), nullable=False),
        sa.Column("account", sa.String(64), nullable=False),
        sa.Column("pub_key", sa.String(64), nullable=False),
        sa.Column("choice", sa.String(8), nullable=False),
        sa.Column("reason", sa.Text, nullable=False, server_default=""),
        sa.Column("timestamp", sa.BigInteger, nullable=False),
        sa.Column("signature", sa.String(128), nullable=False),
        sa.Column("weight", sa.BigInteger, nullable=False, server_default="0"),
        sa.Column("participating", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("is_agent", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("eligibility", pg.JSONB, nullable=False, server_default="{}"),
        sa.Column("received_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("proposal_hash", "account", name="uq_vote_proposal_account"),
    )
    op.create_index("ix_votes_proposal", "votes", ["proposal_hash"])

    op.create_table(
        "fee_ledger",
        sa.Column("fee_block_hash", sa.String(64), primary_key=True),
        sa.Column("proposal_hash", sa.String(64), nullable=False),
        sa.Column("payer", sa.String(64), nullable=False),
        sa.Column("amount", sa.BigInteger, nullable=False),
        sa.Column("state", sa.String(16), nullable=False, server_default="seen"),
        sa.Column("tx_hashes", pg.JSONB, nullable=False, server_default="{}"),
        sa.Column("error", sa.Text, nullable=False, server_default=""),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_fee_ledger_proposal", "fee_ledger", ["proposal_hash"])

    op.create_table(
        "inbox_messages",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("channel", sa.String(8), nullable=False),
        sa.Column("from_account", sa.String(64), nullable=False),
        sa.Column("to_account", sa.String(64), nullable=False),
        sa.Column("pub_key", sa.String(64), nullable=False, server_default=""),
        sa.Column("body", sa.Text, nullable=False),
        sa.Column("timestamp", sa.BigInteger, nullable=False),
        sa.Column("signature", sa.String(128), nullable=False, server_default=""),
        sa.Column("pow_nonce", sa.BigInteger, nullable=False, server_default="0"),
        sa.Column("verified", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("status", sa.String(16), nullable=False, server_default="new"),
        sa.Column("classification", sa.String(32), nullable=False, server_default=""),
        sa.Column("reply_id", sa.String(64), nullable=False, server_default=""),
        sa.Column("redact_sender", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("received_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_inbox_from", "inbox_messages", ["from_account"])

    op.create_table(
        "outbox_messages",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("in_reply_to", sa.String(64), nullable=False, server_default=""),
        sa.Column("from_seat", sa.String(64), nullable=False),
        sa.Column("to_account", sa.String(64), nullable=False),
        sa.Column("body", sa.Text, nullable=False),
        sa.Column("envelope", pg.JSONB, nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="queued"),
        sa.Column("error", sa.Text, nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("sent_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_outbox_reply", "outbox_messages", ["in_reply_to"])

    op.create_table(
        "anchors",
        sa.Column("n", sa.Integer, primary_key=True, autoincrement=False),
        sa.Column("event_index", sa.BigInteger, nullable=False),
        sa.Column("head_hash", sa.String(64), nullable=False),
        sa.Column("session_id", sa.String(64), nullable=False),
        sa.Column("statechain_index", sa.BigInteger, nullable=True),
        sa.Column("statechain_hash", sa.String(64), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    op.create_table(
        "health_checks",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("ts", sa.BigInteger, nullable=False),
        sa.Column("ok", sa.Boolean, nullable=False),
        sa.Column("detail", pg.JSONB, nullable=False),
    )
    op.create_index("ix_health_ts", "health_checks", ["ts"])

    op.create_table(
        "treasury_snapshots",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("ts", sa.BigInteger, nullable=False),
        sa.Column("balances", pg.JSONB, nullable=False),
    )
    op.create_index("ix_treasury_ts", "treasury_snapshots", ["ts"])

    op.create_table(
        "schedule_runs",
        sa.Column("job", sa.String(64), primary_key=True),
        sa.Column("last_run_ts", sa.BigInteger, nullable=False),
        sa.Column("detail", pg.JSONB, nullable=False, server_default="{}"),
    )


def downgrade() -> None:
    # Everything goes with these tables, the signed event log first among it, and no upgrade brings a row
    # back. An empty schema may be taken down; one that holds a record may not (XE-4169).
    if op.get_bind().execute(sa.text("SELECT 1 FROM events LIMIT 1")).first() is not None:
        raise RuntimeError("refusing to downgrade past 0001: that drops the event log and every record with it, and "
                           "nothing restores them. To start again, drop the database.")
    for t in ("schedule_runs", "treasury_snapshots", "health_checks", "anchors", "outbox_messages",
              "inbox_messages", "fee_ledger", "votes", "proposals", "signing_sessions", "pause_records",
              "resolutions", "log_head", "events"):
        op.drop_table(t)
