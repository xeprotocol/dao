"""Inbox: third parties talk to the DAO directly, over XE chat or signed HTTP.

Every inbound message is verified (signature over the envelope id, PoW, key derives the account),
stored, logged, and acknowledged. Replies are written by a seat holder and sent from the DAO's own
account over chat, so the correspondent gets an answer on the channel they used.
"""

from __future__ import annotations

import asyncio
import logging
import secrets
from datetime import datetime, timezone

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from xe.chat import ChatError, Envelope, new_envelope, verify_envelope
from xe.chat_auth import chat_read_proof

from ..auth import Verified
from ..context import Context
from ..models import InboxMessage, OutboxMessage
from ..signer import SignerError
from . import pause

log = logging.getLogger("dao.inbox")

AUTO_ACK = ("Received by the XE DAO and recorded in the public log. A person reads every message; "
            "replies come from this account. Nothing in this message is a commitment.")


def dao_account(ctx: Context) -> str:
    if ctx.signer.has("dao"):
        return ctx.signer.address("dao")
    return ctx.config.accounts.get("dao", "")


async def store_envelope(ctx: Context, db: AsyncSession, env: Envelope, channel: str = "chat") -> InboxMessage | None:
    existing = (await db.execute(select(InboxMessage).where(InboxMessage.id == env.id))).scalar_one_or_none()
    if existing:
        return None
    verified = True
    try:
        verify_envelope(env, ctx.node.chat_pow_difficulty, check_freshness=False)
    except ChatError as e:
        verified = False
        log.info("unverified envelope %s: %s", env.id[:12], e)
    clean_message = (env.message or "").replace("\x00", "")
    m = InboxMessage(id=env.id, channel=channel, from_account=env.from_, to_account=env.to, pub_key=env.pub_key,
                     body=clean_message, timestamp=env.timestamp, signature=env.signature, pow_nonce=env.pow_nonce,
                     verified=verified, status="new")
    db.add(m)
    ev = await ctx.events.append(db, "inbox.received", f"account:{env.from_}", {
        "id": env.id, "channel": channel, "from": env.from_, "verified": verified, "body": clean_message[:4000],
        "timestamp": env.timestamp,
    }, ref=f"inbox:{env.id}")
    if verified and channel == "chat" and not await pause.is_paused(db):
        await queue_reply(ctx, db, m, f"{AUTO_ACK} Log index {ev.index}.", from_seat="harness", kind="ack")
    return m


async def http_submit(ctx: Context, db: AsyncSession, v: Verified) -> InboxMessage:
    body = (v.payload.get("message") or "").strip()
    if not body or len(body) > 8000:
        raise HTTPException(400, "message is required (max 8000 chars)")
    if "\x00" in body:
        raise HTTPException(400, "message contains disallowed NUL byte")
    if any(ord(c) < 0x20 and c not in "\t\r\n" for c in body):
        raise HTTPException(400, "message contains disallowed control characters")
    mid = secrets.token_hex(16)
    m = InboxMessage(id=mid, channel="http", from_account=v.account, to_account=dao_account(ctx), pub_key=v.pub_key,
                     body=body, timestamp=v.timestamp, signature=v.signature, pow_nonce=0, verified=True, status="new")
    db.add(m)
    await ctx.events.append(db, "inbox.received", v.actor, {
        "id": mid, "channel": "http", "from": v.account, "verified": True, "body": body[:4000], "timestamp": v.timestamp,
    }, ref=f"inbox:{mid}")
    return m


async def queue_reply(ctx: Context, db: AsyncSession, m: InboxMessage, text: str, from_seat: str, kind: str = "reply") -> OutboxMessage:
    o = OutboxMessage(id=secrets.token_hex(8), in_reply_to=m.id, from_seat=from_seat, to_account=m.from_account,
                      body=text, envelope={}, status="queued")
    db.add(o)
    if kind == "reply":
        m.status = "answered"
        m.reply_id = o.id
    await ctx.events.append(db, "outbox.queued", from_seat if from_seat == "harness" else f"seat:{from_seat}", {
        "id": o.id, "in_reply_to": m.id, "to": m.from_account, "kind": kind, "body": text[:4000],
    }, ref=f"inbox:{m.id}")
    return o


async def reply(ctx: Context, db: AsyncSession, m: InboxMessage, v: Verified) -> OutboxMessage:
    text = (v.payload.get("text") or "").strip()
    if not text or len(text.encode()) > 8000:
        raise HTTPException(400, "text is required (max 8000 bytes)")
    return await queue_reply(ctx, db, m, text, from_seat=v.seat.id)


async def set_status(ctx: Context, db: AsyncSession, m: InboxMessage, v: Verified) -> InboxMessage:
    status = v.payload.get("status")
    if status not in ("new", "read", "answered", "closed", "spam"):
        raise HTTPException(400, "bad status")
    m.status = status
    m.classification = v.payload.get("classification", m.classification) or m.classification
    await ctx.events.append(db, "inbox.status", v.actor, {"id": m.id, "status": status, "classification": m.classification},
                            ref=f"inbox:{m.id}", public=status != "spam")
    return m


async def flush_outbox(ctx: Context, db: AsyncSession) -> int:
    """Worker: send queued replies from the DAO account over chat. PoW off the loop."""
    if not ctx.signer.has("dao") or await pause.is_paused(db):
        return 0
    rows = list((await db.execute(select(OutboxMessage).where(OutboxMessage.status == "queued").limit(10))).scalars().all())
    n = 0
    for o in rows:
        try:
            kp = ctx.signer.keypair("dao", "chat.send")
            env = await asyncio.to_thread(new_envelope, kp, o.to_account, o.body, ctx.node.chat_pow_difficulty)
            await ctx.chain.chat_send(env.to_json())
            o.envelope = env.to_json()
            o.status = "sent"
            o.sent_at = datetime.now(timezone.utc)
            await ctx.events.append(db, "outbox.sent", "harness", {"id": o.id, "envelope_id": env.id, "to": o.to_account},
                                    ref=f"inbox:{o.in_reply_to}")
            n += 1
        except (SignerError, ChatError, Exception) as e:
            o.error = str(e)[:500]
            log.warning("outbox send failed %s: %s", o.id, e)
    return n


async def read_proof(ctx: Context) -> dict[str, str]:
    ch = await ctx.chain.chat_challenge()
    kp = ctx.signer.keypair("dao", "chat.read_proof")
    return chat_read_proof(kp, ch["challenge"])


async def backfill(ctx: Context, db: AsyncSession, since_ns: int) -> int:
    """Pull messages since a timestamp (used at start and after stream drops)."""
    if not ctx.signer.has("dao"):
        return 0
    proof = await read_proof(ctx)
    msgs = await ctx.chain.chat_messages(proof, since_ns)
    me = dao_account(ctx)
    n = 0
    for d in msgs or []:
        env = Envelope.from_json(d)
        if env.to != me:
            continue
        if await store_envelope(ctx, db, env):
            n += 1
    return n


async def list_messages(db: AsyncSession, status: str | None = None, limit: int = 100) -> list[InboxMessage]:
    q = select(InboxMessage).order_by(InboxMessage.timestamp.desc()).limit(limit)
    if status:
        q = q.where(InboxMessage.status == status)
    return list((await db.execute(q)).scalars().all())


async def get(db: AsyncSession, mid: str) -> InboxMessage:
    m = (await db.execute(select(InboxMessage).where(InboxMessage.id == mid))).scalar_one_or_none()
    if m is None:
        raise HTTPException(404, "message not found")
    return m


async def replies_for(db: AsyncSession, mid: str) -> list[OutboxMessage]:
    return list((await db.execute(select(OutboxMessage).where(OutboxMessage.in_reply_to == mid).order_by(OutboxMessage.created_at.asc()))).scalars().all())


def to_dict(m: InboxMessage, replies: list[OutboxMessage] | None = None) -> dict:
    d = {"id": m.id, "channel": m.channel, "from": m.from_account if not m.redact_sender else "redacted", "body": m.body,
         "timestamp": m.timestamp, "verified": m.verified, "status": m.status, "classification": m.classification}
    if replies is not None:
        d["replies"] = [{"id": o.id, "from_seat": o.from_seat, "body": o.body, "status": o.status,
                         "sent_at": o.sent_at.isoformat() if o.sent_at else None, "error": o.error} for o in replies]
    return d
