"""Inbox: third parties talk to the DAO directly, over XE chat or signed HTTP.

Every inbound message is verified (signature over the envelope id, PoW, key derives the account),
stored, logged, and acknowledged. One that fails the harness's own verification is still stored, so the
id is remembered and never fetched again, but it is never public: the node checks every envelope before
the harness sees it, so such a message means a node or a configuration the harness should not trust for
attribution, and the public record carries only what the harness itself verified (XE-1254). Replies are
written by a seat holder and sent from the DAO's own account over chat, so the correspondent gets an
answer on the channel they used.
"""

from __future__ import annotations

import asyncio
import logging
import secrets
import time
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException
from sqlalchemy import case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from xe.chat import ChatError, Envelope, new_envelope, verify_envelope
from xe.chat_auth import chat_read_proof
from xe.pow import WORKER_POW_DEADLINE_S

from ..auth import Verified, require_pow
from ..context import Context
from ..log import EventLog
from ..models import InboxMessage, OutboxMessage
from ..signer import SignerError
from ..text import clean_text, field_text, has_bad_control, scrub
from . import pause

log = logging.getLogger("dao.inbox")

OUTBOX_RETRY_DAYS = 7
AUTO_ACK = ("Received by the XE DAO and recorded in the public log. A person reads every message; "
            "replies come from this account. Nothing in this message is a commitment.")


def dao_account(ctx: Context) -> str:
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
    body, status = env.message, "new"
    if has_bad_control(body):
        # The signature covers the exact bytes, so we cannot clean a verified body and still call it verified.
        # Store a visibly scrubbed copy, marked unverified and spam, so the id is remembered and never re-fetched.
        body, verified, status = scrub(body), False, "spam"
        log.info("envelope %s carried control characters; stored scrubbed as spam", env.id[:12])
    m = InboxMessage(id=env.id, channel=channel, from_account=env.from_, to_account=env.to, pub_key=env.pub_key,
                     body=body, timestamp=env.timestamp, signature=env.signature, pow_nonce=env.pow_nonce,
                     verified=verified, status=status)
    db.add(m)
    ev = await ctx.events.append(db, "inbox.received", f"account:{env.from_}", {
        "id": env.id, "channel": channel, "from": env.from_, "verified": verified, "body": body[:4000],
        "timestamp": env.timestamp,
    }, ref=f"inbox:{env.id}", public=verified and status != "spam")
    if verified and channel == "chat" and not await pause.is_paused(db) and not await _acked_recently(db, env.from_):
        await queue_reply(ctx, db, m, f"{AUTO_ACK} Log index {ev.index}.", from_seat="harness", kind="ack")
    return m


ACK_EVERY_S = 3600


async def _acked_recently(db: AsyncSession, account: str) -> bool:
    """One acknowledgement per correspondent per hour. Every verified envelope is still stored and logged;
    only the courtesy reply is rationed, so a flood of cheap messages cannot fill the outbox with
    acknowledgements and hold members' replies behind them (XE-1845)."""
    since = datetime.now(timezone.utc) - timedelta(seconds=ACK_EVERY_S)
    q = select(func.count()).select_from(OutboxMessage).where(OutboxMessage.to_account == account,
                                                               OutboxMessage.from_seat == "harness",
                                                               OutboxMessage.created_at >= since)
    return int((await db.execute(q)).scalar_one()) > 0


async def http_submit(ctx: Context, db: AsyncSession, v: Verified) -> InboxMessage:
    """A signed message over HTTP. Costs the sender a chat-level proof of work (XE-0032).

    The receipt is logged privately: it is in the hash chain, but not on the public log until a member has
    looked at it (`publish_on_triage`). Anyone can still send; nobody can fill the permanent record unread.
    """
    require_pow(v, ctx.node.chat_pow_difficulty)
    body = clean_text(v.payload.get("message"), "message", max_len=8000)
    mid = secrets.token_hex(16)
    m = InboxMessage(id=mid, channel="http", from_account=v.account, to_account=dao_account(ctx), pub_key=v.pub_key,
                     body=body, timestamp=v.timestamp, signature=v.signature, pow_nonce=v.pow_nonce or 0,
                     verified=True, status="new")
    db.add(m)
    await ctx.events.append(db, "inbox.received", v.actor, {
        "id": mid, "channel": "http", "from": v.account, "verified": True, "body": body[:4000], "timestamp": v.timestamp,
    }, ref=f"inbox:{mid}", public=False)
    return m


async def publish_on_triage(ctx: Context, db: AsyncSession, m: InboxMessage, actor: str) -> None:
    """First time a member moves an HTTP message out of `new` or `spam`, put it on the public log. Once is
    enough: a message marked spam and then reconsidered is published then, not twice."""
    if m.channel != "http" or m.status not in ("new", "spam"):
        return
    if await EventLog.page(db, 0, 1, "inbox.published", f"inbox:{m.id}"):
        return
    await ctx.events.append(db, "inbox.published", actor, {
        "id": m.id, "channel": m.channel, "from": m.from_account, "verified": m.verified, "body": m.body[:4000],
        "timestamp": m.timestamp,
    }, ref=f"inbox:{m.id}")


async def queue_reply(ctx: Context, db: AsyncSession, m: InboxMessage, text: str, from_seat: str, kind: str = "reply") -> OutboxMessage:
    """Queue a reply. A member's reply moves the message to `replying`; it becomes `answered` when the reply
    has gone out and returns to `new` if the reply is given up, so the record says what was delivered,
    not what was intended (XE-1776, XE-1846)."""
    o = OutboxMessage(id=secrets.token_hex(8), in_reply_to=m.id, from_seat=from_seat, to_account=m.from_account,
                      body=text, envelope={}, status="queued")
    db.add(o)
    if kind == "reply":
        m.status = "replying"
        m.reply_id = o.id
    await ctx.events.append(db, "outbox.queued", from_seat if from_seat == "harness" else f"seat:{from_seat}", {
        "id": o.id, "in_reply_to": m.id, "to": m.from_account, "kind": kind, "body": text[:4000],
    }, ref=f"inbox:{m.id}")
    return o


async def reply(ctx: Context, db: AsyncSession, m: InboxMessage, v: Verified) -> OutboxMessage:
    text = clean_text(v.payload.get("text"), "text", max_len=8000, max_bytes=8000)
    await publish_on_triage(ctx, db, m, v.actor)
    return await queue_reply(ctx, db, m, text, from_seat=v.seat.id)


async def set_status(ctx: Context, db: AsyncSession, m: InboxMessage, v: Verified) -> InboxMessage:
    status = field_text(v.payload, "status")
    if status not in ("new", "read", "closed", "spam"):
        raise HTTPException(400, "bad status")   # `replying` and `answered` are set by delivery, not by hand
    if status not in ("new", "spam"):
        await publish_on_triage(ctx, db, m, v.actor)
    m.status = status
    m.classification = clean_text(v.payload.get("classification"), "classification", max_len=64,
                                  required=False) or m.classification
    await ctx.events.append(db, "inbox.status", v.actor, {"id": m.id, "status": status, "classification": m.classification},
                            ref=f"inbox:{m.id}", public=status != "spam")
    return m


async def flush_outbox(ctx: Context, db: AsyncSession) -> int:
    """Worker: send queued replies from the DAO account over chat. PoW off the loop. Each row is marked and
    committed as soon as its envelope has gone out, before the next is built: a crash or a pause landing
    mid-batch cannot roll a delivered reply back to `queued` and send it twice (XE-1487, the rule from
    XE-0486 on the fee path)."""
    if not ctx.signer.has("dao") or await pause.is_paused(db):
        return 0
    await _settle_unconfirmed(ctx, db)
    # Members' replies before acknowledgements, oldest first (XE-1845).
    order = (case((OutboxMessage.from_seat == "harness", 1), else_=0), OutboxMessage.created_at.asc())
    rows = list((await db.execute(select(OutboxMessage).where(OutboxMessage.status == "queued").order_by(*order).limit(10))).scalars().all())
    n = 0
    give_up_before = datetime.now(timezone.utc) - timedelta(days=OUTBOX_RETRY_DAYS)
    for o in rows:
        if o.created_at and o.created_at < give_up_before:
            # retried on every tick for a week; the channel is not going to open. Stop, and say so on the record.
            o.status = "failed"
            await ctx.events.append(db, "outbox.failed", "harness", {"id": o.id, "to": o.to_account, "error": o.error[:300]},
                                    ref=f"inbox:{o.in_reply_to}")
            await _reply_outcome(ctx, db, o, delivered=False)
            await db.commit()
            continue
        try:
            kp = ctx.signer.keypair("dao", "chat.send")
            env = await asyncio.to_thread(new_envelope, kp, o.to_account, o.body, ctx.node.chat_pow_difficulty,
                                          None, WORKER_POW_DEADLINE_S)
            if await pause.is_paused(db):   # read after the work, right before the send (XE-1172)
                return n
            # At most once: the intent to send is on disk before the send, so a commit that fails after it
            # cannot roll a delivered reply back to `queued` and send it again under a new id (XE-1729).
            o.status, o.envelope = "sending", env.to_json()
            await db.commit()
            await ctx.chain.chat_send(env.to_json())
            o.status = "sent"
            o.sent_at = datetime.now(timezone.utc)
            await ctx.events.append(db, "outbox.sent", "harness", {"id": o.id, "envelope_id": env.id, "to": o.to_account},
                                    ref=f"inbox:{o.in_reply_to}")
            await _reply_outcome(ctx, db, o, delivered=True)
            n += 1
        except (SignerError, ChatError, Exception) as e:
            o.status = "queued"   # the node did not take it; it goes again
            o.error = str(e)[:500]
            log.warning("outbox send failed %s: %s", o.id, e)
        await db.commit()
    return n


async def _settle_unconfirmed(ctx: Context, db: AsyncSession) -> None:
    """A row found `sending` was handed to the node before the pass that wrote it ended; whether the node
    took it is unknown. It is not sent again: a reply goes out at most once, and the uncertainty is on the
    record (XE-1729)."""
    for o in (await db.execute(select(OutboxMessage).where(OutboxMessage.status == "sending"))).scalars().all():
        o.status, o.sent_at = "sent", datetime.now(timezone.utc)
        o.error = "delivery unconfirmed: the pass that sent it did not finish"
        await ctx.events.append(db, "outbox.unconfirmed", "harness", {"id": o.id, "to": o.to_account},
                                ref=f"inbox:{o.in_reply_to}")
        await _reply_outcome(ctx, db, o, delivered=True)
    await db.commit()


async def _reply_outcome(ctx: Context, db: AsyncSession, o: OutboxMessage, *, delivered: bool) -> None:
    """The inbox message a member's reply answers follows the reply: `answered` once it has gone out, back
    to `new` if it never will (XE-1776, XE-1846). Acknowledgements leave the message as it is."""
    if o.from_seat == "harness":
        return
    m = (await db.execute(select(InboxMessage).where(InboxMessage.id == o.in_reply_to))).scalar_one_or_none()
    if m is None or m.reply_id != o.id:
        return
    m.status = "answered" if delivered else "new"
    if not delivered:
        m.reply_id = ""
    await ctx.events.append(db, "inbox.status", "harness", {"id": m.id, "status": m.status, "reply": o.id},
                            ref=f"inbox:{m.id}")


async def read_proof(ctx: Context) -> dict[str, str]:
    ch = await ctx.chain.chat_challenge()
    kp = ctx.signer.keypair("dao", "chat.read_proof")
    return chat_read_proof(kp, ch["challenge"])


NS = 1_000_000_000
CURSOR_MARGIN_NS = 15 * 60 * NS   # three times the node's envelope clock skew (5 minutes)
CURSOR_START_NS = 24 * 3600 * NS


async def chat_cursor(db: AsyncSession) -> int:
    """Where a backfill asks the node from: the newest stored chat envelope's timestamp less a margin wider
    than the node's clock skew allowance, or a day ago if nothing is stored. The cursor is derived from
    what is on disk, never from what was seen: an envelope that failed to store, or one dated five minutes
    ahead by its sender, cannot move it past honest messages (XE-1651, XE-1666, XE-1768). Over-fetching is
    harmless; `store_envelope` skips ids it holds."""
    newest = (await db.execute(select(func.max(InboxMessage.timestamp)).where(InboxMessage.channel == "chat"))).scalar_one()
    now = time.time_ns()
    return max(now - CURSOR_START_NS, int(newest) - CURSOR_MARGIN_NS) if newest else now - CURSOR_START_NS


async def backfill(ctx: Context, db: AsyncSession) -> int:
    """Pull messages the node holds since the stored cursor (used at start and after stream drops)."""
    if not ctx.signer.has("dao"):
        return 0
    proof = await read_proof(ctx)
    msgs = await ctx.chain.chat_messages(proof, await chat_cursor(db))
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


def is_public(m: InboxMessage) -> bool:
    """What the public surfaces may show (XE-0195). Only what the harness verified (XE-1254); spam never;
    an HTTP message not until a member has moved it out of `new`, matching when its receipt reaches the
    public log (`publish_on_triage`). Verified chat is logged on receipt and public from the start.
    `list_public` is the same rule in SQL."""
    return m.verified and m.status != "spam" and not (m.channel == "http" and m.status == "new")


async def list_public(db: AsyncSession, limit: int = 100) -> list[InboxMessage]:
    """Public listing under `is_public`'s rule, in SQL so `limit` counts visible rows."""
    q = (select(InboxMessage).where(InboxMessage.verified.is_(True), InboxMessage.status != "spam")
         .where(~((InboxMessage.channel == "http") & (InboxMessage.status == "new")))
         .order_by(InboxMessage.timestamp.desc()).limit(limit))
    return list((await db.execute(q)).scalars().all())


_UNTRIAGED = (InboxMessage.channel == "http", InboxMessage.status == "new")


async def list_untriaged(db: AsyncSession, limit: int = 100, offset: int = 0) -> list[InboxMessage]:
    """For a seat holder, over a signed request: HTTP messages nobody has looked at yet, oldest first, so
    the one that has waited longest is on the first page however many arrive after it (XE-1565)."""
    q = select(InboxMessage).where(*_UNTRIAGED).order_by(InboxMessage.timestamp.asc()).offset(offset).limit(limit)
    return list((await db.execute(q)).scalars().all())


async def count_untriaged(db: AsyncSession) -> int:
    return int((await db.execute(select(func.count()).select_from(InboxMessage).where(*_UNTRIAGED))).scalar_one())


async def get_public(db: AsyncSession, mid: str) -> InboxMessage:
    m = await get(db, mid)
    if not is_public(m):
        raise HTTPException(404, "message not found")
    return m


async def get(db: AsyncSession, mid: str, *, lock: bool = False) -> InboxMessage:
    """`lock=True` takes the row FOR UPDATE: every path that changes a message loads it this way, so two
    writers queue instead of each saving its own copy of a list over the other's (XE-0672)."""
    q = select(InboxMessage).where(InboxMessage.id == mid)
    m = (await db.execute(q.with_for_update() if lock else q)).scalar_one_or_none()
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
