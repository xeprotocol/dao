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

from xe.chat import MAX_ENVELOPE_SKEW_NS, ChatError, Envelope, new_envelope, verify_envelope
from xe.chat_auth import chat_read_proof
from xe.pow import WORKER_POW_DEADLINE_S

from ..auth import Verified, require_pow
from ..context import Context
from ..log import EventLog
from ..models import InboxMessage, OutboxMessage
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


# The outbox, in one rule (XE-2148): a reply has one envelope at a time, the envelope is on disk before it
# is offered, and the row says `sent` only when the node has said it took that envelope or the node's own
# store holds it. Nothing is concluded from a send that raised: the node stores an envelope after the
# recipient's node has it and before it answers, so a timeout says nothing about delivery.
#
#   queued    no envelope is in play. One is built (signed, worked) and committed with the row.
#   sending   an envelope is in play. While it is fresh it is offered again as it is, which is safe however
#             many times it happens: the node and the recipient both keep one copy per envelope id. Once it
#             is too old for any node to take, the node's store says whether it ever landed: there, the row
#             is `sent`; not there, the row is `queued` again and a new envelope is built.
#   sent      the node took the envelope.
#
# The earlier versions each named the failure they had seen (a commit lost after the send, then a pass that
# died mid-send) and guessed for the rest; the guess for "the send raised" was "not taken", and the retry
# went out under a new id that nothing could match to the first.
#
# What this cannot see, stated rather than guessed at: the node's chat store is in memory and bounded, so a
# node restarted (or an account's store evicted) between a send and the read-back looks like "never held",
# and the reply goes out again under a new id; and a recipient whose node stored the envelope while ours
# never did (the answer between the two nodes was lost) is offered a second one after the first has expired.

FRESH_NS = MAX_ENVELOPE_SKEW_NS - 60 * 1_000_000_000     # still worth offering: a node will take it
EXPIRED_NS = MAX_ENVELOPE_SKEW_NS + 60 * 1_000_000_000   # no node will take it now, whatever its clock


async def flush_outbox(ctx: Context, db: AsyncSession) -> int:
    """Worker: send queued replies from the DAO account over chat. PoW off the loop. Every row is committed
    at each step it takes, so a crash or a pause landing mid-batch leaves each row saying exactly how far
    it got. Returns how many rows became `sent`.

    Under a pause nothing is built and nothing is offered. What was offered before the pause is still
    looked up in the node's store, which is a read: a reply the node took is recorded as sent while the
    store still holds it, rather than after a pause that may outlast the store."""
    if not ctx.signer.has("dao"):
        return 0
    n = await _resolve_sending(ctx, db)
    if await pause.is_paused(db):
        return n
    # Members' replies before acknowledgements, oldest first (XE-1845).
    order = (case((OutboxMessage.from_seat == "harness", 1), else_=0), OutboxMessage.created_at.asc())
    rows = list((await db.execute(select(OutboxMessage).where(OutboxMessage.status == "queued").order_by(*order).limit(10))).scalars().all())
    give_up_before = datetime.now(timezone.utc) - timedelta(days=OUTBOX_RETRY_DAYS)
    for o in rows:
        if o.created_at and o.created_at < give_up_before:
            # retried for a week; the channel is not going to open. Stop, and say so on the record.
            await _lock_answered(db, o)
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
        except Exception as e:   # nothing was built, so nothing was offered: the row is still `queued`
            o.error = str(e)[:500]
            log.warning("outbox %s: no envelope built: %s", o.id, e)
            await db.commit()
            continue
        if await pause.is_paused(db):   # read after the work, right before the send (XE-1172)
            return n                    # the envelope is discarded; the row is still `queued`
        o.status, o.envelope, o.error = "sending", env.to_json(), ""
        await db.commit()
        n += await _offer(ctx, db, o)
    return n


async def _offer(ctx: Context, db: AsyncSession, o: OutboxMessage) -> bool:
    """Offer a `sending` row's envelope to the node. True: the node took it and the row is `sent`. False:
    the send raised, which says nothing either way, so the row stays `sending` for `_resolve_sending`.
    The caller has read the pause."""
    try:
        await ctx.chain.chat_send(o.envelope)
    except Exception as e:
        o.error = str(e)[:500]
        log.warning("outbox %s: send of %s raised; outcome unknown: %s", o.id, str(o.envelope.get("id"))[:12], e)
        await db.commit()
        return False
    await _sent(ctx, db, o)
    await db.commit()
    return True


async def _lock_answered(db: AsyncSession, o: OutboxMessage) -> None:
    """Locks are taken in one order everywhere: the inbox message, then the log head. A member's reply or
    status change holds the message while it appends its event, so the outbox takes the message before it
    appends what became of the reply, not after; the other way round, the two wait on each other."""
    if o.from_seat != "harness":
        await db.execute(select(InboxMessage.id).where(InboxMessage.id == o.in_reply_to).with_for_update())


async def _sent(ctx: Context, db: AsyncSession, o: OutboxMessage) -> None:
    await _lock_answered(db, o)
    o.status, o.sent_at, o.error = "sent", datetime.now(timezone.utc), ""
    await ctx.events.append(db, "outbox.sent", "harness", {"id": o.id, "envelope_id": o.envelope["id"], "to": o.to_account},
                            ref=f"inbox:{o.in_reply_to}")
    await _reply_outcome(ctx, db, o, delivered=True)


async def _resolve_sending(ctx: Context, db: AsyncSession) -> int:
    """Rows whose envelope was offered (or was about to be) and whose outcome is not on disk. The node's
    store is asked once for all of them. A store that cannot be read concludes nothing: no row becomes
    `sent` or `queued` on its account, and an envelope still fresh is offered again all the same."""
    rows = list((await db.execute(select(OutboxMessage).where(OutboxMessage.status == "sending")
                                  .order_by(OutboxMessage.created_at.asc()))).scalars().all())
    for o in [o for o in rows if not _in_play(o)]:   # no envelope to look for: nothing can have been offered
        o.status = "queued"
        rows.remove(o)
    await db.commit()
    if not rows:
        return 0
    # An envelope's age is taken once, as the store is asked. "Not in the store and expired" is only the
    # end of an envelope if it had expired before the store answered; measured later, row by row, a pass
    # slowed by its own sends would call one expired that a node could still have taken after the read.
    asked_at = time.time_ns()
    held: set[str] | None = None
    try:
        since = min(o.envelope["timestamp"] for o in rows) - 1
        store = await ctx.chain.chat_messages(await read_proof(ctx), since)
        held = {d["id"] for d in store if isinstance(d.get("id"), str)}
    except Exception as e:   # nothing is concluded for any row; a fresh envelope can still be offered again
        log.warning("outbox: %d replies in play and the node's chat store cannot be read: %s", len(rows), e)
    n = 0
    for o in rows:
        age = asked_at - o.envelope["timestamp"]
        if held is not None and o.envelope["id"] in held:
            await _sent(ctx, db, o)   # a record of what happened; nothing is written to the node
            n += 1
        elif age < FRESH_NS:
            # the same envelope again, which no reading of the store is needed for: both nodes keep one copy
            # per id. The pause is read here, after the store was (XE-1172); under one, nothing is offered.
            if not await pause.is_paused(db):
                n += await _offer(ctx, db, o)
        elif held is not None and age > EXPIRED_NS:
            o.status = "queued"
            o.error = (f"the node never held the envelope and it is now too old to offer; a new one will be built"
                       f"{'. The last send said: ' + o.error if o.error else ''}")[:500]
        await db.commit()
    return n


def _in_play(o: OutboxMessage) -> bool:
    e = o.envelope if isinstance(o.envelope, dict) else {}
    ts = e.get("timestamp")
    return isinstance(e.get("id"), str) and bool(e["id"]) and isinstance(ts, int) and not isinstance(ts, bool)


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
    n = 0
    for d in await ctx.chain.chat_messages(proof, await chat_cursor(db)):
        if await receive(ctx, db, d):
            n += 1
    return n


async def receive(ctx: Context, db: AsyncSession, item) -> InboxMessage | None:
    """One item from the node's chat feed (the stream or a backfill): stored if it is an envelope addressed
    to the DAO that is not already held. An item that is not an envelope at all is logged and skipped, so
    one bad item costs itself and nothing behind it (XE-2209); both readers come through here."""
    try:
        env = Envelope.from_json(item)
    except ChatError as e:
        log.info("chat item skipped: %s", e)
        return None
    if env.to != ctx.signer.address("dao"):
        return None
    return await store_envelope(ctx, db, env)


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
