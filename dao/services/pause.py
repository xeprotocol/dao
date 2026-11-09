"""Pause: the one lever that stops the harness, held by members only.

One member may pause for 72 hours on a written determination naming a ground. Both members may
extend by 7 days at a time. A public post is due within 4 hours; the harness drafts it in the
members' plain words and publishes it automatically at the deadline if nobody has edited it.
While paused: no outbound chat, no fee movements, no state-chain block built, signed or submitted,
no new registry or anchor sessions, no agent output. Reads, the log, the portal's vote intake, session
approvals (record-keeping) and the inbox stay up, so the DAO stays addressable: the worker keeps its
directory entry alive, a signed record naming only its own node peer, because letting it lapse would
turn away every message sent to the DAO during the pause (XE-1445). A pause is the company suspending
its own operations; it does not touch the chain. `is_paused` is read inside the transaction of every
chain write, not only at job start.
"""

from __future__ import annotations

import secrets
import time

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth import Verified
from ..context import Context
from ..models import PauseRecord
from ..text import clean_text, field_text

H = 3600 * 1_000_000_000
D = 24 * H


def in_force(r: PauseRecord) -> bool:
    """A pause is in force by its clock, not by its stored status: the worker marks a lapsed row `expired`
    on its next pass, and until then the row still reads `active`. Every reader and every member action on
    a pause asks this, so a lapsed pause cannot be extended back to life, lifted after it ended, or given a
    public post (XE-1726, XE-1893)."""
    return r.status == "active" and (r.indefinite or r.expires_at > time.time_ns())


def require_in_force(r: PauseRecord) -> None:
    if not in_force(r):
        raise HTTPException(409, "pause is not active" if r.status != "active" else "pause has expired")


async def active(db: AsyncSession) -> PauseRecord | None:
    rows = (await db.execute(select(PauseRecord).where(PauseRecord.status == "active"))).scalars().all()
    for r in rows:
        if in_force(r):
            return r
    return None


async def is_paused(db: AsyncSession) -> bool:
    return (await active(db)) is not None


async def start(ctx: Context, db: AsyncSession, v: Verified) -> PauseRecord:
    cfg = ctx.config.pause
    ground = field_text(v.payload, "ground")
    text = clean_text(v.payload.get("determination"), "determination", max_len=20_000)
    if ground not in cfg.get("grounds", []):
        raise HTTPException(400, f"ground must be one of {cfg.get('grounds', [])}")
    if len(text) < 20:
        raise HTTPException(400, "a written determination is required")
    await expire_lapsed(ctx, db)
    await db.flush()
    now = time.time_ns()
    r = PauseRecord(id=secrets.token_hex(8), determined_by=v.seat.id, ground=ground, determination=text,
                    started_at=now, expires_at=now + int(cfg.get("initial_hours", 72)) * H, indefinite=False,
                    extensions=[], lifted_by=[], post_text=_draft_post(ctx, ground), status="active")
    db.add(r)
    try:
        # The pause is a singleton and the database says so: one active row (`ux_pause_one_active`). Two
        # members pausing at once are serialised by the index, not by a read that each can pass (XE-1176).
        await db.flush()
    except IntegrityError as e:
        raise HTTPException(409, "already paused") from e
    await ctx.events.append(db, "pause.started", v.actor, {
        "pause_id": r.id, "ground": ground, "determination": text, "started_at": now, "expires_at": r.expires_at,
        "public_post_due": now + int(cfg.get("public_post_within_hours", 4)) * H,
    }, ref=f"pause:{r.id}")
    return r


def _draft_post(ctx: Context, ground: str) -> str:
    plain = {
        "exploit_or_irreversible_loss": "we found something that could cause irreversible loss",
        "legal_compulsion": "we have been legally required to",
        "both_members_agree": "the two of us agreed it was the right call",
    }.get(ground, "we judged it necessary")
    return (f"We have paused the automated side of the DAO because {plain}. Reads, the log and the portal stay up. "
            f"Nothing moves while this is in place. We will post again within the pause window with what we found "
            f"and what happens next.")


def _consent(ctx: Context, sigs: list[dict]) -> tuple[bool, int, list[str]]:
    """Every current member who holds the pause right must have signed: the set that is counted is the set
    the routes let sign, so consent can always be reached (XE-1013). A signature from a seat that has since
    left the company carries nothing (XE-0646, as XE-0600 for resolutions): (met, live_count, set_aside_seats)."""
    current = {s.id: s.public_key for s in ctx.config.members if s.can("pause")}
    # ... and made with the key the seat holds today, as for resolutions (XE-1761).
    live = [s for s in sigs if current.get(s["seat"]) and current[s["seat"]] == (s.get("public_key") or "").lower()]
    set_aside = sorted({s["seat"] for s in sigs} - {s["seat"] for s in live})
    return len(live) >= len(current), len(live), set_aside


async def extend(ctx: Context, db: AsyncSession, r: PauseRecord, v: Verified) -> PauseRecord:
    """Extensions need every current member: the first signature is recorded, the last applies it."""
    require_in_force(r)
    pending = [e for e in r.extensions if not e.get("applied")]
    sigs = (pending[0]["signatures"] if pending else [])
    if any(s["seat"] == v.seat.id for s in sigs):
        raise HTTPException(409, "this member already signed this extension")
    sigs = [*sigs, {"seat": v.seat.id, "public_key": v.pub_key, "signature": v.signature, "timestamp": v.timestamp}]
    entry = {"signatures": sigs, "applied": False, "reason": clean_text(v.payload.get("reason"), "reason", max_len=2000, required=False)}
    met, n_live, set_aside = _consent(ctx, sigs)
    if met:
        entry["applied"] = True
        base = max(r.expires_at, time.time_ns())
        r.expires_at = base + int(ctx.config.pause.get("extension_days", 7)) * D
        entry["new_expires_at"] = r.expires_at
    r.extensions = [*[e for e in r.extensions if e.get("applied")], entry]
    await ctx.events.append(db, "pause.extended" if entry["applied"] else "pause.extension_signed", v.actor, {
        "pause_id": r.id, "expires_at": r.expires_at, "signatures": n_live, "reason": entry["reason"],
        **({"set_aside": set_aside} if set_aside else {}),
    }, ref=f"pause:{r.id}")
    return r


async def lift(ctx: Context, db: AsyncSession, r: PauseRecord, v: Verified) -> PauseRecord:
    """Lifting early needs every current member, like an extension."""
    require_in_force(r)
    if any(s["seat"] == v.seat.id for s in r.lifted_by):
        raise HTTPException(409, "already signed")
    r.lifted_by = [*r.lifted_by, {"seat": v.seat.id, "public_key": v.pub_key, "signature": v.signature, "timestamp": v.timestamp}]
    met, n_live, set_aside = _consent(ctx, r.lifted_by)
    if met:
        r.status = "lifted"
        r.lifted_at = time.time_ns()
        await ctx.events.append(db, "pause.lifted", v.actor, {"pause_id": r.id, "lifted_at": r.lifted_at,
                                                               **({"set_aside": set_aside} if set_aside else {})}, ref=f"pause:{r.id}")
    else:
        await ctx.events.append(db, "pause.lift_signed", v.actor, {"pause_id": r.id, "signatures": n_live,
                                                                    **({"set_aside": set_aside} if set_aside else {})}, ref=f"pause:{r.id}")
    return r


async def set_post(ctx: Context, db: AsyncSession, r: PauseRecord, v: Verified) -> PauseRecord:
    """The public post is written while the pause is in force; a lifted or expired pause's record stands."""
    require_in_force(r)
    text = clean_text(v.payload.get("text"), "text", max_len=20_000)
    r.post_text = text
    if r.posted_at:
        await ctx.events.append(db, "pause.post_updated", v.actor, {"pause_id": r.id, "text": text}, ref=f"pause:{r.id}")
    else:
        await publish_post(ctx, db, r, v.actor)
    return r


async def publish_post(ctx: Context, db: AsyncSession, r: PauseRecord, actor: str) -> None:
    r.posted_at = time.time_ns()
    await ctx.events.append(db, "pause.posted", actor, {"pause_id": r.id, "text": r.post_text}, ref=f"pause:{r.id}")


async def _due_rows(db: AsyncSession, *predicates) -> list[PauseRecord]:
    """Active rows matching the predicates, each FOR UPDATE SKIP LOCKED: a member's extend, lift or post on
    the same row either waits for this writer or is skipped by it, never overwritten (XE-0987)."""
    q = select(PauseRecord).where(PauseRecord.status == "active", *predicates).with_for_update(skip_locked=True)
    return list((await db.execute(q)).scalars().all())


async def expire_lapsed(ctx: Context, db: AsyncSession) -> int:
    now = time.time_ns()
    rows = await _due_rows(db, PauseRecord.indefinite.is_(False), PauseRecord.expires_at <= now)
    for r in rows:
        r.status = "expired"
        await ctx.events.append(db, "pause.expired", "harness", {"pause_id": r.id, "expires_at": r.expires_at}, ref=f"pause:{r.id}")
    return len(rows)


async def tick(ctx: Context, db: AsyncSession) -> None:
    """Worker: expire lapsed pauses, then auto-publish overdue posts for the ones still in force."""
    await expire_lapsed(ctx, db)
    now = time.time_ns()
    due_h = int(ctx.config.pause.get("public_post_within_hours", 4))
    for r in await _due_rows(db, PauseRecord.posted_at.is_(None), PauseRecord.started_at <= now - due_h * H):
        if in_force(r):
            await publish_post(ctx, db, r, "harness")


async def history(db: AsyncSession, limit: int = 50) -> list[PauseRecord]:
    return list((await db.execute(select(PauseRecord).order_by(PauseRecord.started_at.desc()).limit(limit))).scalars().all())


def to_dict(r: PauseRecord) -> dict:
    return {
        "id": r.id, "status": r.status, "determined_by": r.determined_by, "ground": r.ground,
        "determination": r.determination, "started_at": r.started_at, "expires_at": r.expires_at,
        "indefinite": r.indefinite, "extensions": [{"applied": e.get("applied"), "signatures": len(e.get("signatures", [])),
                                                    "new_expires_at": e.get("new_expires_at"), "reason": e.get("reason", "")}
                                                   for e in r.extensions],
        "lifted_at": r.lifted_at, "lift_signatures": len(r.lifted_by), "post_text": r.post_text, "posted_at": r.posted_at,
    }
