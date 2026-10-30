"""Pause: the one lever that stops the harness, held by members only.

One member may pause for 72 hours on a written determination naming a ground. Both members may
extend by 7 days at a time. A public post is due within 4 hours; the harness drafts it in the
members' plain words and publishes it automatically at the deadline if nobody has edited it.
While paused: no outbound chat, no fee movements, no state-chain block built, signed or submitted,
no new registry or anchor sessions, no agent output. Reads, the log, the portal's vote intake and
session approvals (record-keeping) stay up. A pause is the company suspending its own operations;
it does not touch the chain.
"""

from __future__ import annotations

import secrets
import time

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth import Verified
from ..context import Context
from ..models import PauseRecord
from ..text import clean_text

H = 3600 * 1_000_000_000
D = 24 * H


async def active(db: AsyncSession) -> PauseRecord | None:
    now = time.time_ns()
    rows = (await db.execute(select(PauseRecord).where(PauseRecord.status == "active"))).scalars().all()
    for r in rows:
        if r.indefinite or r.expires_at > now:
            return r
    return None


async def is_paused(db: AsyncSession) -> bool:
    return (await active(db)) is not None


async def start(ctx: Context, db: AsyncSession, v: Verified) -> PauseRecord:
    cfg = ctx.config.pause
    ground = v.payload.get("ground", "")
    text = clean_text(v.payload.get("determination"), "determination", max_len=20_000)
    if ground not in cfg.get("grounds", []):
        raise HTTPException(400, f"ground must be one of {cfg.get('grounds', [])}")
    if len(text) < 20:
        raise HTTPException(400, "a written determination is required")
    if await active(db):
        raise HTTPException(409, "already paused")
    now = time.time_ns()
    r = PauseRecord(id=secrets.token_hex(8), determined_by=v.seat.id, ground=ground, determination=text,
                    started_at=now, expires_at=now + int(cfg.get("initial_hours", 72)) * H, indefinite=False,
                    extensions=[], lifted_by=[], post_text=_draft_post(ctx, ground), status="active")
    db.add(r)
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


async def extend(ctx: Context, db: AsyncSession, r: PauseRecord, v: Verified) -> PauseRecord:
    """Extensions need both members: the first signature is recorded, the second applies it."""
    if r.status != "active":
        raise HTTPException(409, "pause is not active")
    pending = [e for e in r.extensions if not e.get("applied")]
    sigs = (pending[0]["signatures"] if pending else [])
    if any(s["seat"] == v.seat.id for s in sigs):
        raise HTTPException(409, "this member already signed this extension")
    sigs = [*sigs, {"seat": v.seat.id, "public_key": v.pub_key, "signature": v.signature, "timestamp": v.timestamp}]
    entry = {"signatures": sigs, "applied": False, "reason": clean_text(v.payload.get("reason"), "reason", max_len=2000, required=False)}
    if len(sigs) >= len(ctx.config.members):
        entry["applied"] = True
        base = max(r.expires_at, time.time_ns())
        r.expires_at = base + int(ctx.config.pause.get("extension_days", 7)) * D
        entry["new_expires_at"] = r.expires_at
    r.extensions = [*[e for e in r.extensions if e.get("applied")], entry]
    await ctx.events.append(db, "pause.extended" if entry["applied"] else "pause.extension_signed", v.actor, {
        "pause_id": r.id, "expires_at": r.expires_at, "signatures": len(sigs), "reason": entry["reason"],
    }, ref=f"pause:{r.id}")
    return r


async def lift(ctx: Context, db: AsyncSession, r: PauseRecord, v: Verified) -> PauseRecord:
    """Lifting early needs both members, like an extension."""
    if r.status != "active":
        raise HTTPException(409, "pause is not active")
    if any(s["seat"] == v.seat.id for s in r.lifted_by):
        raise HTTPException(409, "already signed")
    r.lifted_by = [*r.lifted_by, {"seat": v.seat.id, "public_key": v.pub_key, "signature": v.signature, "timestamp": v.timestamp}]
    if len(r.lifted_by) >= len(ctx.config.members):
        r.status = "lifted"
        r.lifted_at = time.time_ns()
        await ctx.events.append(db, "pause.lifted", v.actor, {"pause_id": r.id, "lifted_at": r.lifted_at}, ref=f"pause:{r.id}")
    else:
        await ctx.events.append(db, "pause.lift_signed", v.actor, {"pause_id": r.id, "signatures": len(r.lifted_by)}, ref=f"pause:{r.id}")
    return r


async def set_post(ctx: Context, db: AsyncSession, r: PauseRecord, v: Verified) -> PauseRecord:
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


async def tick(ctx: Context, db: AsyncSession) -> None:
    """Worker: auto-publish overdue posts, expire pauses."""
    now = time.time_ns()
    due_h = int(ctx.config.pause.get("public_post_within_hours", 4))
    rows = (await db.execute(select(PauseRecord).where(PauseRecord.status == "active"))).scalars().all()
    for r in rows:
        if not r.posted_at and now >= r.started_at + due_h * H:
            await publish_post(ctx, db, r, "harness")
        if not r.indefinite and now >= r.expires_at:
            r.status = "expired"
            await ctx.events.append(db, "pause.expired", "harness", {"pause_id": r.id, "expires_at": r.expires_at}, ref=f"pause:{r.id}")


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
