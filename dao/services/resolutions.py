"""Member resolutions: the company path.

A resolution is text (and optionally state-chain ops) proposed by a seat and signed by members.
Reserved matters need every member; ordinary matters need a majority of members. Once passed, a
resolution with ops opens a signing session; one without ops is simply recorded.
"""

from __future__ import annotations

import secrets
import time
from datetime import datetime, timezone

from fastapi import HTTPException
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth import Verified
from ..canonical import DOMAIN_RESOLUTION, digest
from ..context import Context
from ..models import Resolution
from ..text import clean_text
from . import sessions

RESERVED_MATTERS = {
    "amend_articles", "amend_operating_agreement", "admit_member", "remove_member", "dissolve",
    "change_keyset", "change_treasury_policy", "change_quorum", "designate_agent", "retire_agent",
    "change_schedule_b", "change_schedule_c", "spend", "borrow", "contract",
}
ORDINARY_MATTERS = {"note", "registry", "anchor", "parameter", "respond", "adopt_open_vote", "decline_open_vote", "other"}


def _matter_rule(cfg, matter: str) -> tuple[int, str]:
    members = cfg.members
    n = len(members)
    if matter in RESERVED_MATTERS:
        return n, "all members"
    return (n // 2) + 1, "majority of members"


def resolution_target(res_id: str, body_hash: str, decision: str) -> bytes:
    return digest(DOMAIN_RESOLUTION, {"resolution_id": res_id, "body_hash": body_hash, "decision": decision})


async def _next_number(db: AsyncSession) -> int:
    return int((await db.execute(select(func.coalesce(func.max(Resolution.number), 0)))).scalar_one()) + 1


async def propose(ctx: Context, db: AsyncSession, v: Verified) -> Resolution:
    p = v.payload
    title = clean_text(p.get("title"), "title", max_len=160)
    body = clean_text(p.get("body"), "body", max_len=50_000)
    matter = p.get("matter") or "other"
    ops = p.get("ops")
    if matter not in RESERVED_MATTERS | ORDINARY_MATTERS:
        raise HTTPException(400, f"unknown matter {matter!r}")
    if ops is not None:
        ops = sessions.normalise_ops(ops)
    r = Resolution(id=secrets.token_hex(8), number=await _next_number(db), title=title, body=body, matter=matter,
                   ops=ops, proposed_by=v.seat.id, status="open", signatures=[],
                   related_proposal=clean_text(p.get("related_proposal"), "related_proposal", max_len=64, required=False))
    db.add(r)
    await ctx.events.append(db, "resolution.proposed", v.actor, {
        "resolution_id": r.id, "number": r.number, "title": title, "body": body, "matter": matter, "ops": ops,
        "reserved": matter in RESERVED_MATTERS, "related_proposal": r.related_proposal,
    }, ref=f"resolution:{r.id}")
    return r


def body_hash(r: Resolution) -> str:
    from ..canonical import canonical_json, sha256_hex
    return sha256_hex(canonical_json({"title": r.title, "body": r.body, "matter": r.matter, "ops": r.ops}))


async def decide(ctx: Context, db: AsyncSession, r: Resolution, v: Verified, decision: str) -> Resolution:
    """A member signs for or against. payload = {resolution_id, body_hash, decision}."""
    if r.status != "open":
        raise HTTPException(409, f"resolution is {r.status}")
    if decision not in ("for", "against"):
        raise HTTPException(400, "decision must be 'for' or 'against'")
    if v.payload.get("resolution_id") != r.id or v.payload.get("body_hash") != body_hash(r) or v.payload.get("decision") != decision:
        raise HTTPException(400, "signed payload does not match this resolution")
    if any(s["seat"] == v.seat.id for s in r.signatures):
        raise HTTPException(409, "this member has already signed")
    r.signatures = [*r.signatures, {"seat": v.seat.id, "public_key": v.pub_key, "signature": v.signature,
                                    "decision": decision, "timestamp": v.timestamp}]
    needed, rule = _matter_rule(ctx.config, r.matter)
    fors = sum(1 for s in r.signatures if s["decision"] == "for")
    againsts = sum(1 for s in r.signatures if s["decision"] == "against")
    await ctx.events.append(db, "resolution.signed", v.actor, {
        "resolution_id": r.id, "decision": decision, "for": fors, "against": againsts, "needed": needed, "rule": rule,
    }, ref=f"resolution:{r.id}")
    n_members = len(ctx.config.members)
    if fors >= needed:
        r.status = "passed"
        r.decided_at = datetime.now(timezone.utc)
        await ctx.events.append(db, "resolution.passed", "harness", {
            "resolution_id": r.id, "number": r.number, "title": r.title, "matter": r.matter, "for": fors, "against": againsts,
        }, ref=f"resolution:{r.id}")
        if r.ops:
            kind = r.matter if r.matter in sessions.KINDS else "parameter"
            w = ctx.config.windows
            timelock_h = int(w.get("upgrade_timelock_hours", 0) or 0) if w.get("upgrade_timelock_status") == "active" else 0
            not_before = time.time_ns() + timelock_h * 3600 * 1_000_000_000 if timelock_h else None
            s = await sessions.create(ctx, db, kind=kind, title=f"R{r.number}: {r.title}", ops=r.ops, actor="harness",
                                      resolution_id=r.id, not_before=not_before)
            r.session_id = s.id
    elif againsts > n_members - needed:
        r.status = "rejected"
        r.decided_at = datetime.now(timezone.utc)
        await ctx.events.append(db, "resolution.rejected", "harness", {
            "resolution_id": r.id, "number": r.number, "for": fors, "against": againsts,
        }, ref=f"resolution:{r.id}")
    return r


async def withdraw(ctx: Context, db: AsyncSession, r: Resolution, v: Verified) -> Resolution:
    if r.status != "open":
        raise HTTPException(409, f"resolution is {r.status}")
    if r.proposed_by != v.seat.id and not v.seat.is_member:
        raise HTTPException(403, "only the proposer or a member may withdraw")
    r.status = "withdrawn"
    r.decided_at = datetime.now(timezone.utc)
    await ctx.events.append(db, "resolution.withdrawn", v.actor, {"resolution_id": r.id}, ref=f"resolution:{r.id}")
    return r


async def get(db: AsyncSession, res_id: str) -> Resolution:
    r = (await db.execute(select(Resolution).where(Resolution.id == res_id))).scalar_one_or_none()
    if r is None:
        raise HTTPException(404, "resolution not found")
    return r


async def list_resolutions(db: AsyncSession, status: str | None = None, limit: int = 200) -> list[Resolution]:
    q = select(Resolution).order_by(Resolution.number.desc()).limit(limit)
    if status:
        q = q.where(Resolution.status == status)
    return list((await db.execute(q)).scalars().all())


def to_dict(r: Resolution, cfg) -> dict:
    needed, rule = _matter_rule(cfg, r.matter)
    return {
        "id": r.id, "number": r.number, "title": r.title, "body": r.body, "body_hash": body_hash(r), "matter": r.matter,
        "reserved": r.matter in RESERVED_MATTERS, "ops": r.ops, "proposed_by": r.proposed_by, "status": r.status,
        "signatures": [{"seat": s["seat"], "decision": s["decision"], "timestamp": s["timestamp"]} for s in r.signatures],
        "needed": needed, "rule": rule, "related_proposal": r.related_proposal, "session_id": r.session_id,
        "created_at": r.created_at.isoformat() if r.created_at else None,
        "decided_at": r.decided_at.isoformat() if r.decided_at else None,
    }
