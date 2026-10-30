"""/v1/members/*: signed actions by seat holders. Every call carries a SignedRequest under the
member-action domain; the seat is resolved from the key. Nothing here is reachable without a seat.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException

from ..auth import SignedRequest, require_seat, verify_and_claim
from ..canonical import DOMAIN_MEMBER_ACTION, DOMAIN_OPS_APPROVAL, DOMAIN_RESOLUTION
from ..services import inbox as inbox_svc
from ..services import pause as pause_svc
from ..services import records, resolutions, sessions
from ..text import clean_text
from .deps import Ctx, Db

router = APIRouter(prefix="/v1/members", tags=["members"])


@router.get("/whoami/{pub_key}")
async def whoami(pub_key: str, ctx: Ctx):
    s = ctx.config.seat_by_key(pub_key)
    if not s:
        raise HTTPException(404, "no seat for this key")
    return {"seat": s.id, "name": s.name, "kind": s.kind, "role": s.role, "may": list(s.may), "account": s.account}


# ---- resolutions ------------------------------------------------------------------------------

@router.post("/resolutions", status_code=201)
async def propose_resolution(req: SignedRequest, ctx: Ctx, db: Db):
    v = require_seat(await verify_and_claim(db, req, DOMAIN_MEMBER_ACTION), ctx.config)
    if v.payload.get("matter") in resolutions.RESERVED_MATTERS and not v.seat.is_member:
        raise HTTPException(403, "reserved matters are proposed by members")
    r = await resolutions.propose(ctx, db, v)
    await db.commit()
    return resolutions.to_dict(r, ctx.config)


@router.post("/resolutions/{res_id}/sign", status_code=201)
async def sign_resolution(res_id: str, req: SignedRequest, ctx: Ctx, db: Db):
    v = require_seat(await verify_and_claim(db, req, DOMAIN_RESOLUTION), ctx.config, right="sign_resolutions", members_only=True)
    r = await resolutions.get(db, res_id)
    await resolutions.decide(ctx, db, r, v, v.payload.get("decision", ""))
    await db.commit()
    return resolutions.to_dict(r, ctx.config)


@router.post("/resolutions/{res_id}/withdraw")
async def withdraw_resolution(res_id: str, req: SignedRequest, ctx: Ctx, db: Db):
    v = require_seat(await verify_and_claim(db, req, DOMAIN_MEMBER_ACTION), ctx.config)
    r = await resolutions.get(db, res_id)
    await resolutions.withdraw(ctx, db, r, v)
    await db.commit()
    return resolutions.to_dict(r, ctx.config)


# ---- signing sessions (state chain) -----------------------------------------------------------

@router.get("/sessions")
async def list_sessions(db: Db, status: str | None = None):
    return {"sessions": [sessions.to_dict(s) for s in await sessions.list_sessions(db, status)]}


@router.get("/sessions/{sid}")
async def get_session(sid: str, ctx: Ctx, db: Db):
    s = await sessions.get(db, sid)
    d = sessions.to_dict(s)
    d["stale"] = await sessions.is_stale(ctx, s)
    return d


@router.post("/sessions/registry", status_code=201)
async def open_registry(req: SignedRequest, ctx: Ctx, db: Db):
    v = require_seat(await verify_and_claim(db, req, DOMAIN_MEMBER_ACTION), ctx.config, members_only=True)
    if await pause_svc.is_paused(db):
        raise HTTPException(409, "paused")
    out = await records.open_registry_session(ctx, db, v.actor)
    await db.commit()
    return out


@router.post("/sessions/anchor", status_code=201)
async def open_anchor(req: SignedRequest, ctx: Ctx, db: Db):
    v = require_seat(await verify_and_claim(db, req, DOMAIN_MEMBER_ACTION), ctx.config)
    if await pause_svc.is_paused(db):
        raise HTTPException(409, "paused")
    out = await records.open_anchor_session(ctx, db, v.actor)
    await db.commit()
    return out


@router.post("/sessions/{sid}/approve", status_code=201)
async def approve_session(sid: str, req: SignedRequest, ctx: Ctx, db: Db):
    """payload = {session_id, ops_digest}; signed under the ops-approval domain by a keyset key."""
    v = require_seat(await verify_and_claim(db, req, DOMAIN_OPS_APPROVAL), ctx.config, right="sign_statechain")
    s = await sessions.get(db, sid)
    await sessions.approve(ctx, db, s, v)
    await db.commit()
    return sessions.to_dict(s)


@router.post("/sessions/{sid}/rebuild")
async def rebuild_session(sid: str, req: SignedRequest, ctx: Ctx, db: Db):
    v = require_seat(await verify_and_claim(db, req, DOMAIN_MEMBER_ACTION), ctx.config, right="sign_statechain")
    s = await sessions.get(db, sid)
    if s.status not in ("approving", "signing") or len(s.approvals) < s.required_approvals:
        raise HTTPException(409, "session is not ready to build a block")
    await sessions.rebuild(ctx, db, s, actor=v.actor)
    await db.commit()
    return sessions.to_dict(s)


@router.post("/sessions/{sid}/sign", status_code=201)
async def sign_session_block(sid: str, req: SignedRequest, ctx: Ctx, db: Db):
    """payload = {block_hash, block_signature}. The outer SignedRequest proves the seat; the inner
    block_signature is the raw ed25519 signature over the block hash bytes that goes on chain."""
    v = require_seat(await verify_and_claim(db, req, DOMAIN_MEMBER_ACTION), ctx.config, right="sign_statechain")
    s = await sessions.get(db, sid)
    if v.payload.get("block_hash") != s.block_hash:
        raise HTTPException(409, "block hash has changed (tip moved); fetch the session again and re-sign")
    await sessions.sign(ctx, db, s, v.pub_key, v.payload.get("block_signature", ""), v.actor)
    await db.commit()
    return sessions.to_dict(s)


@router.post("/sessions/{sid}/cancel")
async def cancel_session(sid: str, req: SignedRequest, ctx: Ctx, db: Db):
    v = require_seat(await verify_and_claim(db, req, DOMAIN_MEMBER_ACTION), ctx.config, members_only=True)
    s = await sessions.get(db, sid)
    await sessions.cancel(ctx, db, s, v, clean_text(v.payload.get("reason"), "reason", max_len=2000, required=False))
    await db.commit()
    return sessions.to_dict(s)


# ---- pause ------------------------------------------------------------------------------------

@router.post("/pause", status_code=201)
async def start_pause(req: SignedRequest, ctx: Ctx, db: Db):
    v = require_seat(await verify_and_claim(db, req, DOMAIN_MEMBER_ACTION), ctx.config, right="pause", members_only=True)
    r = await pause_svc.start(ctx, db, v)
    await db.commit()
    return pause_svc.to_dict(r)


@router.post("/pause/{pid}/extend")
async def extend_pause(pid: str, req: SignedRequest, ctx: Ctx, db: Db):
    v = require_seat(await verify_and_claim(db, req, DOMAIN_MEMBER_ACTION), ctx.config, right="pause", members_only=True)
    r = await _pause(db, pid)
    await pause_svc.extend(ctx, db, r, v)
    await db.commit()
    return pause_svc.to_dict(r)


@router.post("/pause/{pid}/lift")
async def lift_pause(pid: str, req: SignedRequest, ctx: Ctx, db: Db):
    v = require_seat(await verify_and_claim(db, req, DOMAIN_MEMBER_ACTION), ctx.config, right="pause", members_only=True)
    r = await _pause(db, pid)
    await pause_svc.lift(ctx, db, r, v)
    await db.commit()
    return pause_svc.to_dict(r)


@router.post("/pause/{pid}/post")
async def pause_post(pid: str, req: SignedRequest, ctx: Ctx, db: Db):
    v = require_seat(await verify_and_claim(db, req, DOMAIN_MEMBER_ACTION), ctx.config, members_only=True)
    r = await _pause(db, pid)
    await pause_svc.set_post(ctx, db, r, v)
    await db.commit()
    return pause_svc.to_dict(r)


async def _pause(db, pid: str):
    from sqlalchemy import select
    from ..models import PauseRecord
    r = (await db.execute(select(PauseRecord).where(PauseRecord.id == pid))).scalar_one_or_none()
    if r is None:
        raise HTTPException(404, "pause not found")
    return r


# ---- inbox handling ---------------------------------------------------------------------------

@router.get("/inbox")
async def inbox_all(db: Db, status: str | None = None, limit: int = 200):
    rows = await inbox_svc.list_messages(db, status, limit)
    return {"messages": [inbox_svc.to_dict(m) for m in rows]}


@router.post("/inbox/{mid}/reply", status_code=201)
async def inbox_reply(mid: str, req: SignedRequest, ctx: Ctx, db: Db):
    v = require_seat(await verify_and_claim(db, req, DOMAIN_MEMBER_ACTION), ctx.config)
    m = await inbox_svc.get(db, mid)
    o = await inbox_svc.reply(ctx, db, m, v)
    await db.commit()
    return {"queued": o.id, "to": o.to_account}


@router.post("/inbox/{mid}/status")
async def inbox_status(mid: str, req: SignedRequest, ctx: Ctx, db: Db):
    v = require_seat(await verify_and_claim(db, req, DOMAIN_MEMBER_ACTION), ctx.config)
    m = await inbox_svc.get(db, mid)
    await inbox_svc.set_status(ctx, db, m, v)
    await db.commit()
    return inbox_svc.to_dict(m)


# ---- notes ------------------------------------------------------------------------------------

@router.post("/notes", status_code=201)
async def post_note(req: SignedRequest, ctx: Ctx, db: Db):
    """A signed public note from a seat holder, straight into the log (daily notes, explanations)."""
    v = require_seat(await verify_and_claim(db, req, DOMAIN_MEMBER_ACTION), ctx.config)
    text = clean_text(v.payload.get("text"), "text", max_len=20_000)
    title = clean_text(v.payload.get("title"), "title", max_len=160, required=False)
    ev = await ctx.events.append(db, "note", v.actor, {"title": title, "text": text,
                                                       "signature": v.signature, "timestamp": v.timestamp})
    await db.commit()
    return {"index": ev.index, "hash": ev.hash}
