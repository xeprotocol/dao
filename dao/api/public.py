"""/v1: the public surface. Public vocabulary (copy/public.yaml); nothing here uses company terms."""

from __future__ import annotations

import asyncio
import json
import time

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import RedirectResponse
from sse_starlette.sse import EventSourceResponse

from .. import __version__
from ..auth import SignedRequest, claim_signature, require_seat, verify_and_claim, verify_signed
from ..canonical import DOMAIN_INBOX_HTTP, DOMAIN_MEMBER_ACTION, DOMAIN_PROPOSAL, DOMAIN_VOTE
from ..db import session
from ..log import EventLog, event_to_dict
from ..ratelimit import INBOX, PROPOSAL, VOTE, enforce
from ..services import inbox as inbox_svc
from ..services import pause as pause_svc
from ..services import portal, records
from ..worker_schedule import next_runs
from .deps import Ctx, Db

router = APIRouter(prefix="/v1", tags=["public"])


@router.get("")
async def manifest(ctx: Ctx, db: Db):
    head = await EventLog.head(db)
    base = ctx.settings.public_base_url
    return {
        "name": "XE DAO",
        "network": ctx.node.badge,
        "network_id": ctx.node.network_id,
        "version": __version__,
        "git_commit": ctx.settings.git_commit,
        "mode": ctx.config.mode,
        "paused": await pause_svc.is_paused(db),
        "accounts": {
            "dao": inbox_svc.dao_account(ctx),
            "fee": portal.fee_account(ctx),
        },
        "log_head": {"index": head.index, "hash": head.hash},
        "endpoints": {
            "legal": f"{base}/v1/legal/identifier",
            "charter": f"{base}/v1/charter",
            "seats": f"{base}/v1/seats",
            "proposals": f"{base}/v1/proposals",
            "log": f"{base}/v1/log",
            "events": f"{base}/v1/events",
            "inbox": f"{base}/v1/inbox",
            "health": f"{base}/v1/health",
            "schedule": f"{base}/v1/schedule/next",
        },
        "signing": {
            "method": "ed25519 over sha256(domain || canonical_json({payload, timestamp}))",
            "domains": {
                "proposal": DOMAIN_PROPOSAL.decode().rstrip("\x00"),
                "vote": DOMAIN_VOTE.decode().rstrip("\x00"),
                "inbox": DOMAIN_INBOX_HTTP.decode().rstrip("\x00"),
                "member_action": DOMAIN_MEMBER_ACTION.decode().rstrip("\x00"),
            },
            "note": "domain bytes are the string followed by a single 0x00 byte",
        },
        "rules": ctx.config.pinned_rules(),
    }


@router.get("/charter")
async def charter(ctx: Ctx):
    return {"sha256": ctx.config.charter_hash, "markdown": ctx.config.charter_md}


@router.get("/seats")
async def seats(ctx: Ctx):
    return {
        "mode": ctx.config.mode,
        "people": [{"id": s.id, "name": s.name, "role": s.role, "public_key": s.public_key or None,
                    "account": s.account or None,
                    "page": f"{ctx.settings.public_base_url}/seats/{s.slug}"} for s in ctx.config.human_seats],
        "agents": [{"id": a.id, "role": a.role, "summary": a.summary, "class": a.cls, "status": a.status,
                    "model": a.model or None, "account": a.account or None, "tool_scopes": list(a.tool_scopes),
                    "prompt_hash": ctx.config.prompt_hash(a.id) or None,
                    "prompt": f"{ctx.settings.public_base_url}/v1/seats/{a.id}/prompt",
                    "page": f"{ctx.settings.public_base_url}/seats/{a.slug}"} for a in ctx.config.agent_seats],
        "tool_scopes": ctx.config.tool_scope_glossary,
        "preamble_hash": ctx.config.hashes.get("prompts/_preamble.md"),
        "note": "prompt_hash = sha256(preamble + seat prompt); recorded on every analysis a seat produces",
    }


@router.get("/seats/{seat_id}/prompt")
async def seat_prompt(seat_id: str, ctx: Ctx):
    """The exact text a seat is given: the shared preamble, then the seat prompt. Public, versioned, hashed."""
    body = ctx.config.prompts.get(seat_id)
    if body is None or seat_id.startswith("_"):
        raise HTTPException(404, "no prompt for this seat")
    return {"seat": seat_id, "hash": ctx.config.prompt_hash(seat_id),
            "preamble_hash": ctx.config.hashes.get("prompts/_preamble.md"),
            "seat_prompt_hash": ctx.config.hashes.get(f"prompts/{seat_id}.md"),
            "preamble": ctx.config.prompts.get("_preamble", ""), "prompt": body}


# ---- proposals and votes ----------------------------------------------------------------------

@router.get("/proposals")
async def list_proposals(db: Db, status: str | None = None, offset: int = 0, limit: int = 50):
    rows = await portal.list_proposals(db, status, offset, limit)
    return {"proposals": [portal.to_dict(p, include_body=False) for p in rows], "counts": await portal.counts(db)}


@router.post("/proposals", status_code=201)
async def submit_proposal(request: Request, req: SignedRequest, ctx: Ctx, db: Db):
    enforce(request, PROPOSAL)
    v = verify_signed(req, DOMAIN_PROPOSAL)
    enforce(request, PROPOSAL, v.account)
    await claim_signature(db, v)
    pr = await portal.submit(ctx, db, v)
    await db.commit()
    return portal.to_dict(pr)


@router.get("/proposals/{h}")
async def get_proposal(h: str, db: Db):
    pr = await portal.get(db, h)
    return portal.to_dict(pr, await portal.votes_for(db, pr.hash))


@router.get("/proposals/{h}/votes")
async def proposal_votes(h: str, db: Db):
    pr = await portal.get(db, h)
    votes = await portal.votes_for(db, pr.hash)
    return {"proposal": pr.hash, "tally": portal.tally(pr, votes),
            "votes": [{"account": v.account, "choice": v.choice, "weight": v.weight, "participating": v.participating,
                       "is_agent": v.is_agent, "timestamp": v.timestamp, "reason": v.reason, "signature": v.signature,
                       "pub_key": v.pub_key} for v in votes]}


@router.post("/proposals/{h}/votes", status_code=201)
async def cast_vote(request: Request, h: str, req: SignedRequest, ctx: Ctx, db: Db):
    enforce(request, VOTE)
    v = verify_signed(req, DOMAIN_VOTE)
    enforce(request, VOTE, v.account)
    await claim_signature(db, v)
    pr = await portal.get(db, h)
    row = await portal.vote(ctx, db, pr, v)
    await db.commit()
    return {"account": row.account, "choice": row.choice, "weight": row.weight, "participating": row.participating,
            "eligibility": row.eligibility}


@router.post("/votes", status_code=201)
async def cast_vote_flat(request: Request, req: SignedRequest, ctx: Ctx, db: Db):
    """Same as POST /proposals/{hash}/votes; the proposal hash comes from the signed payload."""
    enforce(request, VOTE)
    v = verify_signed(req, DOMAIN_VOTE)
    enforce(request, VOTE, v.account)
    await claim_signature(db, v)
    pr = await portal.get(db, v.payload.get("proposal", ""))
    row = await portal.vote(ctx, db, pr, v)
    await db.commit()
    return {"account": row.account, "choice": row.choice, "weight": row.weight, "participating": row.participating,
            "eligibility": row.eligibility}


@router.get("/decisions")
async def decisions(db: Db, limit: int = 50):
    rows = await portal.list_proposals(db, "decided", 0, limit)
    closed = await portal.list_proposals(db, "closed", 0, limit)
    return {"decided": [portal.to_dict(p, include_body=False) for p in rows],
            "awaiting_decision": [portal.to_dict(p, include_body=False) for p in closed]}


@router.get("/snapshot/{account}")
async def snapshot(account: str, ctx: Ctx, at: int | None = None):
    """What a wallet's weight and participation would be at time `at` (ns), default now."""
    from ..chainops import account_snapshot
    rules = ctx.config.pinned_rules()
    at = at or time.time_ns()
    snap = await account_snapshot(ctx.chain, account.lower(), at)
    pw = rules["participating_wallet"]
    return {"account": account.lower(), "at": at, **snap,
            "participating": snap["exists"] and snap["balance"] >= int(pw.get("min_balance_micro_xe", 0))
            and account.lower() not in set(rules["excluded_accounts"])}


# ---- inbox ------------------------------------------------------------------------------------

@router.get("/inbox")
async def inbox_info(ctx: Ctx, db: Db, limit: int = 50):
    rows = await inbox_svc.list_messages(db, None, limit)
    return {
        "account": inbox_svc.dao_account(ctx),
        "how": "send an XE chat envelope to the account above, or POST a signed message here with a proof of work",
        "pow": {
            "difficulty": f"0x{ctx.node.chat_pow_difficulty:016x}",
            "rule": "pow_nonce (u64) such that sha256(nonce_le8 || signing_digest)[0:8] read big-endian >= difficulty; "
                    "signing_digest = sha256(domain || 0x00 || canonical_json({payload, timestamp}))",
            "domain": DOMAIN_INBOX_HTTP.rstrip(b"\x00").decode(),
        },
        "logging": "messages sent here are kept in the hash chain on receipt and appear on the public log once a member has read them",
        "recent": [inbox_svc.to_dict(m) for m in rows if m.status != "spam"],
    }


@router.post("/inbox", status_code=201)
async def inbox_post(request: Request, req: SignedRequest, ctx: Ctx, db: Db):
    """Signed message plus a chat-level proof of work over the signing digest (see GET /v1/inbox for the rule)."""
    enforce(request, INBOX)
    v = verify_signed(req, DOMAIN_INBOX_HTTP)
    enforce(request, INBOX, v.account)
    await claim_signature(db, v)
    m = await inbox_svc.http_submit(ctx, db, v)
    await db.commit()
    return inbox_svc.to_dict(m)


@router.get("/inbox/{mid}")
async def inbox_get(mid: str, db: Db):
    m = await inbox_svc.get(db, mid)
    if m.status == "spam":
        raise HTTPException(404, "message not found")
    return inbox_svc.to_dict(m, await inbox_svc.replies_for(db, mid))


# ---- log --------------------------------------------------------------------------------------

@router.get("/log")
async def log_page(db: Db, offset: int = 0, limit: int = 100, kind: str | None = None, ref: str | None = None):
    rows = await EventLog.page(db, offset, limit, kind, ref)
    head = await EventLog.head(db)
    return {"head": {"index": head.index, "hash": head.hash}, "events": [event_to_dict(e) for e in rows]}


@router.get("/log/head")
async def log_head(ctx: Ctx, db: Db):
    head = await EventLog.head(db)
    return {"index": head.index, "hash": head.hash,
            "signer": ctx.signer.public_key("harness") if ctx.signer.has("harness") else None,
            "anchors": await records.anchors(db, 5)}


@router.get("/log/verify")
async def log_verify(db: Db):
    return await EventLog.verify(db)


@router.get("/log/{index}")
async def log_get(index: int, db: Db):
    ev = await EventLog.get(db, index)
    if ev is None or not ev.public:
        raise HTTPException(404, "no such event")
    return event_to_dict(ev)


@router.get("/events")
async def events_stream(request: Request, ctx: Ctx, db: Db, after: int | None = None):
    """Server-sent events. Each public log entry is sent as `event: entry` (kind inside the data) as it
    lands in the database, whichever process wrote it; `event: ping` every 15 s. Resumes from
    `Last-Event-ID` or `?after=<index>`. Browsers navigating here directly are sent to /live."""
    accept = request.headers.get("accept", "")
    if "text/html" in accept and "text/event-stream" not in accept:
        return RedirectResponse("/live", status_code=302)

    head = await EventLog.head(db)
    resume = request.headers.get("last-event-id")
    last_index = int(resume) if resume and resume.lstrip("-").isdigit() else (after if after is not None else head.index)
    wake: asyncio.Queue = asyncio.Queue(maxsize=1000)
    ctx.events.subscribe(wake)  # same-process appends shortcut the poll interval

    async def gen():
        nonlocal last_index
        idle_since = time.monotonic()
        try:
            while not await request.is_disconnected():
                async with session() as s:
                    rows = await EventLog.since(s, last_index)
                for ev in rows:
                    last_index = ev.index
                    idle_since = time.monotonic()
                    yield {"event": "entry", "id": str(ev.index), "data": json.dumps(event_to_dict(ev))}
                if time.monotonic() - idle_since >= 15:
                    idle_since = time.monotonic()
                    yield {"event": "ping", "data": json.dumps({"ts": time.time_ns(), "last": last_index})}
                try:
                    await asyncio.wait_for(wake.get(), timeout=3)
                    while not wake.empty():
                        wake.get_nowait()
                except asyncio.TimeoutError:
                    pass
        finally:
            ctx.events.unsubscribe(wake)

    return EventSourceResponse(gen())


# ---- schedule and health ----------------------------------------------------------------------

@router.get("/schedule/next")
async def schedule_next(ctx: Ctx, db: Db):
    return {"jobs": await next_runs(ctx, db)}


@router.get("/health")
async def health(ctx: Ctx, db: Db):
    last = await records.last_health(db)
    return {"ok": bool(last and last.get("ok")), "last_check": last, "uptime_30d": await records.uptime_30d(db),
            "paused": await pause_svc.is_paused(db)}


@router.get("/ready")
async def ready(ctx: Ctx, db: Db):
    try:
        await EventLog.head(db)
    except Exception as e:
        raise HTTPException(503, f"database not ready: {e}")
    return {"ready": True, "network_id": ctx.node.network_id}


# ---- signed member/officer actions on the public router (analysis, decision) -------------------

@router.post("/proposals/{h}/analysis", status_code=201)
async def proposal_analysis(h: str, req: SignedRequest, ctx: Ctx, db: Db):
    v = require_seat(await verify_and_claim(db, req, DOMAIN_MEMBER_ACTION), ctx.config)
    pr = await portal.get(db, h)
    await portal.add_analysis(ctx, db, pr, v)
    await db.commit()
    return portal.to_dict(pr)


@router.post("/proposals/{h}/decision", status_code=201)
async def proposal_decision(h: str, req: SignedRequest, ctx: Ctx, db: Db):
    v = require_seat(await verify_and_claim(db, req, DOMAIN_MEMBER_ACTION), ctx.config)
    if not (v.seat.is_member or v.seat.can("operational_review")):
        raise HTTPException(403, "decisions are recorded by members or an officer with operational_review")
    pr = await portal.get(db, h)
    await portal.decide(ctx, db, pr, v)
    await db.commit()
    return portal.to_dict(pr)
