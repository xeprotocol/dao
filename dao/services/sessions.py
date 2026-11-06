"""State-chain signing sessions, in two steps, because the tip moves every ten minutes.

  1. approving  keyset holders approve the *ops digest* (what will be written). Durable: an approval
                never expires with the tip.
  2. signing    the harness builds a block at the live tip and keyset holders sign its hash. If the
                tip moves before enough signatures land, the block is rebuilt and signatures reset.
                Approvals from step 1 stand, so nobody has to re-read anything.
  → submitted / failed / cancelled

The harness holds no keyset key. It only assembles, counts, and submits.
"""

from __future__ import annotations

import json
import re
import secrets
import time

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from xe.client import XeError
from xe.keys import KeyError_, is_valid_public_key, verify_hex_signature
from xe.statechain import StateBlock, StateChainError, StateOp, build_block

from ..auth import Verified
from ..canonical import canonical_json, sha256_hex
from ..context import Context
from ..models import SigningSession
from . import pause

KINDS = {"registry", "anchor", "parameter", "keyset"}
KEYSET_KEY = "sys.dao_keyset"
KEY_HEX_RE = re.compile(r"[0-9a-f]{64}")
MAX_KEYSET = 16
MAX_OPS = 32


def check_ops(kind: str, ops: list[dict]) -> None:
    """What a session of this kind may write. Every kind but `keyset` writes the harness's own `dao.*` keys.
    A `keyset` session is the one route to a `sys.*` key and it is exactly one op: set `sys.dao_keyset` to
    a well-formed keyset. The same check runs when a resolution is proposed, so nothing can pass a vote and
    then be refused at execution (XE-0349)."""
    parsed = _ops_from_json(ops)
    for o in parsed:
        o.validate()
    if kind != "keyset":
        for o in parsed:
            if not o.key.startswith("dao."):
                raise HTTPException(400, f"harness sessions may only write dao.* keys (got {o.key})")
        return
    if len(parsed) != 1 or parsed[0].action != "set" or parsed[0].key != KEYSET_KEY:
        raise HTTPException(400, f"a keyset session is exactly one op: set {KEYSET_KEY}")
    _check_keyset(json.loads(parsed[0].value))


def _check_keyset(value) -> None:
    """keys: 2..MAX_KEYSET distinct lowercase hex ed25519 public keys, each a usable point; threshold 1..len.
    A key nobody can sign with, if the threshold needs it, would leave the chain with no valid signer
    (XE-0694 on the node side; checked here before the block is ever built)."""
    if not isinstance(value, dict) or set(value) != {"keys", "threshold"}:
        raise HTTPException(400, "keyset value must be {keys: [...], threshold: n}")
    keys, threshold = value["keys"], value["threshold"]
    if not isinstance(keys, list) or not 2 <= len(keys) <= MAX_KEYSET:
        raise HTTPException(400, f"keyset needs 2 to {MAX_KEYSET} keys")
    if any(not isinstance(k, str) or not KEY_HEX_RE.fullmatch(k) for k in keys):
        raise HTTPException(400, "every keyset key is 64 lowercase hex digits")
    if len(set(keys)) != len(keys):
        raise HTTPException(400, "keyset keys must be distinct")
    for k in keys:
        if not is_valid_public_key(bytes.fromhex(k)):
            raise HTTPException(400, f"{k[:12]}… is not a usable ed25519 public key")
    if not isinstance(threshold, int) or isinstance(threshold, bool) or not 1 <= threshold <= len(keys):
        raise HTTPException(400, "keyset threshold must be between 1 and the number of keys")


def ops_digest(ops: list[dict]) -> str:
    return sha256_hex(canonical_json(ops))


def normalise_ops(ops) -> list[dict]:
    """Store `value` as the exact compact JSON text that will be hashed. JSONB reorders object keys,
    so values must never be stored as parsed objects. Every op is validated as the node would, so a
    proposal or resolution cannot carry ops that could never be written."""
    if not isinstance(ops, list) or not ops:
        raise HTTPException(400, "ops must be a non-empty list")
    if len(ops) > MAX_OPS:
        raise HTTPException(400, f"at most {MAX_OPS} ops")
    out = []
    for o in ops:
        if not isinstance(o, dict) or not isinstance(o.get("action"), str) or not isinstance(o.get("key"), str):
            raise HTTPException(400, "each op is an object with a string action and key")
        try:
            op = StateOp.from_json(o)
            op.validate()
        except (StateChainError, TypeError, ValueError) as e:
            raise HTTPException(400, f"ops are malformed: {e}") from e
        d = {"action": op.action, "key": op.key}
        if op.action == "set":
            d["value"] = op.value
        out.append(d)
    return out


def _ops_from_json(ops: list[dict]) -> list[StateOp]:
    return [StateOp(o["action"], o["key"], o.get("value")) for o in ops]


def _block_from_session(s: SigningSession) -> StateBlock:
    blk = StateBlock(index=int(s.block["index"]), prev_hash=s.block["prev_hash"], ops=_ops_from_json(s.ops),
                     timestamp=int(s.block["timestamp"]), signatures=list(s.block_signatures))
    blk.hash = s.block_hash
    return blk


async def require_unpaused(db: AsyncSession) -> None:
    """Approving a session is record-keeping and stays open during a pause; building, signing and
    submitting a block are the company acting on the chain and stop. Lifted pauses release them."""
    if await pause.is_paused(db):
        raise HTTPException(409, "paused: no state-chain block is built, signed or submitted while a pause is active")


async def live_keyset(ctx: Context) -> dict:
    ks = await ctx.chain.dao_keyset()
    keys = [k.lower() for k in (ks.get("keys") or [])]
    return {"keys": keys, "threshold": int(ks.get("threshold", 2))}


async def create(ctx: Context, db: AsyncSession, *, kind: str, title: str, ops: list[dict], actor: str,
                 resolution_id: str = "", not_before: int | None = None) -> SigningSession:
    if kind not in KINDS:
        raise HTTPException(400, f"unknown session kind {kind!r}")
    ops = normalise_ops(ops)
    check_ops(kind, ops)
    ks = await live_keyset(ctx)
    s = SigningSession(id=secrets.token_hex(8), kind=kind, title=title, ops=ops, ops_digest=ops_digest(ops),
                       status="approving", approvals=[], required_approvals=ks["threshold"], block=None,
                       block_hash="", block_signatures=[], rebuilds=0, resolution_id=resolution_id,
                       not_before=not_before)
    db.add(s)
    await ctx.events.append(db, "session.created", actor, {
        "session_id": s.id, "kind": kind, "title": title, "ops": ops, "ops_digest": s.ops_digest,
        "required_approvals": s.required_approvals, "keyset_keys": ks["keys"], "resolution_id": resolution_id,
        "not_before": not_before,
    }, ref=f"session:{s.id}")
    return s


async def get(db: AsyncSession, session_id: str, *, lock: bool = False) -> SigningSession:
    """`lock=True` takes the row FOR UPDATE: every path that changes a session loads it this way, so two
    writers queue instead of each saving its own copy of a list over the other's (XE-0672)."""
    q = select(SigningSession).where(SigningSession.id == session_id)
    s = (await db.execute(q.with_for_update() if lock else q)).scalar_one_or_none()
    if s is None:
        raise HTTPException(404, "session not found")
    return s


async def list_sessions(db: AsyncSession, status: str | None = None, limit: int = 100) -> list[SigningSession]:
    q = select(SigningSession).order_by(SigningSession.created_at.desc()).limit(limit)
    if status:
        q = q.where(SigningSession.status == status)
    return list((await db.execute(q)).scalars().all())


def approvals_met(s: SigningSession, ks: dict) -> bool:
    """Enough approvals from keys that are in the keyset now. A key rotated out takes its approval with it,
    and a raised threshold applies to sessions already open; the figure stored at creation is a record."""
    live = {k.lower() for k in ks["keys"]}
    return sum(1 for a in s.approvals if a["public_key"] in live) >= int(ks["threshold"])


async def approve(ctx: Context, db: AsyncSession, s: SigningSession, v: Verified) -> SigningSession:
    """`v.payload` must be {"session_id", "ops_digest"} and signed by a keyset key (checked via the
    member-action domain by the router); here we additionally require keyset membership."""
    if s.status != "approving":
        raise HTTPException(409, f"session is {s.status}, not approving")
    ks = await live_keyset(ctx)
    if v.pub_key not in ks["keys"]:
        raise HTTPException(403, "this key is not in the live sys.dao_keyset")
    if v.payload.get("ops_digest") != s.ops_digest or v.payload.get("session_id") != s.id:
        raise HTTPException(400, "approval payload does not match this session")
    if any(a["public_key"] == v.pub_key for a in s.approvals):
        raise HTTPException(409, "already approved by this key")
    s.approvals = [*s.approvals, {"public_key": v.pub_key, "signature": v.signature, "timestamp": v.timestamp,
                                  "seat": v.seat.id if v.seat else ""}]
    await ctx.events.append(db, "session.approved", v.actor, {
        "session_id": s.id, "ops_digest": s.ops_digest, "approvals": len(s.approvals), "required": ks["threshold"],
    }, ref=f"session:{s.id}")
    if approvals_met(s, ks):
        now = time.time_ns()
        if (s.not_before and now < s.not_before) or await pause.is_paused(db):
            # timelock or pause: stay in approving; the worker's timer job promotes it when clear
            return s
        await rebuild(ctx, db, s, actor="harness")
    return s


def require_timelock_run(s: SigningSession) -> None:
    """The upgrade timelock is the window between adoption and execution in which members can still cancel.
    Every path that moves a session towards the chain checks it here, so no route can shorten it (XE-0284)."""
    now = time.time_ns()
    if s.not_before and now < s.not_before:
        left = (s.not_before - now) // 1_000_000_000
        raise HTTPException(409, f"the upgrade timelock on this session runs for another {left // 3600}h {left % 3600 // 60}m")


async def rebuild(ctx: Context, db: AsyncSession, s: SigningSession, actor: str = "harness") -> SigningSession:
    """Build (or re-build) the block at the live tip. Resets block signatures. Only an approved session,
    counted against the keyset as it is now, and not before the timelock has run."""
    if s.status not in ("approving", "signing"):
        raise HTTPException(409, f"session is {s.status}")
    require_timelock_run(s)
    await require_unpaused(db)
    if not approvals_met(s, await live_keyset(ctx)):
        raise HTTPException(409, "the session does not hold enough approvals from the live keyset")
    try:
        tip = await ctx.chain.statechain_tip()
    except XeError as e:
        if e.status == 404:
            tip = None
        else:
            raise
    blk = build_block(tip, _ops_from_json(s.ops), time.time_ns())
    s.block = {"index": blk.index, "prev_hash": blk.prev_hash, "timestamp": blk.timestamp, "hash": blk.hash}
    s.block_hash = blk.hash
    s.block_signatures = []
    s.rebuilds = (s.rebuilds or 0) + (1 if s.status == "signing" else 0)
    s.status = "signing"
    await ctx.events.append(db, "session.block_built", actor, {
        "session_id": s.id, "index": blk.index, "prev_hash": blk.prev_hash, "block_hash": blk.hash,
        "rebuilds": s.rebuilds,
    }, ref=f"session:{s.id}")
    return s


async def sign(ctx: Context, db: AsyncSession, s: SigningSession, pub_key: str, signature: str, actor: str) -> SigningSession:
    """Collect a raw ed25519 signature over the block hash from a keyset key. Submit when enough."""
    if s.status != "signing":
        raise HTTPException(409, f"session is {s.status}, not signing")
    require_timelock_run(s)
    await require_unpaused(db)
    pub_key = pub_key.lower()
    ks = await live_keyset(ctx)
    if pub_key not in ks["keys"]:
        raise HTTPException(403, "this key is not in the live sys.dao_keyset")
    try:
        verify_hex_signature(pub_key, signature, bytes.fromhex(s.block_hash))
    except KeyError_ as e:
        raise HTTPException(401, f"signature does not verify over block hash: {e}") from e
    if any(x["public_key"] == pub_key for x in s.block_signatures):
        raise HTTPException(409, "already signed by this key")
    s.block_signatures = [*s.block_signatures, {"public_key": pub_key, "signature": signature.lower()}]
    await ctx.events.append(db, "session.block_signed", actor, {
        "session_id": s.id, "block_hash": s.block_hash, "signatures": len(s.block_signatures), "required": ks["threshold"],
    }, ref=f"session:{s.id}")
    if len(s.block_signatures) >= ks["threshold"]:
        await submit(ctx, db, s)
    return s


async def is_stale(ctx: Context, s: SigningSession) -> bool:
    if s.status != "signing" or not s.block:
        return False
    try:
        tip = await ctx.chain.statechain_tip()
    except XeError as e:
        if e.status == 404:
            return False
        raise
    return tip.get("hash") != s.block["prev_hash"]


async def submit(ctx: Context, db: AsyncSession, s: SigningSession) -> SigningSession:
    require_timelock_run(s)
    await require_unpaused(db)
    blk = _block_from_session(s)
    try:
        await ctx.chain.submit_statechain_block(blk)
    except XeError as e:
        msg = str(e).lower()
        if any(w in msg for w in ("prev", "index", "tip", "stale", "not the next")):
            await ctx.events.append(db, "session.tip_moved", "harness", {
                "session_id": s.id, "error": str(e), "block_hash": s.block_hash,
            }, ref=f"session:{s.id}")
            await rebuild(ctx, db, s)
            return s
        s.status = "failed"
        s.error = str(e)
        await ctx.events.append(db, "session.failed", "harness", {"session_id": s.id, "error": str(e)}, ref=f"session:{s.id}")
        return s
    s.status = "submitted"
    s.submitted_index = blk.index
    s.submitted_hash = blk.hash
    await ctx.events.append(db, "session.submitted", "harness", {
        "session_id": s.id, "kind": s.kind, "index": blk.index, "hash": blk.hash, "ops": s.ops,
    }, ref=f"session:{s.id}")
    return s


async def cancel(ctx: Context, db: AsyncSession, s: SigningSession, v: Verified, reason: str) -> SigningSession:
    if s.status in ("submitted", "cancelled"):
        raise HTTPException(409, f"session is {s.status}")
    s.status = "cancelled"
    s.error = reason
    await ctx.events.append(db, "session.cancelled", v.actor, {"session_id": s.id, "reason": reason}, ref=f"session:{s.id}")
    return s


def to_dict(s: SigningSession, public: bool = True) -> dict:
    d = {
        "id": s.id, "kind": s.kind, "title": s.title, "status": s.status, "ops": s.ops, "ops_digest": s.ops_digest,
        "approvals": [{"public_key": a["public_key"], "seat": a.get("seat", ""), "timestamp": a.get("timestamp")} for a in s.approvals],
        "required_approvals": s.required_approvals, "block": s.block, "block_hash": s.block_hash,
        "block_signatures": [x["public_key"] for x in s.block_signatures], "rebuilds": s.rebuilds,
        "submitted_index": s.submitted_index, "submitted_hash": s.submitted_hash, "error": s.error,
        "resolution_id": s.resolution_id, "not_before": s.not_before,
        "created_at": s.created_at.isoformat() if s.created_at else None,
    }
    return d
