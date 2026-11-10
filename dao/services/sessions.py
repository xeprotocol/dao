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
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from xe.client import XeError
from xe.keys import KeyError_, is_valid_public_key, verify_hex_signature
from xe.statechain import StateBlock, StateChainError, StateOp, build_block, check_ops_fit, validate_keyset

from ..auth import Verified
from ..canonical import canonical_json, sha256_hex
from ..context import Context
from ..models import Anchor, SigningSession
from . import pause

KINDS = {"registry", "anchor", "parameter", "keyset"}
KEYSET_KEY = "sys.dao_keyset"
SIGN_RIGHT = "sign_statechain"   # the seat right that lets a key approve ops and sign a block
KEY_HEX_RE = re.compile(r"[0-9a-f]{64}")
MAX_KEYSET = 16
MAX_OPS = 32


def check_ops(kind: str, ops: list[dict], seat_keys: set[str] | None = None) -> None:
    """What a session of this kind may write. Every kind but `keyset` writes the harness's own `dao.*` keys.
    A `keyset` session is the one route to a `sys.*` key and it is exactly one op: set `sys.dao_keyset` to
    a well-formed keyset the seats can meet. The same check runs when a resolution is proposed and when a
    proposal is submitted (`check_proposal_ops`), so nothing can pass a vote and then be refused at
    execution (XE-0349, XE-1650)."""
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
    _check_keyset(json.loads(parsed[0].value), seat_keys)


def check_proposal_ops(ops: list[dict], seat_keys: set[str] | None = None) -> None:
    """A proposal names no session kind, so its ops must be ones *some* kind could authorise: all `dao.*`
    keys (any kind but keyset), or exactly the one keyset op. Otherwise the vote is spent on ops no
    resolution can carry and adoption refuses forever (XE-1650)."""
    parsed = _ops_from_json(ops)
    if any(o.key == KEYSET_KEY for o in parsed):
        check_ops("keyset", ops, seat_keys)
    else:
        check_ops("parameter", ops, seat_keys)


def seat_keys_of(config) -> set[str]:
    """The keys a keyset may ask signatures from: those held by a human seat the routes let approve and
    sign a state-chain block (`SIGN_RIGHT`, the right `dao.api.members` requires on both). A seat that
    holds a key and not the right can do neither, so a keyset whose threshold leans on it is one the
    seats cannot meet (XE-2028, the same deadlock as XE-1705 by another door)."""
    return {s.public_key for s in config.human_seats if s.public_key and s.can(SIGN_RIGHT)}


def _check_keyset(value, seat_keys: set[str] | None = None) -> None:
    """The node's rule for `sys.dao_keyset`, as the protocol mirror states it (`xe.statechain.validate_keyset`:
    distinct keys, threshold between MIN_DAO_THRESHOLD and the key count), plus what the harness asks on
    top: the shape, lowercase hex, at most MAX_KEYSET keys, and every key a usable ed25519 point. A key
    nobody can sign with, if the threshold needs it, would leave the chain with no valid signer (XE-0694).
    The gate states no bound of its own, so it cannot be looser than the node on any of them (XE-1447).
    When the seats' keys are given, at least `threshold` of the keyset's keys must be seat keys: a keyset
    the seats cannot meet would end every later session, including the one to fix it (XE-1705)."""
    if not isinstance(value, dict) or set(value) != {"keys", "threshold"}:
        raise HTTPException(400, "keyset value must be {keys: [...], threshold: n}")
    keys, threshold = value["keys"], value["threshold"]
    if not isinstance(keys, list) or len(keys) > MAX_KEYSET:
        raise HTTPException(400, f"keyset holds at most {MAX_KEYSET} keys")
    if any(not isinstance(k, str) or not KEY_HEX_RE.fullmatch(k) for k in keys):
        raise HTTPException(400, "every keyset key is 64 lowercase hex digits")
    if not isinstance(threshold, int) or isinstance(threshold, bool):
        raise HTTPException(400, "keyset threshold must be an integer")
    try:
        validate_keyset(value)
    except StateChainError as e:
        raise HTTPException(400, f"keyset: {e}") from e
    for k in keys:
        if not is_valid_public_key(bytes.fromhex(k)):
            raise HTTPException(400, f"{k[:12]}… is not a usable ed25519 public key")
    if seat_keys is not None:
        held = sum(1 for k in keys if k in seat_keys)
        if held < threshold:
            raise HTTPException(400, f"keyset needs {threshold} signatures but only {held} of its keys are held by a seat; "
                                     "the seats could never meet it, nor change it back")


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
    try:
        check_ops_fit(_ops_from_json(out))   # the node bounds the block, not only each op (XE-1917)
    except StateChainError as e:
        raise HTTPException(400, f"ops are malformed: {e}") from e
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
    """`sys.dao_keyset` as the node serves it now: lower-case keys and an integer threshold, both checked
    by the client. A keyset without a threshold is malformed, not a 2-of-n."""
    ks = await ctx.chain.dao_keyset()
    return {"keys": [k.lower() for k in ks["keys"]], "threshold": ks["threshold"]}


async def create(ctx: Context, db: AsyncSession, *, kind: str, title: str, ops: list[dict], actor: str,
                 resolution_id: str = "", not_before: int | None = None) -> SigningSession:
    if kind not in KINDS:
        raise HTTPException(400, f"unknown session kind {kind!r}")
    ops = normalise_ops(ops)
    check_ops(kind, ops, seat_keys_of(ctx.config))
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


OPEN = ("approving", "signing")


async def list_sessions(db: AsyncSession, status: str | None = None, limit: int = 100, offset: int = 0) -> list[SigningSession]:
    """A page of sessions, newest first, for listings. Not for deciding whether something is pending: a
    page cannot see past its own end, and sessions are never deleted (XE-1561). Ask `open_sessions`."""
    q = select(SigningSession).order_by(SigningSession.created_at.desc()).offset(offset).limit(limit)
    if status:
        q = q.where(SigningSession.status == status)
    return list((await db.execute(q)).scalars().all())


async def count_sessions(db: AsyncSession, status: str | None = None) -> int:
    q = select(func.count()).select_from(SigningSession)
    if status:
        q = q.where(SigningSession.status == status)
    return int((await db.execute(q)).scalar_one())


async def open_sessions(db: AsyncSession, kind: str | None = None) -> list[SigningSession]:
    """Every session still approving or signing, unpaged, oldest first; optionally of one kind."""
    q = select(SigningSession).where(SigningSession.status.in_(OPEN)).order_by(SigningSession.created_at.asc())
    if kind:
        q = q.where(SigningSession.kind == kind)
    return list((await db.execute(q)).scalars().all())


def approvals_met(s: SigningSession, ks: dict) -> bool:
    """Enough approvals from keys that are in the keyset now. A key rotated out takes its approval with it,
    and a raised threshold applies to sessions already open; the figure stored at creation is a record."""
    live = {k.lower() for k in ks["keys"]}
    return sum(1 for a in s.approvals if a["public_key"] in live) >= int(ks["threshold"])


def signatures_met(s: SigningSession, ks: dict) -> bool:
    """The same count on the block's signatures: enough of them from keys that are in the keyset now. Every
    place that asks whether the block can go to the chain asks this, so a signature from a key rotated out
    since it was given is counted nowhere (XE-2713)."""
    live = {k.lower() for k in ks["keys"]}
    return sum(1 for x in s.block_signatures if x["public_key"] in live) >= int(ks["threshold"])


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
        try:
            await rebuild(ctx, db, s, actor="harness")
        except XeError as e:
            # The approval is on the record; building the block needs the node and the node did not answer.
            # The worker's timer pass builds it when the node is back (XE-1713).
            await ctx.events.append(db, "session.build_deferred", "harness",
                                    {"session_id": s.id, "error": str(e)[:300]}, ref=f"session:{s.id}")
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
    if s.status == "signing" and await landed(ctx, s):
        # The tip moved because this block is the tip: rebuilding would write the same ops twice (XE-1511).
        return await _submitted(ctx, db, s)
    require_timelock_run(s)
    await require_unpaused(db)
    ks = await live_keyset(ctx)
    if not approvals_met(s, ks):
        if s.status == "signing":
            # The keyset moved under a session that was already approved (a rotation landed first): the
            # approvals it holds no longer meet the live threshold. It goes back to approving rather than
            # sitting in signing with a block nobody may sign; the new keys approve and it proceeds (XE-0988).
            s.block, s.block_hash, s.block_signatures, s.status = None, "", [], "approving"
            await ctx.events.append(db, "session.reapproval_needed", actor, {
                "session_id": s.id, "ops_digest": s.ops_digest, "approvals": len(s.approvals), "required": ks["threshold"],
                "live_approvals": sum(1 for a in s.approvals if a["public_key"] in ks["keys"]),
            }, ref=f"session:{s.id}")
            return s
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


async def rebuild_if_stale(ctx: Context, db: AsyncSession, s: SigningSession, actor: str) -> SigningSession:
    """A member-requested rebuild. The first build of an approved session is always allowed; once a block
    exists it is rebuilt only when the tip has moved, because a rebuild discards every signature collected
    and at an unchanged tip one seat could loop it and stall signing for good (XE-0882)."""
    if s.status == "signing" and not await is_stale(ctx, s):
        raise HTTPException(409, "the block is current; collected signatures stand")
    return await rebuild(ctx, db, s, actor=actor)


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
    if signatures_met(s, ks):
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


async def landed(ctx: Context, s: SigningSession) -> bool:
    """Whether the session's block is on the chain at its index. The chain is the record of what happened;
    the node's answer to a submit is not: it can refuse after it has applied the block (a gossip publish
    failing after AddBlock), and a session marked failed on that answer would say a rotation, a parameter
    change or an anchor did not happen when it did, with `failed` terminal and the anchor row gone
    (XE-1511). Raises if the chain cannot be read; the caller leaves the session as it is."""
    if not s.block:
        return False
    try:
        got = await ctx.chain.statechain_block(int(s.block["index"]))
    except XeError as e:
        if e.status == 404:
            return False
        raise
    return bool(got) and got.get("hash") == s.block_hash


async def _submitted(ctx: Context, db: AsyncSession, s: SigningSession) -> SigningSession:
    s.status = "submitted"
    s.submitted_index = int(s.block["index"])
    s.submitted_hash = s.block_hash
    await ctx.events.append(db, "session.submitted", "harness", {
        "session_id": s.id, "kind": s.kind, "index": s.submitted_index, "hash": s.submitted_hash, "ops": s.ops,
    }, ref=f"session:{s.id}")
    return s


TIP_MOVED = ("prev", "index", "tip", "stale", "not the next")
KEYSET_MOVED = ("keyset", "signer", "signature")


def ready_to_submit(s: SigningSession, ks: dict) -> bool:
    """A signing session holding a threshold of live signatures over its block: its submit is owed to the chain."""
    return s.status == "signing" and bool(s.block) and signatures_met(s, ks)


async def submit(ctx: Context, db: AsyncSession, s: SigningSession) -> SigningSession:
    """Submit the signed block. A node failure never escapes and never, on its own, ends the session: only
    a refusal that is about the block, from a node that answered and whose chain does not hold the block,
    sets `failed`. Everything else leaves the session `signing` with the error on record, and the worker
    submits it again (XE-1511, XE-1677, XE-1689, XE-1817)."""
    require_timelock_run(s)
    await require_unpaused(db)
    blk = _block_from_session(s)
    try:
        await ctx.chain.submit_statechain_block(blk)
    except XeError as e:
        return await _refused(ctx, db, s, e)
    return await _submitted(ctx, db, s)


async def _refused(ctx: Context, db: AsyncSession, s: SigningSession, e: XeError) -> SigningSession:
    # Before believing a refusal, ask the chain. If the block is there, it was accepted.
    try:
        if await landed(ctx, s):
            return await _submitted(ctx, db, s)
    except XeError as read_err:
        return await _deferred(ctx, db, s, f"submit: {e}; could not confirm against the chain: {read_err}")
    if e.transient:
        # 429, 5xx, no answer: the node said nothing about the block.
        return await _deferred(ctx, db, s, f"submit: {e}")
    msg = str(e).lower()
    if any(w in msg for w in TIP_MOVED) or any(w in msg for w in KEYSET_MOVED):
        # The chain moved under the block (its tip, or the keyset it is checked against): rebuild on what is
        # live. A rotation that leaves the approvals short sends it back to approving (XE-0988).
        kind = "session.tip_moved" if any(w in msg for w in TIP_MOVED) else "session.keyset_moved"
        await ctx.events.append(db, kind, "harness", {"session_id": s.id, "error": str(e), "block_hash": s.block_hash},
                                ref=f"session:{s.id}")
        try:
            await rebuild(ctx, db, s)
        except XeError as build_err:
            return await _deferred(ctx, db, s, f"submit: {e}; rebuild: {build_err}")
        return s
    s.status = "failed"
    s.error = str(e)
    await _ended(db, s)
    await ctx.events.append(db, "session.failed", "harness", {"session_id": s.id, "error": str(e)}, ref=f"session:{s.id}")
    return s


async def _deferred(ctx: Context, db: AsyncSession, s: SigningSession, error: str) -> SigningSession:
    s.error = error[:500]
    await ctx.events.append(db, "session.submit_deferred", "harness", {"session_id": s.id, "error": error[:300]},
                            ref=f"session:{s.id}")
    return s


async def cancel(ctx: Context, db: AsyncSession, s: SigningSession, v: Verified, reason: str) -> SigningSession:
    """A member ends a session. One that holds a block is first checked against the chain: a block that
    landed is recorded as submitted, not cancelled, whatever the node said at the time (XE-1843, as for
    rebuild and submit). If the chain cannot be read the cancel waits (502). The answer carries the
    session as it now stands."""
    if s.status in ("submitted", "cancelled"):
        raise HTTPException(409, f"session is {s.status}")
    if s.status == "signing" and await landed(ctx, s):
        return await _submitted(ctx, db, s)
    s.status = "cancelled"
    s.error = reason
    await _ended(db, s)
    await ctx.events.append(db, "session.cancelled", v.actor, {"session_id": s.id, "reason": reason}, ref=f"session:{s.id}")
    return s


async def _ended(db: AsyncSession, s: SigningSession) -> None:
    """A session that ends without reaching the chain leaves no record that says otherwise: the anchor row
    opened with it goes, so the register and the health check see only anchors that were written (XE-0990)."""
    if s.kind == "anchor":
        await db.execute(delete(Anchor).where(Anchor.session_id == s.id))


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
