"""The open portal: anyone proposes for a fee, anyone with XE votes, the result advises the DAO.

Rules are pinned to a proposal at open time (`proposal.rules`) so a later Schedule B change never
moves a live vote. Weight is the voter's XE balance at the snapshot, an hour before open. Quorum is a count of
participating wallets, not an amount of XE. Agents' weight is bounded and they never count toward
quorum. Nothing here executes anything: a passed proposal becomes a decision item for the DAO.
"""

from __future__ import annotations

import re
import time

from fastapi import HTTPException
from sqlalchemy import and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from xe.client import XeError

from ..auth import Verified, bind
from ..canonical import DOMAIN_PROPOSAL, canonical_json, sha256_hex
from ..chainops import account_snapshot, snapshot_time
from ..context import Context
from ..db import serialize
from ..models import FeeLedger, Proposal, Resolution, Vote
from ..text import clean_text, field_text
from . import sessions

D = 24 * 3600 * 1_000_000_000
MAX_TITLE = 160
MAX_BODY = 20_000
HEX64 = re.compile(r"[0-9a-f]{64}")
FINAL = ("adopt", "decline")


def fee_account(ctx: Context) -> str:
    if ctx.signer.has("fee"):
        return ctx.signer.address("fee")
    return ctx.config.accounts.get("fee", "")


def proposal_hash(author: str, title: str, body: str, ops, fee_block_hash: str, timestamp: int) -> str:
    return sha256_hex(DOMAIN_PROPOSAL + canonical_json({
        "author": author, "title": title, "body": body, "ops": ops, "fee_block_hash": fee_block_hash, "timestamp": timestamp,
    }))


async def _verify_fee(ctx: Context, db: AsyncSession, fee_block_hash: str, author: str, fee: int) -> dict:
    """The fee is a send block from the author to the fee account, ≥ fee, in XE, not already used."""
    if fee <= 0:
        return {"hash": "", "amount": 0}
    fee_acct = fee_account(ctx)
    if not fee_acct:
        raise HTTPException(503, "fee account is not configured")
    # Two submits reusing one block: the second waits here for the first to commit, then sees its row and
    # gets this 409 rather than losing on the unique key after the node read (XE-1290).
    await serialize(db, f"fee:{fee_block_hash}")
    used = (await db.execute(select(Proposal.hash).where(Proposal.fee_block_hash == fee_block_hash))).first()
    if used:
        raise HTTPException(409, "this fee block has already been used")
    try:
        b = await ctx.chain.block(fee_block_hash)
    except XeError as e:
        if e.status == 404:
            raise HTTPException(400, "fee block not found on the chain yet; wait for it to be seen and retry") from e
        raise HTTPException(502, f"node error reading fee block: {e}") from e
    if b.get("type") != "send":
        raise HTTPException(400, "fee block must be a send")
    if b.get("asset") != "XE":
        raise HTTPException(400, "fee must be paid in XE")
    if (b.get("destination") or "").lower() != fee_acct:
        raise HTTPException(400, f"fee must be sent to {fee_acct}")
    if (b.get("account") or "").lower() != author:
        raise HTTPException(400, "fee must be sent from the proposing account")
    if int(b.get("amount", 0)) < fee:
        raise HTTPException(400, f"fee is {fee} µXE; block sends {b.get('amount')}")
    if b.get("finalized") is not True:
        # A seen-but-unfinalised send can still be dropped by the node (xeprotocol/xe#55, XE-0034).
        # Accepting it would open a proposal whose fee may never arrive and later refund XE we never held.
        raise HTTPException(400, "fee block is not yet finalised; retry in a few seconds")
    return b


async def submit(ctx: Context, db: AsyncSession, v: Verified) -> Proposal:
    p = v.payload
    title = clean_text(p.get("title"), "title", max_len=MAX_TITLE)
    body = clean_text(p.get("body"), "body", max_len=MAX_BODY)
    ops = p.get("ops")
    fee_block_hash = field_text(p, "fee_block_hash").lower()
    if fee_block_hash and not HEX64.fullmatch(fee_block_hash):
        raise HTTPException(400, "fee_block_hash must be 64 hex characters")
    if ops is not None:
        ops = sessions.normalise_ops(ops)
    rules = ctx.config.pinned_rules()
    fee = int(rules["fee_micro_xe"])
    if fee and not fee_block_hash:
        raise HTTPException(400, f"a fee of {fee} µXE to {fee_account(ctx)} is required; include fee_block_hash")
    fee_block = await _verify_fee(ctx, db, fee_block_hash, v.account, fee)
    now = time.time_ns()
    h = proposal_hash(v.account, title, body, ops, fee_block_hash, v.timestamp)
    pr = Proposal(hash=h, title=title, body=body, ops=ops, author_account=v.account, author_pub_key=v.pub_key,
                  author_signature=v.signature, author_timestamp=v.timestamp, fee_block_hash=fee_block_hash or h,
                  status="open", opened_at=now, closes_at=now + int(rules["window_days"]) * D, rules=rules,
                  result=None, decision=None, analysis=[])
    db.add(pr)
    if fee:
        db.add(FeeLedger(fee_block_hash=fee_block_hash, proposal_hash=h, payer=v.account,
                         amount=int(fee_block.get("amount", 0)), state="seen", tx_hashes={}))
    await ctx.events.append(db, "proposal.opened", v.actor, {
        "proposal": h, "title": title, "body": body, "ops": ops, "author": v.account, "fee_block_hash": fee_block_hash,
        "opened_at": now, "snapshot_at": snapshot_time(now), "closes_at": pr.closes_at, "rules": rules,
    }, ref=f"proposal:{h}")
    return pr


async def get(db: AsyncSession, h: str, *, lock: bool = False) -> Proposal:
    """`lock=True` takes the row FOR UPDATE: every path that changes a proposal loads it this way, so two
    writers queue instead of each saving its own copy of a list over the other's (XE-0672)."""
    q = select(Proposal).where(Proposal.hash == h.lower())
    if lock:   # and read the row as it is now, even if an unlocked copy is already in this session (XE-0960)
        q = q.with_for_update().execution_options(populate_existing=True)
    pr = (await db.execute(q)).scalar_one_or_none()
    if pr is None:
        raise HTTPException(404, "proposal not found")
    return pr


async def list_proposals(db: AsyncSession, status: str | None = None, offset: int = 0, limit: int = 50) -> list[Proposal]:
    q = select(Proposal).order_by(Proposal.opened_at.desc()).offset(offset).limit(min(limit, 200))
    if status:
        q = q.where(Proposal.status == status)
    return list((await db.execute(q)).scalars().all())


async def awaiting_decision(db: AsyncSession, limit: int = 50) -> list[Proposal]:
    """Closed proposals with no decision, and decided ones whose decision was interim (deferred or referred)."""
    q = (select(Proposal).where(or_(Proposal.status == "closed",
                                    and_(Proposal.status == "decided", Proposal.decision["decision"].astext.notin_(FINAL))))
         .order_by(Proposal.opened_at.desc()).limit(min(limit, 200)))
    return list((await db.execute(q)).scalars().all())


# ---- votes ------------------------------------------------------------------------------------

def _open(pr: Proposal) -> None:
    if pr.status != "open" or time.time_ns() >= pr.closes_at:
        raise HTTPException(409, "voting is closed")


async def vote(ctx: Context, db: AsyncSession, pr: Proposal, v: Verified) -> Vote:
    """payload = {proposal, choice, reason?}. One vote per account; a later vote replaces an earlier one.

    The node read (the voter's snapshot) happens on an unlocked copy of the proposal; the write happens
    under row locks taken afterwards: the proposal FOR UPDATE, so a close that lands during the read is seen
    before anything is recorded, and the account's existing vote FOR UPDATE, so two votes from one account
    compare timestamps against the same row (XE-0960). Votes serialise for the write, not for the read."""
    _open(pr)
    choice = field_text(v.payload, "choice")
    if choice not in ("for", "against", "abstain"):
        raise HTTPException(400, "choice must be for | against | abstain")
    if field_text(v.payload, "proposal").lower() != pr.hash:
        raise HTTPException(400, "signed payload names a different proposal")
    rules = pr.rules
    pw = rules.get("participating_wallet", {})
    snap = await account_snapshot(ctx.chain, v.account, snapshot_time(pr.opened_at), rules.get("weight_asset", "XE"))
    is_agent = v.account in ctx.config.agent_accounts
    excluded = v.account in set(rules.get("excluded_accounts", []))
    reasons = []
    if excluded:
        reasons.append("excluded account")
    if pw.get("must_exist_before_open", True) and not snap["exists"]:
        reasons.append("account did not exist at the snapshot, an hour before the proposal opened")
    if snap["balance"] < int(pw.get("min_balance_micro_xe", 0)):
        reasons.append("balance below the participation minimum at snapshot")
    if is_agent and not rules.get("agents", {}).get("count_toward_quorum", False):
        reasons.append("agent accounts do not count toward quorum")
    participating = not reasons
    weight = 0 if excluded else int(snap["balance"])
    reason = clean_text(v.payload.get("reason"), "reason", max_len=2000, required=False)
    pr = await get(db, pr.hash, lock=True)
    _open(pr)
    existing = (await db.execute(select(Vote).where(Vote.proposal_hash == pr.hash, Vote.account == v.account)
                                 .with_for_update())).scalar_one_or_none()
    if existing:
        # Replacement is by signer time, not arrival: a vote signed earlier than the one on record is stale
        # and cannot overwrite it, whoever replays it and whenever (XE-0033).
        if v.timestamp <= existing.timestamp:
            raise HTTPException(409, "a newer vote from this account is already recorded")
        existing.choice, existing.reason, existing.timestamp, existing.signature = choice, reason, v.timestamp, v.signature
        existing.pub_key, existing.weight, existing.participating, existing.is_agent = v.pub_key, weight, participating, is_agent
        existing.eligibility = {"snapshot": snap, "not_participating_because": reasons}
        row = existing
    else:
        row = Vote(proposal_hash=pr.hash, account=v.account, pub_key=v.pub_key, choice=choice,
                   reason=reason, timestamp=v.timestamp, signature=v.signature, weight=weight,
                   participating=participating, is_agent=is_agent, eligibility={"snapshot": snap, "not_participating_because": reasons})
        db.add(row)
    await ctx.events.append(db, "vote.cast", v.actor, {
        "proposal": pr.hash, "account": v.account, "choice": choice, "weight": weight, "participating": participating,
        "is_agent": is_agent, "replaced": existing is not None, "reason": row.reason[:500],
    }, ref=f"proposal:{pr.hash}")
    return row


async def votes_for(db: AsyncSession, h: str) -> list[Vote]:
    return list((await db.execute(select(Vote).where(Vote.proposal_hash == h).order_by(Vote.timestamp.asc()))).scalars().all())


def tally(pr: Proposal, votes: list[Vote]) -> dict:
    rules = pr.rules
    agents = rules.get("agents", {})
    cap = float(agents.get("max_weight_share", 0.01))
    human = {"for": 0, "against": 0, "abstain": 0}
    agent = {"for": 0, "against": 0, "abstain": 0}
    participating = 0
    for v in votes:
        (agent if v.is_agent else human)[v.choice] += v.weight
        if v.participating:
            participating += 1
    # Agents may tip a human decision, never make one: their weight counts up to cap × the weight humans
    # decided with (for and against), scaled pro rata across their votes. Measured against the human
    # decision and not the total cast, so where humans only abstain, or vote dust, the agents count for
    # nothing and the proposal fails on `decided == 0` rather than passing on the agents alone (XE-1459).
    human_decided = human["for"] + human["against"]
    agent_total = sum(agent.values())
    agent_allowed = int(cap * human_decided) if agent_total else 0
    scale = min(1.0, agent_allowed / agent_total) if agent_total else 0.0
    counted = {k: human[k] + int(agent[k] * scale) for k in human}
    decided = counted["for"] + counted["against"]
    quorum = int(rules.get("quorum_wallets", 20))
    quorum_met = participating >= quorum
    pass_mark = float(rules.get("pass_mark_fraction", 0.5))
    passed = quorum_met and decided > 0 and (counted["for"] / decided) > pass_mark
    return {
        "votes": len(votes), "participating_wallets": participating, "quorum_wallets": quorum, "quorum_met": quorum_met,
        "weight": counted, "weight_human": human, "weight_agent_raw": agent, "agent_scale": round(scale, 6),
        "for_share": (counted["for"] / decided) if decided else 0.0, "pass_mark": pass_mark,
        "outcome": ("passed" if passed else ("failed" if quorum_met else "no_quorum")),
    }


async def close_due(ctx: Context, db: AsyncSession) -> list[Proposal]:
    """Worker: close proposals whose window has ended; record result; queue the fee action."""
    now = time.time_ns()
    due = list((await db.execute(select(Proposal).where(Proposal.status == "open", Proposal.closes_at <= now)
                                 .with_for_update(skip_locked=True))).scalars().all())
    for pr in due:
        res = tally(pr, await votes_for(db, pr.hash))
        pr.result = res
        pr.status = "closed"
        await ctx.events.append(db, "proposal.closed", "harness", {"proposal": pr.hash, "title": pr.title, "result": res}, ref=f"proposal:{pr.hash}")
        fee = (await db.execute(select(FeeLedger).where(FeeLedger.proposal_hash == pr.hash))).scalar_one_or_none()
        if fee and fee.state == "seen":
            action = pr.rules.get("fee_on_quorum", "refund") if res["quorum_met"] else pr.rules.get("fee_below_quorum", "burn")
            fee.state = f"due_{action}"
    return due


async def _decision_resolution(db: AsyncSession, pr: Proposal, res_id: str) -> Resolution:
    """A resolution named by a decision must exist, have passed, and be about this proposal (XE-0201)."""
    r = (await db.execute(select(Resolution).where(Resolution.id == res_id))).scalar_one_or_none()
    if r is None:
        raise HTTPException(400, "resolution_id names no resolution")
    if r.related_proposal != pr.hash:
        raise HTTPException(409, "that resolution is not about this proposal")
    if r.status != "passed":
        raise HTTPException(409, f"that resolution is {r.status}, not passed")
    return r


async def decide(ctx: Context, db: AsyncSession, pr: Proposal, v: Verified) -> Proposal:
    """The DAO's response to a closed proposal: adopt / decline / defer / refer_to_resolution, with reasons.
    Members or officers with operational_review may record it, once (XE-0201): the record is the DAO's
    published position, so a single seat key cannot flip it afterwards. `adopt` needs the vote to have
    passed; `adopt` of a proposal carrying state-chain ops also needs a passed resolution about this
    proposal that authorises exactly those ops. `decline`, `defer` and `refer_to_resolution` are recordable
    on any closed vote, including a failed or no-quorum one; the last two are interim and may be followed by
    one adopt or decline. Nothing here executes anything; ops still move only through a resolution and a
    signing session."""
    bind(v, proposal=pr.hash)
    decision = field_text(v.payload, "decision")
    if decision not in ("adopt", "decline", "defer", "refer_to_resolution"):
        raise HTTPException(400, "decision must be adopt | decline | defer | refer_to_resolution")
    if pr.status == "decided":
        # `defer` and `refer_to_resolution` say "not yet": each may be followed by one final adopt or
        # decline, with the earlier record kept under `history` (XE-1127). adopt and decline are final.
        if (pr.decision or {}).get("decision") in FINAL or decision not in FINAL:
            raise HTTPException(409, "a decision is already recorded for this proposal")
    elif pr.status != "closed":
        raise HTTPException(409, "proposal is not closed")
    reasons = clean_text(v.payload.get("reasons"), "reasons", max_len=MAX_BODY)
    if len(reasons) < 10:
        raise HTTPException(400, "reasons are required")
    res_id = clean_text(v.payload.get("resolution_id"), "resolution_id", max_len=64, required=False)
    outcome = (pr.result or {}).get("outcome")
    resolution = await _decision_resolution(db, pr, res_id) if res_id else None
    if decision == "adopt":
        if outcome != "passed":
            raise HTTPException(409, f"the vote {outcome or 'has no tally'}; a proposal is adopted only when it passed")
        if pr.ops:
            if resolution is None:
                raise HTTPException(409, "a proposal with ops is adopted via a passed resolution; give its resolution_id")
            if resolution.ops != pr.ops:
                raise HTTPException(409, "that resolution does not authorise exactly this proposal's ops")
    history = [*pr.decision.get("history", []), {k: x for k, x in pr.decision.items() if k != "history"}] if pr.decision else []
    pr.decision = {"decision": decision, "reasons": reasons, "by": v.seat.id, "timestamp": v.timestamp,
                   "resolution_id": res_id, "outcome": outcome, **({"history": history} if history else {})}
    pr.status = "decided"
    await ctx.events.append(db, "proposal.decided", v.actor, {"proposal": pr.hash, **pr.decision}, ref=f"proposal:{pr.hash}")
    return pr


async def add_analysis(ctx: Context, db: AsyncSession, pr: Proposal, v: Verified) -> Proposal:
    bind(v, proposal=pr.hash)
    text = clean_text(v.payload.get("text"), "text", max_len=MAX_BODY)
    entry = {"by": v.seat.id if v.seat else v.account, "timestamp": v.timestamp, "text": text}
    pr.analysis = [*pr.analysis, entry]
    await ctx.events.append(db, "proposal.analysis", v.actor, {"proposal": pr.hash, **entry}, ref=f"proposal:{pr.hash}")
    return pr


async def counts(db: AsyncSession) -> dict:
    rows = (await db.execute(select(Proposal.status, func.count()).group_by(Proposal.status))).all()
    return {s: int(c) for s, c in rows}


def to_dict(pr: Proposal, votes: list[Vote] | None = None, include_body: bool = True) -> dict:
    d = {
        "hash": pr.hash, "title": pr.title, "author": pr.author_account, "status": pr.status, "opened_at": pr.opened_at,
        "snapshot_at": snapshot_time(pr.opened_at), "closes_at": pr.closes_at, "fee_block_hash": pr.fee_block_hash,
        "rules": pr.rules, "ops": pr.ops,
        "result": pr.result, "decision": pr.decision, "analysis": pr.analysis,
    }
    if include_body:
        d["body"] = pr.body
    if votes is not None:
        d["tally"] = tally(pr, votes)
        d["votes"] = [{"account": v.account, "choice": v.choice, "weight": v.weight, "participating": v.participating,
                       "is_agent": v.is_agent, "timestamp": v.timestamp, "reason": v.reason} for v in votes]
    return d
