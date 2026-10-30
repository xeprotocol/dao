"""Fee handling: receive into the fee account, then refund or burn per the pinned rules."""

from __future__ import annotations

import logging

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .. import chainops
from ..context import Context
from ..models import FeeLedger
from ..signer import SignerError

log = logging.getLogger("dao.fees")


async def receive_all(ctx: Context, db: AsyncSession) -> int:
    """Pull any pending sends into the fee account (fees land as pending sends until received)."""
    if not ctx.signer.has("fee"):
        return 0
    try:
        made = await chainops.receive_pending(ctx, "fee")
    except SignerError as e:
        log.warning("fee receive refused: %s", e)
        return 0
    for b in made:
        await ctx.events.append(db, "fee.received", "harness", {
            "block": b.hash, "source": b.source, "amount": b.balance, "asset": b.asset,
        }, ref=f"fee:{b.source}", public=True)
        row = (await db.execute(select(FeeLedger).where(FeeLedger.fee_block_hash == b.source))).scalar_one_or_none()
        if row:
            row.tx_hashes = {**(row.tx_hashes or {}), "receive": b.hash}
    return len(made)


async def settle_due(ctx: Context, db: AsyncSession) -> int:
    """Refund or burn fees whose proposals have closed."""
    if not ctx.signer.has("fee"):
        return 0
    rows = list((await db.execute(select(FeeLedger).where(FeeLedger.state.in_(("due_refund", "due_burn"))))).scalars().all())
    n = 0
    for f in rows:
        if not (f.tx_hashes or {}).get("receive"):
            # We never received this fee into the fee account, so there is nothing of the payer's to refund or
            # burn: paying out here would spend other payers' XE (XE-0034). Park it; a member can look.
            f.state = "unreceived"
            f.error = "fee send was never received into the fee account; nothing to settle"
            await ctx.events.append(db, "fee.unreceived", "harness", {
                "proposal": f.proposal_hash, "payer": f.payer, "amount": f.amount, "fee_block_hash": f.fee_block_hash,
            }, ref=f"proposal:{f.proposal_hash}")
            log.warning("fee for %s was never received; not settling", f.proposal_hash)
            continue
        try:
            if f.state == "due_refund":
                b = await chainops.send(ctx, "fee", "block.send.refund", f.payer, f.amount, memo=f"fee refund {f.proposal_hash[:12]}")
                f.tx_hashes = {**(f.tx_hashes or {}), "refund": b.hash}
                f.state = "refunded"
                kind = "fee.refunded"
            else:
                b = await chainops.burn(ctx, "fee", "block.burn", f.amount, memo=f"fee burn {f.proposal_hash[:12]}")
                f.tx_hashes = {**(f.tx_hashes or {}), "burn": b.hash}
                f.state = "burned"
                kind = "fee.burned"
            await ctx.events.append(db, kind, "harness", {
                "proposal": f.proposal_hash, "payer": f.payer, "amount": f.amount, "block": b.hash,
            }, ref=f"proposal:{f.proposal_hash}")
            n += 1
        except Exception as e:  # keep going; retried next tick
            f.error = str(e)[:500]
            log.warning("fee settle failed for %s: %s", f.proposal_hash, e)
    return n


def to_dict(f: FeeLedger) -> dict:
    return {"fee_block_hash": f.fee_block_hash, "proposal": f.proposal_hash, "payer": f.payer, "amount": f.amount,
            "state": f.state, "tx_hashes": f.tx_hashes, "error": f.error}
