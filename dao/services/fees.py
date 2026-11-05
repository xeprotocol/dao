"""Fee handling: receive into the fee account, then refund or burn per the pinned rules.

Every chain write here is made exactly once, whatever the worker does around it (XE-0486, XE-0488):

- a receive is recorded and committed the moment the node has it, before the next one is attempted;
- a settlement is marked `settling` with a nonce and committed *before* the send or burn goes out, and the
  nonce rides in the memo; the block hash is committed straight after;
- on every pass, a row still `settling` is reconciled against the fee account's own chain: a block carrying
  its nonce means the payment landed and the record is completed; no block means it never went out and the
  row goes back to due. A row with no receive on record is reconciled the same way, by looking for a receive
  whose source is the fee send, before it is given up on.

The chain is the ground truth; the ledger is a record of it, never ahead of it.
"""

from __future__ import annotations

import logging
import secrets

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .. import chainops
from ..context import Context
from ..models import FeeLedger
from ..signer import SignerError

log = logging.getLogger("dao.fees")

DUE = ("due_refund", "due_burn")
UNRECEIVED_ERROR = "fee send was never received into the fee account; nothing to settle"


async def receive_all(ctx: Context, db: AsyncSession) -> int:
    """Pull any pending sends into the fee account (fees land as pending sends until received)."""
    if not ctx.signer.has("fee"):
        return 0

    async def record(b):
        await ctx.events.append(db, "fee.received", "harness", {
            "block": b.hash, "source": b.source, "amount": b.balance, "asset": b.asset,
        }, ref=f"fee:{b.source}", public=True)
        row = (await db.execute(select(FeeLedger).where(FeeLedger.fee_block_hash == b.source))).scalar_one_or_none()
        if row:
            row.tx_hashes = {**(row.tx_hashes or {}), "receive": b.hash}
        await db.commit()

    try:
        made = await chainops.receive_pending(ctx, "fee", on_made=record)
    except SignerError as e:
        log.warning("fee receive refused: %s", e)
        return 0
    return len(made)


class _FeeChain:
    """The fee account's chain, read once per pass and only when something needs reconciling."""

    def __init__(self, ctx: Context):
        self.ctx, self._blocks = ctx, None

    async def blocks(self) -> list[dict]:
        if self._blocks is None:
            self._blocks = await chainops.chain_index(self.ctx.chain, self.ctx.signer.address("fee"))
        return self._blocks

    async def receive_of(self, send_hash: str) -> dict | None:
        return next((b for b in await self.blocks() if b.get("type") == "receive" and b.get("source") == send_hash), None)

    async def settlement_with(self, nonce: str) -> dict | None:
        return next((b for b in await self.blocks()
                     if b.get("type") in ("send", "burn") and (b.get("memo") or "").endswith(f" {nonce}")), None)


async def settle_due(ctx: Context, db: AsyncSession) -> int:
    """Refund or burn fees whose proposals have closed. Each row is committed as it moves."""
    if not ctx.signer.has("fee"):
        return 0
    rows = list((await db.execute(select(FeeLedger).where(FeeLedger.state.in_(DUE + ("settling",))))).scalars().all())
    chain = _FeeChain(ctx)
    n = 0
    for f in rows:
        try:
            if f.state == "settling":
                if await _finish_or_retry(ctx, db, f, chain):
                    n += 1
                    continue
                # not on chain: back to due, and fall through to settle it now
            if not (f.tx_hashes or {}).get("receive") and not await _find_receive(ctx, db, f, chain):
                continue
            await _settle(ctx, db, f)
            n += 1
        except Exception as e:  # keep going; retried next tick
            f.error = str(e)[:500]
            await db.commit()
            log.warning("fee settle failed for %s: %s", f.proposal_hash, e)
    return n


async def _find_receive(ctx: Context, db: AsyncSession, f: FeeLedger, chain: _FeeChain) -> bool:
    """A due row with no receive on record: the receive may have landed without being recorded (XE-0488)."""
    got = await chain.receive_of(f.fee_block_hash)
    if got:
        f.tx_hashes = {**(f.tx_hashes or {}), "receive": got["hash"]}
        f.error = ""
        await ctx.events.append(db, "fee.received", "harness", {
            "block": got["hash"], "source": f.fee_block_hash, "amount": got.get("balance"), "asset": got.get("asset"),
            "reconciled": True,
        }, ref=f"fee:{f.fee_block_hash}", public=True)
        await db.commit()
        return True
    # We never received this fee into the fee account, so there is nothing of the payer's to refund or burn:
    # paying out here would spend other payers' XE (XE-0034). The row stays due and is looked at every pass;
    # the event fires once.
    if f.error != UNRECEIVED_ERROR:
        f.error = UNRECEIVED_ERROR
        await ctx.events.append(db, "fee.unreceived", "harness", {
            "proposal": f.proposal_hash, "payer": f.payer, "amount": f.amount, "fee_block_hash": f.fee_block_hash,
        }, ref=f"proposal:{f.proposal_hash}")
        await db.commit()
        log.warning("fee for %s was never received; not settling", f.proposal_hash)
    return False


async def _settle(ctx: Context, db: AsyncSession, f: FeeLedger) -> None:
    """Mark, commit, pay, record, commit."""
    if f.state in DUE:
        as_ = "refund" if f.state == "due_refund" else "burn"
        f.tx_hashes = {**(f.tx_hashes or {}), "settle_as": as_, "settle_nonce": secrets.token_hex(4)}
        f.state = "settling"
        await db.commit()
    as_, nonce = f.tx_hashes["settle_as"], f.tx_hashes["settle_nonce"]
    memo = f"fee {as_} {f.proposal_hash[:12]} {nonce}"
    if as_ == "refund":
        b = await chainops.send(ctx, "fee", "block.send.refund", f.payer, f.amount, memo=memo)
    else:
        b = await chainops.burn(ctx, "fee", "block.burn", f.amount, memo=memo)
    await _record_settled(ctx, db, f, b.hash)


async def _finish_or_retry(ctx: Context, db: AsyncSession, f: FeeLedger, chain: _FeeChain) -> bool:
    """A row left `settling`: completed from the chain if the payment landed, else returned to due."""
    nonce = (f.tx_hashes or {}).get("settle_nonce", "")
    got = await chain.settlement_with(nonce) if nonce else None
    if got:
        await _record_settled(ctx, db, f, got["hash"], reconciled=True)
        return True
    f.state = "due_refund" if f.tx_hashes.get("settle_as") == "refund" else "due_burn"
    f.tx_hashes = {k: v for k, v in f.tx_hashes.items() if k not in ("settle_as", "settle_nonce")}
    await db.commit()
    return False


async def _record_settled(ctx: Context, db: AsyncSession, f: FeeLedger, block_hash: str, reconciled: bool = False) -> None:
    as_ = f.tx_hashes["settle_as"]
    f.tx_hashes = {**{k: v for k, v in f.tx_hashes.items() if k not in ("settle_as", "settle_nonce")}, as_: block_hash}
    f.state = "refunded" if as_ == "refund" else "burned"
    f.error = ""
    payload = {"proposal": f.proposal_hash, "payer": f.payer, "amount": f.amount, "block": block_hash}
    if reconciled:
        payload["reconciled"] = True
    await ctx.events.append(db, f"fee.{f.state}", "harness", payload, ref=f"proposal:{f.proposal_hash}")
    await db.commit()


def to_dict(f: FeeLedger) -> dict:
    return {"fee_block_hash": f.fee_block_hash, "proposal": f.proposal_hash, "payer": f.payer, "amount": f.amount,
            "state": f.state, "tx_hashes": f.tx_hashes, "error": f.error}
