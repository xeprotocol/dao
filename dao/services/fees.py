"""Fee handling: receive into the fee account, then refund or burn per the pinned rules.

The chain is the ground truth; the ledger is a record of it, never ahead of it and never guessing. Nothing
is recorded from what the node answers to a submit, only from a block read back from the chain, final.

A settlement (a refund, a burn, or the return of what was paid above the fee) is one block:

- it is built once, signed, and committed to the row (`tx_hashes["settle_block"]`) before it is offered;
- every pass asks the chain what stands where that block was built to stand (`chainops.placed`). The block,
  final: the row is recorded settled, with its hash. Nothing: the same block is offered again. Another
  block, final: this one can never land, so it is dropped and a new one is built. Anything else: wait.

An account chain is a line, so the one block can land at most once, and a row can only be paid twice if
two blocks are built for it; the second is built only when the first provably cannot land. That replaces
the memo nonce and its search of the chain, which read "no block with this nonce yet" as "never sent",
forgot the nonce and paid again (XE-2043), and which recorded a settlement on the node's answer to the
submit without asking the chain at all (XE-2380). The first rule here was XE-0486/XE-0488: every chain
write is made exactly once, whatever the worker does around it. One pass runs at a time (the worker holds
`db.only_one` for the job), so a row has one block because one process builds it.

A block the node keeps refusing is offered for as long as nothing else stands in its place, with the reason
on the row. It is replaced when the fee account's chain next moves, which the next fee received does.

A receive is offered for every send pending to the fee account, and recorded for a fee the ledger knows
when the fee account's chain holds a final receive whose source is that fee's send. A fee whose receive is
not on the chain is not settled: there is nothing of the payer's to pay out.
"""

from __future__ import annotations

import logging

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .. import chainops
from ..context import Context
from ..log import EventLog
from ..models import FeeLedger, Proposal
from ..signer import SignerError
from . import pause

log = logging.getLogger("dao.fees")

DUE = ("due_refund", "due_burn")
UNRECEIVED_ERROR = "fee send was never received into the fee account; nothing to settle"
ARRIVING_NOTE = "the fee's receive is not final on the fee account's chain yet; settlement waits for it"


async def receive_all(ctx: Context, db: AsyncSession) -> int:
    """Offer a receive for every send pending to the fee account (fees arrive as pending sends). Returns
    how many the node took; `record_receives` is what puts a receive on record."""
    if not ctx.signer.has("fee"):
        return 0
    try:
        return await chainops.receive_pending(ctx, "fee", lambda: pause.is_paused(db))
    except SignerError as e:
        log.warning("fee receive refused: %s", e)
        return 0


async def record_receives(ctx: Context, db: AsyncSession) -> int:
    """Record the receive of every fee that has none on record and whose receive the chain now holds.
    Returns how many were recorded. The fee account's chain is read only when a row is waiting."""
    if not ctx.signer.has("fee"):
        return 0
    rows = (await db.execute(select(FeeLedger).where(FeeLedger.state.in_(("seen",) + DUE))
                             .order_by(FeeLedger.fee_block_hash))).scalars().all()
    chain = _FeeChain(ctx)
    n = 0
    for f in rows:
        if not (f.tx_hashes or {}).get("receive") and await _record_receive(ctx, db, f, chain):
            n += 1
    return n


class _FeeChain:
    """The fee account's chain, read once per pass and only when something needs it."""

    def __init__(self, ctx: Context):
        self.ctx, self._blocks, self._pending = ctx, None, None

    async def blocks(self) -> list[dict]:
        if self._blocks is None:
            self._blocks = await chainops.chain_index(self.ctx.chain, self.ctx.signer.address("fee"))
        return self._blocks

    async def receive_of(self, send_hash: str) -> dict | None:
        """The final receive of a send. One that is not final yet can still be dropped; it is found on a
        later pass, when it is."""
        return next((b for b in await self.blocks() if b.get("type") == "receive" and b.get("source") == send_hash
                     and b.get("finalized") is True and b.get("hash")), None)   # the hash is what gets recorded

    async def arriving(self, send_hash: str) -> bool:
        """Whether a send with no final receive is still on its way in: its receive is on the chain and
        not final yet, or the node holds the send pending for the fee account, where every pass offers a
        receive for it. Neither is "never received"."""
        if any(b.get("type") == "receive" and b.get("source") == send_hash for b in await self.blocks()):
            return True
        if self._pending is None:
            self._pending = {p["send_hash"] for p in await self.ctx.chain.pending_for(self.ctx.signer.address("fee"))}
        return send_hash in self._pending


async def _record_receive(ctx: Context, db: AsyncSession, f: FeeLedger, chain: _FeeChain) -> bool:
    got = await chain.receive_of(f.fee_block_hash)
    if not got:
        return False
    f.tx_hashes = {**(f.tx_hashes or {}), "receive": got["hash"]}
    f.error = ""
    await ctx.events.append(db, "fee.received", "harness", {
        "block": got["hash"], "source": f.fee_block_hash, "amount": f.amount, "asset": got.get("asset"),
    }, ref=f"fee:{f.fee_block_hash}", public=True)
    await db.commit()
    return True


async def settle_due(ctx: Context, db: AsyncSession) -> int:
    """Refund or burn fees whose proposals have closed. Each row is committed as it moves. Returns how many
    rows reached `refunded` or `burned` this pass."""
    if not ctx.signer.has("fee"):
        return 0
    keys = list((await db.execute(select(FeeLedger.fee_block_hash).where(FeeLedger.state.in_(DUE + ("settling",)))
                                  .order_by(FeeLedger.updated_at.asc(), FeeLedger.fee_block_hash.asc()))).scalars().all())
    chain = _FeeChain(ctx)
    n = 0
    for key in keys:
        f = await db.get(FeeLedger, key)
        try:
            if f.state in DUE and not (f.tx_hashes or {}).get("receive") and not await _received(ctx, db, f, chain):
                continue
            if await _settle(ctx, db, f):
                n += 1
        except Exception as e:  # keep going; the row is as it was last committed, and is taken again next tick
            await db.rollback()
            f = await db.get(FeeLedger, key)
            f.error = str(e)[:500]
            await db.commit()
            log.warning("fee settle failed for %s: %s", f.proposal_hash, e)
    return n


async def _received(ctx: Context, db: AsyncSession, f: FeeLedger, chain: _FeeChain) -> bool:
    """A due row with no receive on record: is its receive on the chain (XE-0488)? If it is not, we never
    received this fee into the fee account, so there is nothing of the payer's to refund or burn: paying out
    here would spend other payers' XE (XE-0034). The row stays due and is looked at every pass.

    A receive that is on the chain and not final, or a send the node still holds pending, is not "never
    received": the row waits and nothing is said. The event fires once for a fee, and the log is what says
    whether it has: the row's `error` is overwritten by whatever last went wrong with the row, so a node
    failure between two passes would otherwise have the same fee announced again."""
    if await _record_receive(ctx, db, f, chain):
        return True
    if await chain.arriving(f.fee_block_hash):
        await _note(db, f, ARRIVING_NOTE)
        return False
    await _note(db, f, UNRECEIVED_ERROR)
    ref = f"proposal:{f.proposal_hash}"
    if not await EventLog.page(db, limit=1, kind="fee.unreceived", ref=ref, public_only=False):
        await ctx.events.append(db, "fee.unreceived", "harness", {
            "proposal": f.proposal_hash, "payer": f.payer, "amount": f.amount, "fee_block_hash": f.fee_block_hash,
        }, ref=ref)
        await db.commit()
        log.warning("fee for %s was never received; not settling", f.proposal_hash)
    return False


async def _fee_due(db: AsyncSession, f: FeeLedger) -> int:
    """The fee the proposal pinned when it opened. A payer may have sent more; only this much is the fee."""
    rules = (await db.execute(select(Proposal.rules).where(Proposal.hash == f.proposal_hash))).scalar_one_or_none() or {}
    return min(int(rules.get("fee_micro_xe", f.amount)), f.amount)


def _phase_amount(f: FeeLedger, fee: int) -> int:
    """What the current settlement phase pays: the whole sum back on a refund; only the fee on a burn; and
    on `excess`, the part above the fee back to the payer, since the documented burn is the fee (XE-0740)."""
    as_ = f.tx_hashes["settle_as"]
    return f.amount if as_ == "refund" else fee if as_ == "burn" else f.amount - fee


_IN_FLIGHT = ("settle_as", "settle_block")


def _mark(f: FeeLedger, as_: str) -> None:
    """Begin a settlement phase: what is owed, and no block yet."""
    f.tx_hashes = {**{k: v for k, v in (f.tx_hashes or {}).items() if k not in _IN_FLIGHT}, "settle_as": as_}
    f.state = "settling"


async def _note(db: AsyncSession, f: FeeLedger, why: str) -> None:
    if f.error != why:
        f.error = why
        await db.commit()


async def _settle(ctx: Context, db: AsyncSession, f: FeeLedger) -> bool:
    """Take a row as far as the chain allows this pass; True once it is `refunded` or `burned`. A burn that
    leaves an excess to return is two phases, one block each."""
    if "settle_nonce" in (f.tx_hashes or {}):
        # Marked by the release before this one, which named its block by a nonce in the memo and kept no
        # hash. Whether that block went out cannot be told from the row, so no block is built for it here.
        raise RuntimeError(f"settlement was begun under the memo-nonce scheme (nonce {f.tx_hashes['settle_nonce']}) "
                           "and is not continued automatically: check the fee account's chain for that memo")
    if f.state in DUE:
        _mark(f, "refund" if f.state == "due_refund" else "burn")
        await db.commit()
    fee = await _fee_due(db, f)
    while f.state == "settling":
        block = f.tx_hashes.get("settle_block")
        if block is None:
            block = await _build(ctx, db, f, fee)
            if block is None:
                return False
            # The block is on the row before it is offered: whatever happens next, this is the block the
            # next pass asks the chain about.
            f.tx_hashes = {**f.tx_hashes, "settle_block": block}
            await db.commit()
            where = "open"
        else:
            where = await chainops.placed(ctx.chain, block)
        if where == "open":
            if await pause.is_paused(db):
                return False
            where = await chainops.offer(ctx, block)
        if where == "landed":
            await _record_settled(ctx, db, f, block["hash"], fee)
        elif where == "lost":
            # Another block is final where this one would have stood: it can never land. The next pass
            # builds another.
            f.tx_hashes = {k: v for k, v in f.tx_hashes.items() if k != "settle_block"}
            f.error = f"settlement block {block['hash'][:12]} was not taken and can no longer land; another is built"
            await db.commit()
            return False
        else:
            if where == "open":
                await _note(db, f, f"settlement block {block['hash'][:12]} was offered and the node did not take it; "
                                   "the same block is offered again until the fee account's chain moves")
            return False   # offered and not final yet, or the node did not take it this time
    return True


async def _build(ctx: Context, db: AsyncSession, f: FeeLedger, fee: int) -> dict | None:
    """The block for the row's current phase; None if it is not to be built now (a pause, or a fee account
    whose tip is not final yet)."""
    if await pause.is_paused(db):
        # Read here, not only at the start of the job: a pause committed since then stops the burn or
        # refund before it is signed (XE-1172). The row stays `settling` and is taken up after the pause.
        return None
    as_ = f.tx_hashes["settle_as"]
    memo = f"fee {as_} {f.proposal_hash[:12]}"
    amount = _phase_amount(f, fee)
    if as_ == "burn":
        return await chainops.build_burn(ctx, "fee", "block.burn", amount, memo=memo)
    return await chainops.build_send(ctx, "fee", "block.send.refund", f.payer, amount, memo=memo)


async def _record_settled(ctx: Context, db: AsyncSession, f: FeeLedger, block_hash: str, fee: int) -> None:
    as_ = f.tx_hashes["settle_as"]
    amount = _phase_amount(f, fee)
    f.tx_hashes = {**{k: v for k, v in f.tx_hashes.items() if k not in _IN_FLIGHT}, as_: block_hash}
    f.error = ""
    payload = {"proposal": f.proposal_hash, "payer": f.payer, "amount": amount, "block": block_hash}
    if as_ == "excess":
        f.state = "burned"
        await ctx.events.append(db, "fee.excess_returned", "harness", payload, ref=f"proposal:{f.proposal_hash}")
    else:
        f.state = "refunded" if as_ == "refund" else "burned"
        await ctx.events.append(db, f"fee.{f.state}", "harness", payload, ref=f"proposal:{f.proposal_hash}")
        if as_ == "burn" and f.amount > fee:
            _mark(f, "excess")   # the burn is on record; what was sent above the fee goes back next
    await db.commit()
