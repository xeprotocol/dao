"""Chain operations the harness performs with company-held keys, plus read-side helpers.

Writes here are limited to what Schedule B allows the harness to do on its own: receive into the
fee account, refund or burn a proposal fee, register in the directory, speak in chat. Nothing
here can touch the treasury or the keyset.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Awaitable, Callable

from xe.client import XeClient, XeError
from xe.encoding import Block, sign_block
from xe.keys import KeyPair
from xe.pow import compute_pow

from .context import Context

log = logging.getLogger("dao.chainops")


async def _pow(hash_hex: str, difficulty: int) -> int:
    # PoW is CPU work; keep it off the event loop.
    return await asyncio.to_thread(compute_pow, bytes.fromhex(hash_hex), difficulty)


async def _tip(chain: XeClient, account: str) -> tuple[str, dict[str, int]]:
    """(previous_hash, balances) for an account; previous == "0" for a fresh account."""
    try:
        page = await chain.chain(account, offset=0, limit=1)
        total = int(page.get("total", 0))
        prev = "0"
        if total > 0:
            last = await chain.chain(account, offset=max(total - 1, 0), limit=1)
            blocks = last.get("blocks", [])
            if blocks:
                prev = blocks[-1]["hash"]
    except XeError as e:
        if e.status != 404:
            raise
        prev = "0"
    bals = await chain.balances(account)
    return prev, bals


async def submit_signed(ctx: Context, b: Block, kp: KeyPair) -> Block:
    sign_block(b, kp, ctx.node.network_id)
    b.pow_nonce = await _pow(b.hash, ctx.node.pow_difficulty)
    await ctx.chain.submit_block(b)
    return b


async def receive_pending(ctx: Context, key_name: str, scope: str = "block.receive",
                          on_made: Callable[[Block], Awaitable[None]] | None = None) -> list[Block]:
    """Receive every pending send to the account held under `key_name`. Returns the blocks made.

    Each block is reported through `on_made` as soon as the node has it, so the caller can record it before
    the next one is attempted; a send that cannot be received is logged and skipped rather than stopping the
    run, since the ones behind it are independent (XE-0488)."""
    kp = ctx.signer.keypair(key_name, scope)
    made: list[Block] = []
    for p in await ctx.chain.pending_for(kp.address):
        try:
            prev, bals = await _tip(ctx.chain, kp.address)
            b = Block(type="receive", account=kp.address, previous=prev,
                      balance=bals.get(p["asset"], 0) + p["amount"], timestamp=time.time_ns(),
                      asset=p["asset"], source=p["send_hash"])
            b = await submit_signed(ctx, b, kp)
        except XeError as e:
            log.warning("receive of %s into %s failed: %s", p["send_hash"][:12], key_name, e)
            continue
        made.append(b)
        if on_made is not None:
            await on_made(b)
    return made


async def chain_index(chain: XeClient, account: str) -> list[dict]:
    """Every block on an account, oldest first; [] for an account the node does not know."""
    try:
        return await chain.full_chain(account)
    except XeError as e:
        if e.status == 404:
            return []
        raise


async def send(ctx: Context, key_name: str, scope: str, destination: str, amount: int, memo: str = "",
               asset: str = "XE") -> Block:
    kp = ctx.signer.keypair(key_name, scope)
    prev, bals = await _tip(ctx.chain, kp.address)
    have = bals.get(asset, 0)
    if have < amount:
        raise XeError(409, f"insufficient {asset} in {key_name}: have {have}, need {amount}")
    b = Block(type="send", account=kp.address, previous=prev, balance=have - amount, timestamp=time.time_ns(),
              asset=asset, destination=destination, amount=amount, memo=memo[:64])
    return await submit_signed(ctx, b, kp)


async def burn(ctx: Context, key_name: str, scope: str, amount: int, memo: str = "", asset: str = "XE") -> Block:
    kp = ctx.signer.keypair(key_name, scope)
    prev, bals = await _tip(ctx.chain, kp.address)
    have = bals.get(asset, 0)
    if have < amount:
        raise XeError(409, f"insufficient {asset} in {key_name}: have {have}, need {amount}")
    b = Block(type="burn", account=kp.address, previous=prev, balance=have - amount, timestamp=time.time_ns(),
              asset=asset, amount=amount, memo=memo[:64])
    return await submit_signed(ctx, b, kp)


# ---- read side ---------------------------------------------------------------------------------

# A node accepts a block whose timestamp is within an hour of its clock either way, so a sender can date a
# block up to an hour early or late. Two things follow for a balance snapshot taken at a point in time.
#
# First, a block made after that point can carry a timestamp before it, as long as the gap is under an hour.
# So the snapshot for a proposal is not taken at the moment it opens but an hour and a margin earlier
# (`snapshot_time`): a block made at real time r is dated r - 1h at the earliest, which is after the snapshot
# whenever r is after the open. Nothing done once a proposal is visible can move its snapshot: not a new
# wallet, not a transfer, not a split (XE-0352). Holders see the balance they had an hour before open.
#
# Second, a receive dated before the snapshot whose source send is dated after it is possible on the wire and
# impossible in fact: the XE cannot be in the receiving wallet before it left the sending one. Counting it
# would let one balance vote from two wallets (send dated late, receive dated early), as many times as there
# are wallets. A receive only counts when its source send is also at or before the snapshot. Only receives
# dated within two hours of the snapshot can be affected, so only those are looked up.
TIMESTAMP_WINDOW_NS = 3600 * 1_000_000_000
SNAPSHOT_MARGIN_NS = 5 * 60 * 1_000_000_000
SNAPSHOT_LEAD_NS = TIMESTAMP_WINDOW_NS + SNAPSHOT_MARGIN_NS
CAUSAL_CHECK_NS = 2 * TIMESTAMP_WINDOW_NS


def snapshot_time(opened_at_ns: int) -> int:
    """The time a proposal's weight is read at: an hour and a margin before it opened (see above)."""
    return opened_at_ns - SNAPSHOT_LEAD_NS


async def account_snapshot(chain: XeClient, account: str, at_ns: int, asset: str = "XE") -> dict:
    """Balance of `asset` as of `at_ns`, plus whether the account existed by then.

    XE accounts are chains; each block carries the post-state balance for its asset, so the balance
    at a time is the balance on the last block of that asset with timestamp <= at_ns, less any receive
    in that run whose source send is dated after at_ns (see above).
    """
    empty = {"exists": False, "balance": 0, "first_block_ts": None, "snapshot_block": "", "excluded_receives": []}
    try:
        blocks = await chain.full_chain(account)
    except XeError as e:
        if e.status == 404:
            return empty
        raise
    if not blocks:
        return empty
    first_ts = int(blocks[0].get("timestamp", 0))
    bal = 0
    prev_bal = 0
    snap = ""
    excluded: list[str] = []
    excluded_amount = 0
    counted = 0
    for b in blocks:
        ts = int(b.get("timestamp", 0))
        if ts > at_ns:
            break
        if b.get("asset") != asset:
            counted += 1
            continue
        bal = int(b.get("balance", 0))
        snap = b.get("hash", "")
        if b.get("type") == "receive" and ts > at_ns - CAUSAL_CHECK_NS:
            if not await _send_at_or_before(chain, b.get("source") or "", at_ns):
                excluded.append(b.get("hash", ""))
                excluded_amount += max(bal - prev_bal, 0)
                prev_bal = bal
                continue
        prev_bal = bal
        counted += 1
    return {"exists": first_ts <= at_ns and counted > 0, "balance": max(bal - excluded_amount, 0),
            "first_block_ts": first_ts, "snapshot_block": snap, "excluded_receives": excluded}


async def _send_at_or_before(chain: XeClient, send_hash: str, at_ns: int) -> bool:
    """True when the send a receive points at is on the chain and dated at or before `at_ns`."""
    if not send_hash:
        return False
    try:
        src = await chain.block(send_hash)
    except XeError as e:
        if e.status == 404:
            return False
        raise
    return int(src.get("timestamp", 0)) <= at_ns


async def account_pub_key(chain: XeClient, account: str) -> str:
    """The key declared on the account's open block, or '' if unknown."""
    try:
        page = await chain.chain(account, offset=0, limit=1)
    except XeError as e:
        if e.status == 404:
            return ""
        raise
    blocks = page.get("blocks", [])
    return (blocks[0].get("pub_key") or "") if blocks else ""
