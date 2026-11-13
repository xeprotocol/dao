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

from xe.client import UNREACHABLE, XeClient, XeError
from xe.encoding import Block, sign_block
from xe.keys import KeyPair
from xe.pow import WORKER_POW_DEADLINE_S, compute_pow

from .context import Context

log = logging.getLogger("dao.chainops")


async def _pow(hash_hex: str, difficulty: int) -> int:
    # PoW is CPU work; keep it off the event loop, and never let it run unbounded (XE-1188).
    return await asyncio.to_thread(compute_pow, bytes.fromhex(hash_hex), difficulty, WORKER_POW_DEADLINE_S)


async def _tip(chain: XeClient, account: str) -> tuple[str, dict[str, int]]:
    """(previous_hash, balances) for an account; previous == "0" for a fresh account."""
    return await chain.tip(account), await chain.balances(account)


# Every block the harness writes to an account chain is built by `signed()`, and nothing is recorded from
# the node's answer to a submit: a 200 from a node that then drops the block is not a write, and a timeout
# after the node took it is not a failure (XE-2043, XE-2380). What is recorded comes from reading the chain.
#
# A block that moves value out (`build_send`, `build_burn`) is made at most once, in three steps:
#
#   build     builds, signs and works the block on a final tip, and notes the place it was built for.
#             Nothing has left the process: the caller puts the block on disk first, so every retry offers
#             the same block.
#   offer()   submits it. What the node answers is logged and decides nothing.
#   placed()  reads what stands at that place on the chain. It is the only thing a caller records from.
#
# Why the same block and not a fresh one: an account chain is a line, so of all the blocks ever built on
# one `previous` at most one can land. A retry that offers the block again cannot pay twice; a retry that
# builds a new block at a new tip can, if the first one landed after all. A block is therefore given up
# (`lost`) only when it provably cannot land: another block, final, stands on its `previous`.

async def signed(ctx: Context, b: Block, kp: KeyPair) -> Block:
    # The network id is part of what is signed. A process that started while the node was down has none,
    # and a block signed for "" is one no node will ever take: ask again, and sign nothing without it.
    if not ctx.node.network_id:
        await ctx.refresh_node()
    if not ctx.node.network_id:
        raise XeError(UNREACHABLE, "the node has not said which network this is; nothing is signed without it")
    sign_block(b, kp, ctx.node.network_id)
    b.pow_nonce = await _pow(b.hash, ctx.node.pow_difficulty)
    return b


async def placed(chain: XeClient, block: dict) -> str:
    """Where a block built by `build_send` or `build_burn` stands on its account's chain. `block["at"]` is
    the place it was built for: the number of blocks below it. One page is read, the parent and whatever
    follows it, so the answer is about one moment of one chain:

      landed    the block stands on its parent and is final
      pending   it stands there and is not final, or another block does that is not final either: nothing
                can be concluded yet. Ask again later; offer nothing, build nothing.
      open      nothing stands on its parent: it can still land, and offering the same block again is safe
      lost      another block stands on its parent and is final: it never can land

    Raises XeError if the chain cannot be read, or if what is served does not hold the parent where the
    block was built on it (a node that is behind, or wrong): nothing is concluded from a chain that is not
    the one the block was built on. The first version looked at the account's tip instead, and took any
    final tip other than the parent to mean `lost`, which a node one block behind also shows."""
    at = block["at"]
    try:
        page = (await chain.chain(block["account"], offset=max(at - 1, 0), limit=2 if at else 1))["blocks"]
    except XeError as e:
        if e.status != 404:
            raise
        page = []
    if at:
        if not page or page[0].get("hash") != block["previous"]:
            raise XeError(UNREACHABLE, f"the chain as served does not hold {block['previous'][:12]} at place {at - 1}, "
                                       f"where {block['hash'][:12]} was built on it; nothing is concluded")
        page = page[1:]
    if not page:
        return "open"
    final = page[0].get("finalized") is True
    if page[0].get("hash") == block["hash"]:
        return "landed" if final else "pending"
    return "lost" if final else "pending"


async def offer(ctx: Context, block: dict) -> str:
    """Submit a built block, then say where it stands (`placed`)."""
    try:
        await ctx.chain.submit_block(Block.from_json(block))
    except XeError as e:
        log.warning("submit of %s: %s", block["hash"][:12], e)
    return await placed(ctx.chain, block)


async def receive_pending(ctx: Context, key_name: str, paused: Callable[[], Awaitable[bool]],
                          scope: str = "block.receive") -> int:
    """Offer a receive for every pending send to the account held under `key_name`. Returns how many the
    node said it took, which is a count for the log and nothing else: no receive is recorded from here. The
    caller records a receive when it reads it, final, on the account's chain (XE-2380).

    `paused()` is asked right before each submit, after the block's proof of work, so a pause that begins
    during a run stops the receives still to come (XE-2483). A send that cannot be received is logged and
    skipped whatever went wrong, since the ones behind it are independent (XE-0488). A receive is not kept
    for a retry: one that did not land leaves its send pending on the node, where the next pass finds it,
    and the node takes one receive per send."""
    kp = ctx.signer.keypair(key_name, scope)
    taken = 0
    for p in await ctx.chain.pending_for(kp.address):
        try:
            prev, bals = await _tip(ctx.chain, kp.address)
            b = await signed(ctx, Block(type="receive", account=kp.address, previous=prev,
                                        balance=bals.get(p["asset"], 0) + p["amount"], timestamp=time.time_ns(),
                                        asset=p["asset"], source=p["send_hash"]), kp)
            if await paused():
                break
            await ctx.chain.submit_block(b)
            taken += 1
        except Exception as e:  # a refusal, a bad entry, proof of work that ran out of time: this send only
            log.warning("receive of %s into %s failed: %s: %s", p["send_hash"][:12], key_name, type(e).__name__, e)
    return taken


async def chain_index(chain: XeClient, account: str) -> list[dict]:
    """Every block on an account, oldest first; [] for an account the node does not know."""
    try:
        return await chain.full_chain(account)
    except XeError as e:
        if e.status == 404:
            return []
        raise


async def build_send(ctx: Context, key_name: str, scope: str, destination: str, amount: int, memo: str = "",
                     asset: str = "XE") -> dict | None:
    """A signed send from the account under `key_name`; not submitted. See `_build_out`."""
    return await _build_out(ctx, key_name, scope, "send", amount, memo, asset, destination=destination)


async def build_burn(ctx: Context, key_name: str, scope: str, amount: int, memo: str = "", asset: str = "XE") -> dict | None:
    """A signed burn from the account under `key_name`; not submitted. See `_build_out`."""
    return await _build_out(ctx, key_name, scope, "burn", amount, memo, asset)


async def _build_out(ctx: Context, key_name: str, scope: str, type_: str, amount: int, memo: str, asset: str,
                     **fields) -> dict | None:
    """A block that moves value out of a harness account, built on the account's tip: its wire form, plus
    `at`, the place on the chain it was built for, which is what `placed` reads. None while that tip is not
    final: a block built on one that can still be dropped can be dropped with it and come back with it, and
    `placed` could not then say for certain that it is lost."""
    kp = ctx.signer.keypair(key_name, scope)
    at, last = await ctx.chain.chain_end(kp.address)
    if last is not None and last.get("finalized") is not True:
        return None
    have = (await ctx.chain.balances(kp.address)).get(asset, 0)
    if have < amount:
        raise XeError(409, f"insufficient {asset} in {key_name}: have {have}, need {amount}")
    b = Block(type=type_, account=kp.address, previous=last["hash"] if last else "0", balance=have - amount,
              timestamp=time.time_ns(), asset=asset, amount=amount, memo=memo[:64], **fields)
    return {**(await signed(ctx, b, kp)).to_json(), "at": at}


# ---- read side ---------------------------------------------------------------------------------

# A node accepts a block whose timestamp is within an hour of its clock either way, so a sender can date a
# block up to an hour early or late. Two things follow for a balance snapshot taken at a point in time.
#
# First, a block made after that point can carry a timestamp before it, as long as the gap is under an hour.
# So the snapshot for a proposal is not taken at the moment it opens but an hour and a margin earlier
# (`snapshot_time`): a block made at real time r is dated r - 1h at the earliest, which is after the snapshot
# whenever r is after the open. Nothing done once a proposal is visible can move its snapshot: not a new
# wallet, not a transfer, not a split (XE-0352). That is the whole of what the lead guarantees. It is not a
# holding period: XE borrowed before the open and returned after it weighs at the snapshot like any other
# balance, and the opener, who picks the moment of opening, can arrange that (XE-1098). What the portal
# promises is that the weights are fixed before anyone else learns there is a vote.
#
# Second, a receive dated before the snapshot whose source send is dated after it is possible on the wire and
# impossible in fact: the XE cannot be in the receiving wallet before it left the sending one. Counting it
# would let one balance vote from two wallets (send dated late, receive dated early), as many times as there
# are wallets. A receive only counts when its source send is also at or before the snapshot. Only receives
# dated within two hours of the snapshot can be affected, so only those are looked up. The same holds for
# every other block that brings the weight asset onto a chain from somewhere else: a lease settle mints XE
# to the provider for a lease named in its `source`, and a settle dated before the snapshot for a lease
# opened after it is the same impossibility as a receive before its send (XE-1789). `ARRIVALS` lists the
# block types that are checked this way; each names its cause in `source`.
#
# Third, a snapshot costs a bounded number of node reads whatever the chain looks like (XE-1460): each
# source send is looked up once, at most `CAUSAL_LOOKUP_CONCURRENCY` at a time, and after
# `MAX_CAUSAL_LOOKUPS` distinct sends the remaining receives in the window are excluded without a lookup.
# Excluding can only lower the weight, so a chain built to be expensive is read cheaply and conservatively.
# The budget is spent where the weight is: only receives of the weight asset are checked (a receive of
# another asset carries no weight, so its causality is nobody's concern here), largest amount first, so
# what the cap drops is dust. A voter's material receive is looked up ahead of thirty dust receives, their
# own or a stranger's, and a flood of foreign-asset dust spends nothing (XE-1548, XE-1589).
TIMESTAMP_WINDOW_NS = 3600 * 1_000_000_000
SNAPSHOT_MARGIN_NS = 5 * 60 * 1_000_000_000
SNAPSHOT_LEAD_NS = TIMESTAMP_WINDOW_NS + SNAPSHOT_MARGIN_NS
CAUSAL_CHECK_NS = 2 * TIMESTAMP_WINDOW_NS
MAX_CAUSAL_LOOKUPS = 32
CAUSAL_LOOKUP_CONCURRENCY = 8
# Bumped whenever the figure this function derives for the same chain and `at` can change. A vote row
# stores the result it was derived from; at close, rows derived under another `at` or rule are re-derived
# before they are tallied (XE-1617).
SNAPSHOT_RULE = 5
# Block types that raise the asset balance by bringing value from another block, which `source` names.
ARRIVALS = ("receive", "lease_settle")


def snapshot_time(opened_at_ns: int) -> int:
    """The time a proposal's weight is read at: an hour and a margin before it opened (see above)."""
    return opened_at_ns - SNAPSHOT_LEAD_NS


def empty_snapshot(at_ns: int, unreadable: str = "") -> dict:
    """The snapshot of an account the chain has nothing for: not there, or (with `unreadable` set) one whose
    chain the harness cannot read on purpose, such as one past the page bound (XE-1706)."""
    d = {"exists": False, "balance": 0, "first_block_ts": None, "snapshot_block": "", "excluded_receives": [],
         "lookups_capped": False, "at": at_ns, "rule": SNAPSHOT_RULE}
    if unreadable:
        d["unreadable"] = unreadable
    return d


def _attestation_median(b: dict) -> int | None:
    """The median timestamp of `b`'s timekeeper attestations, None when `b` carries no `attestations` field,
    or -1 when the field is present with no valid timestamp."""
    if "attestations" not in b:
        return None
    atts = b.get("attestations") or []
    ts = sorted(a["timestamp"] for a in atts if isinstance(a, dict) and isinstance(a.get("timestamp"), int))
    return ts[(len(ts) - 1) // 2] if ts else -1


def _settle_attested_after(b: dict, at_ns: int) -> bool:
    """True when a `lease_settle` carries attestations whose median timestamp is after `at_ns` (or empty)."""
    if b.get("type") != "lease_settle":
        return False
    med = _attestation_median(b)
    return med is not None and (med < 0 or med > at_ns)


def _lease_settled_by(lease_hash: str, src: dict, consumer_blocks: list[dict], provider_blocks: list[dict],
                      at_ns: int) -> bool:
    """True when lease `src` opened, ran every renewal, and reached effective expiry at or before `at_ns`."""
    ts = src.get("timestamp", 0)
    if ts > at_ns:
        return False
    start_ns = max(ts, src.get("start_time", 0))
    for ab in provider_blocks:
        if ab.get("type") == "lease_accept" and ab.get("source") == lease_hash:
            med = _attestation_median(ab)
            if med is not None and med < 0:
                return False
            start_ns = max(start_ns, ab.get("timestamp", 0), med or 0)
    dur_ns = src.get("duration", 0) * 1_000_000_000
    if start_ns > at_ns or start_ns + dur_ns > at_ns:
        return False
    for seg in src.get("renewals") or ():
        if not isinstance(seg, dict):
            return False
        seg_ts = max(seg.get("timestamp", 0), seg.get("start_time", 0))
        dur_ns += seg.get("duration", 0) * 1_000_000_000
        if seg_ts > at_ns or start_ns + dur_ns > at_ns:
            return False
    for rb in consumer_blocks:
        if rb.get("type") == "lease_renew" and rb.get("source") == lease_hash:
            med = _attestation_median(rb)
            if med is not None and med < 0:
                return False
            rb_ts = max(rb.get("timestamp", 0), med or 0)
            dur_ns += rb.get("duration", 0) * 1_000_000_000
            if rb_ts > at_ns or start_ns + dur_ns > at_ns:
                return False
    return True


async def account_snapshot(chain: XeClient, account: str, at_ns: int, asset: str = "XE") -> dict:
    """Balance of `asset` as of `at_ns`, plus whether the account existed by then.

    XE accounts are chains; each block carries the post-state balance for its asset, so the balance at a
    time is the balance on the last counted block of that asset with timestamp <= at_ns. A receive of that
    asset whose source send is dated after at_ns, or whose sender in the causal window only had tainted
    balance to spend, is not counted: its tainted part is carried as `tainted`, which later sends and burns
    spend first, and what is still tainted at the end is taken off the balance. A `lease_settle`
    counts only when the lease and all its renewals expired at or before `at_ns`. `snapshot_block`
    is the last counted block. Node reads are bounded and spent largest arrival first;
    `lookups_capped` says whether the bound was hit. `at` and `rule` record what the figure was
    derived under.
    """
    empty = empty_snapshot(at_ns)
    try:
        blocks = await chain.full_chain(account)
    except XeError as e:
        if e.status == 404:
            return empty
        raise
    if not blocks:
        return empty
    first_ts = blocks[0].get("timestamp", 0)
    gate = asyncio.Semaphore(CAUSAL_LOOKUP_CONCURRENCY)
    blocks_seen: dict[str, dict | None] = {}
    chains_seen: dict[str, list[dict] | None] = {account: blocks}
    send_clean: dict[str, int | None] = {}
    block_budget = MAX_CAUSAL_LOOKUPS
    chain_budget = MAX_CAUSAL_LOOKUPS
    capped = False

    async def fetch_one_block(h: str) -> None:
        async with gate:
            try:
                blocks_seen[h] = await chain.block(h)
            except XeError as e:
                if e.status == 404:
                    blocks_seen[h] = None
                    return
                raise

    async def ensure_blocks(hashes: list[str]) -> None:
        nonlocal block_budget, capped
        unseen = [h for h in hashes if h and h not in blocks_seen]
        if len(unseen) > block_budget:
            capped = True
            unseen = unseen[:block_budget]
        block_budget -= len(unseen)
        if unseen:
            await asyncio.gather(*(fetch_one_block(h) for h in unseen))

    async def fetch_chain(acct: str) -> list[dict] | None:
        nonlocal chain_budget, capped
        if acct in chains_seen:
            return chains_seen[acct]
        if chain_budget <= 0:
            capped = True
            return None
        chain_budget -= 1
        async with gate:
            try:
                ch = await chain.full_chain(acct)
            except XeError as e:
                if e.status in (404, 413):
                    chains_seen[acct] = None
                    return None
                raise
        chains_seen[acct] = ch
        for b in ch:
            if b.get("hash") and b["hash"] not in blocks_seen:
                blocks_seen[b["hash"]] = b
        return ch

    async def walk_prev_chain(tip: dict) -> list[dict] | None:
        seq = [tip]
        cur = tip
        while cur.get("previous") not in (None, "", "0"):
            if cur.get("timestamp", 0) <= at_ns - CAUSAL_CHECK_NS:
                break
            prev_h = cur["previous"]
            await ensure_blocks([prev_h])
            prev_b = blocks_seen.get(prev_h)
            if prev_b is None or any(x.get("hash") == prev_h for x in seq):
                return None
            seq.append(prev_b)
            cur = prev_b
        seq.reverse()
        return seq

    async def eval_chain(acct_blocks: list[dict], visiting: frozenset[str],
                         until_hash: str = "") -> tuple[int, int, str, list[str], int]:
        prefix: list[dict] = []
        for b in acct_blocks:
            if b.get("timestamp", 0) > at_ns:
                break
            prefix.append(b)
            if until_hash and b.get("hash") == until_hash:
                break
        window: list[tuple[int, str, str]] = []
        prev = 0
        for b in prefix:
            if b.get("asset") != asset:
                continue
            new_bal = b.get("balance", 0)
            if b.get("type") in ARRIVALS and b.get("timestamp", 0) > at_ns - CAUSAL_CHECK_NS:
                if not _settle_attested_after(b, at_ns):
                    window.append((max(new_bal - prev, 0), b.get("source") or "", b.get("type") or ""))
            prev = new_bal
        by_amount: dict[str, int] = {}
        kind_of: dict[str, str] = {}
        for amount, src_h, kind in window:
            if src_h:
                by_amount[src_h] = by_amount.get(src_h, 0) + amount
                kind_of[src_h] = kind
        sources = sorted(by_amount, key=lambda s_: -by_amount[s_])
        await ensure_blocks(sources)
        clean_pool: dict[str, int | None] = {}
        for s_hash in sources:
            src = blocks_seen.get(s_hash)
            if src is None or src.get("timestamp", 0) > at_ns:
                clean_pool[s_hash] = 0
                continue
            if kind_of.get(s_hash) == "lease_settle" or src.get("type") == "lease":
                c_acct = src.get("account") or ""
                c_blocks: list[dict] = []
                if c_acct:
                    fetched = await fetch_chain(c_acct)
                    if fetched is None:
                        clean_pool[s_hash] = 0
                        continue
                    c_blocks = fetched
                ok = _lease_settled_by(s_hash, src, c_blocks, prefix, at_ns)
                clean_pool[s_hash] = None if ok else 0
                continue
            if src.get("timestamp", 0) <= at_ns - CAUSAL_CHECK_NS:
                clean_pool[s_hash] = None
                continue
            if s_hash in send_clean:
                clean_pool[s_hash] = send_clean[s_hash]
                continue
            sender = src.get("account") or ""
            prev_h = src.get("previous") or ""
            if not sender and prev_h in ("", "0"):
                clean_pool[s_hash] = None
                continue
            if sender:
                if sender in visiting:
                    clean_pool[s_hash] = 0
                    continue
                s_blocks = await fetch_chain(sender)
                if not s_blocks or not any(sb.get("hash") == s_hash for sb in s_blocks):
                    clean_pool[s_hash] = 0
                    continue
                await eval_chain(s_blocks, visiting | {sender}, until_hash=s_hash)
                clean_pool[s_hash] = send_clean.get(s_hash, 0)
            else:
                if s_hash in visiting:
                    clean_pool[s_hash] = 0
                    continue
                s_blocks = await walk_prev_chain(src)
                if not s_blocks:
                    clean_pool[s_hash] = 0
                    continue
                await eval_chain(s_blocks, visiting | {s_hash}, until_hash=s_hash)
                clean_pool[s_hash] = send_clean.get(s_hash, 0)
        bal = 0
        tainted = 0
        snap = ""
        excluded: list[str] = []
        counted = 0
        for b in prefix:
            ts = b.get("timestamp", 0)
            ours = b.get("asset") == asset
            if ours and b.get("type") in ARRIVALS and ts > at_ns - CAUSAL_CHECK_NS:
                new_bal = b.get("balance", 0)
                arr_amt = max(new_bal - bal, 0)
                s_hash = b.get("source") or ""
                if _settle_attested_after(b, at_ns):
                    clean_take = 0
                    bad_zero = True
                else:
                    pool = clean_pool.get(s_hash, 0)
                    if pool is None:
                        clean_take = arr_amt
                        bad_zero = False
                    else:
                        clean_take = min(arr_amt, pool)
                        clean_pool[s_hash] = pool - clean_take
                        bad_zero = pool == 0
                if clean_take < arr_amt or (arr_amt == 0 and bad_zero):
                    excluded.append(b.get("hash", ""))
                    tainted += arr_amt - clean_take
                    if clean_take == 0:
                        bal = new_bal
                        continue
                counted += 1
                bal = new_bal
                snap = b.get("hash", "")
                continue
            counted += 1
            if not ours:
                continue
            new_bal = b.get("balance", 0)
            if new_bal < bal:
                outflow = bal - new_bal
                tainted_spent = min(outflow, tainted)
                clean_out = min(outflow - tainted_spent, max(bal - tainted, 0))
                if b.get("hash"):
                    send_clean[b["hash"]] = clean_out
                tainted -= tainted_spent
            elif b.get("type") == "send" and b.get("hash"):
                send_clean[b["hash"]] = 0
            bal = new_bal
            snap = b.get("hash", "")
        return bal, tainted, snap, excluded, counted

    bal, tainted, snap, excluded, counted = await eval_chain(blocks, frozenset({account}))
    return {"exists": first_ts <= at_ns and counted > 0, "balance": max(bal - tainted, 0),
            "first_block_ts": first_ts, "snapshot_block": snap, "excluded_receives": excluded,
            "lookups_capped": capped, "at": at_ns, "rule": SNAPSHOT_RULE}


async def _sends_at_or_before(chain: XeClient, send_hashes: list[str], at_ns: int) -> dict[str, bool]:
    """For each source block (a send, or the lease a settle pays out): True when it is on the chain and
    dated at or before `at_ns`. One read per distinct hash, a bounded number in flight; a hash not in the
    result is not causal."""
    gate = asyncio.Semaphore(CAUSAL_LOOKUP_CONCURRENCY)

    async def one(h: str) -> bool:
        if not h:
            return False
        async with gate:
            try:
                src = await chain.block(h)
            except XeError as e:
                if e.status == 404:
                    return False
                raise
        return src.get("timestamp", 0) <= at_ns

    found = await asyncio.gather(*(one(h) for h in send_hashes))
    return dict(zip(send_hashes, found))


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
