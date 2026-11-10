"""XE-0032 / XE-0033 / XE-0034 / XE-0080 against a real Postgres. Skipped unless DAO_TEST_DATABASE_URL is set
(a scratch database; it is wiped). Node calls are stubbed; nothing here touches the network."""

import os
import time
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from dao.auth import MAX_SKEW_NS, Verified, claim_signature, purge_seen_signatures
from dao.db import Base
from dao.log import EventLog
from dao.models import Anchor, Event, FeeLedger, HealthCheck, InboxMessage, Proposal, Resolution, SeenSignature, SigningSession, Vote
from dao.services import fees, inbox, portal, sessions
from dao.signer import Signer
from xe.client import XeError
from xe.keys import KeyPair

URL = os.environ.get("DAO_TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(not URL, reason="DAO_TEST_DATABASE_URL not set")

D = 24 * 3600 * 1_000_000_000
FEE_ACCT = "f" * 64
AUTHOR = "a" * 64


@pytest.fixture
async def db():
    eng = create_async_engine(URL)
    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
        await conn.execute(text("INSERT INTO log_head (id, index, hash) VALUES (1, -1, repeat('0', 64))"))
    sm = async_sessionmaker(eng, expire_on_commit=False)
    async with sm() as s:
        yield s
    await eng.dispose()


class FakeChain:
    def __init__(self, blocks=None, chains=None):
        self.blocks, self.chains, self.state_blocks = blocks or {}, chains or {}, {}

    async def statechain_block(self, index):
        if index not in self.state_blocks:
            raise XeError(404, "not found")
        return self.state_blocks[index]

    async def block(self, h):
        if h not in self.blocks:
            raise XeError(404, "not found")
        return self.blocks[h]

    async def full_chain(self, account):
        return self.chains.get(account, [{"timestamp": 0, "asset": "XE", "balance": 5_000_000, "hash": "b" * 64}])

    async def dao_keyset(self):
        return {"keys": ["k1", "k2", "k3"], "threshold": 2}

    async def statechain_tip(self):
        raise XeError(404, "no tip")


class LedgerChain(FakeChain):
    """Account chains as a node keeps them, for the harness's own writes: a submitted block lands at the
    tip if it is built on the tip and is refused otherwise; a receive takes its send off the pending list.

    `on_submit(block)` stands in for a node that misbehaves. It is awaited before anything else and may
    raise (the node refused, or never answered), return "drop" (the node says yes and keeps nothing) or
    return "lose-answer" (the block lands and the answer does not arrive). `finalized` is what a block is
    stored as; `finalize()` makes everything final."""

    def __init__(self, finalized=True):
        super().__init__()
        self.ledger, self.pending, self.submits, self.finalized, self.on_submit = {}, [], [], finalized, None

    def fund(self, account, amount, source="0" * 64, finalized=True):
        """A receive of `amount` XE at the account's tip, as if the node had taken it earlier."""
        chain = self.ledger.setdefault(account, [])
        b = {"type": "receive", "account": account, "previous": chain[-1]["hash"] if chain else "0", "asset": "XE",
             "balance": (chain[-1]["balance"] if chain else 0) + amount, "timestamp": time.time_ns(), "source": source,
             "hash": os.urandom(32).hex(), "finalized": finalized}
        chain.append(b)
        return b

    def land(self, block, finalized=True):
        self.ledger.setdefault(block["account"], []).append({**block, "finalized": finalized})

    def finalize(self):
        for chain in self.ledger.values():
            for b in chain:
                b["finalized"] = True

    def of(self, account, type_=None):
        return [b for b in self.ledger.get(account, []) if type_ is None or b["type"] == type_]

    async def chain(self, account, offset=0, limit=1000):
        blocks = self.ledger.get(account, [])
        return {"blocks": blocks[offset:offset + limit], "total": len(blocks)}

    async def chain_end(self, account):
        chain = self.ledger.get(account)
        return (len(chain), chain[-1]) if chain else (0, None)

    async def tip(self, account):
        _, last = await self.chain_end(account)
        return last["hash"] if last else "0"

    async def balances(self, account):
        _, last = await self.chain_end(account)
        return {"XE": last["balance"]} if last else {}

    async def block(self, h):
        for chain in self.ledger.values():
            for b in chain:
                if b["hash"] == h:
                    return b
        return await super().block(h)

    async def full_chain(self, account):
        return list(self.ledger.get(account, []))

    async def pending_for(self, account):
        return list(self.pending)

    async def submit_block(self, b):
        d = b.to_json()
        self.submits.append(d)
        how = await self.on_submit(d) if self.on_submit else None
        if how == "drop":
            return {"ok": True}
        if await self.tip(d["account"]) != d["previous"]:
            raise XeError(400, "block rejected: previous is not the account's tip")
        self.land(d, self.finalized)
        self.pending = [p for p in self.pending if p["send_hash"] != d.get("source")]
        if how == "lose-answer":
            raise XeError(0, "ReadTimeout")
        return d


class FakeSigner:
    def __init__(self, scopes=("harness",)):
        self._kp = {s: KeyPair.generate() for s in scopes}

    def has(self, s):
        return s in self._kp

    def address(self, s):
        return self._kp[s].address

    def public_key(self, s):
        return self._kp[s].pub_key_hex

    def infos(self):
        return [SimpleNamespace(name=s) for s in self._kp]

    def keypair(self, s, _scope=None):
        return self._kp[s]

    def sign(self, s, _scope, data):
        return self._kp[s].sign_hex(data)


def _ctx(chain=None, fee=True):
    signer = FakeSigner(("harness", "fee") if fee else ("harness",))
    events = EventLog(Signer({"harness": signer._kp["harness"]}, {"harness": {"event.sign"}}))
    config = SimpleNamespace(agent_accounts=set(), accounts={"dao": "d" * 64, "fee": FEE_ACCT}, human_seats=[],
                             pinned_rules=lambda: {"fee_micro_xe": 1000, "window_days": 7, "participating_wallet": {},
                                                   "excluded_accounts": [], "agents": {}})
    return SimpleNamespace(chain=chain or FakeChain(), signer=signer, events=events, config=config,
                           node=SimpleNamespace(chat_pow_difficulty=0, pow_difficulty=0, network_id="xe-test"))


def _v(account=AUTHOR, payload=None, ts=None, sig=None):
    return Verified(account=account, pub_key="p" * 64, payload=payload or {}, timestamp=ts or time.time_ns(),
                    signature=sig or os.urandom(64).hex())


def _send(finalized, amount=1000):
    return {"type": "send", "asset": "XE", "destination": FEE_ACCT, "account": AUTHOR, "amount": amount,
            "finalized": finalized}


# ---- XE-0033: durable, transactional replay protection -----------------------------------------

async def test_claim_is_once_and_survives_a_new_session(db):
    v = _v()
    await claim_signature(db, v)
    await db.commit()
    with pytest.raises(HTTPException) as e:
        await claim_signature(db, v)
    assert e.value.status_code == 409
    # a fresh session (as after a restart) still refuses it
    sm = async_sessionmaker(db.bind, expire_on_commit=False)
    async with sm() as other:
        with pytest.raises(HTTPException):
            await claim_signature(other, v)


async def test_claim_rolls_back_with_the_request(db):
    v = _v()
    await claim_signature(db, v)
    await db.rollback()           # the request failed after the claim; nothing is durable
    await claim_signature(db, v)  # so the same signature can be presented again
    await db.commit()


async def test_purge_drops_only_expired_claims(db):
    old = _v(ts=time.time_ns() - 3 * MAX_SKEW_NS)
    fresh = _v()
    await claim_signature(db, old)
    await claim_signature(db, fresh)
    await db.commit()
    assert await purge_seen_signatures(db) == 1
    await db.commit()
    left = (await db.execute(select(SeenSignature.sig))).scalars().all()
    assert left == [fresh.signature]


async def test_vote_replacement_is_by_signer_time_not_arrival(db):
    ctx = _ctx()
    now = time.time_ns()
    pr = Proposal(hash="c" * 64, title="t", body="b", ops=None, author_account=AUTHOR, author_pub_key="p" * 64,
                  author_signature="s", author_timestamp=now, fee_block_hash="c" * 64, status="open", opened_at=now,
                  closes_at=now + D, rules=ctx.config.pinned_rules(), analysis=[])
    db.add(pr)
    await db.flush()
    early = _v(payload={"proposal": pr.hash, "choice": "for"}, ts=now - 1000)
    late = _v(payload={"proposal": pr.hash, "choice": "against"}, ts=now)
    await portal.vote(ctx, db, pr, late)
    with pytest.raises(HTTPException) as e:
        await portal.vote(ctx, db, pr, early)      # older signature arrives second: cannot overwrite
    assert e.value.status_code == 409
    with pytest.raises(HTTPException):
        await portal.vote(ctx, db, pr, _v(payload={"proposal": pr.hash, "choice": "for"}, ts=now))  # equal time too
    row = (await db.execute(select(Vote).where(Vote.account == AUTHOR))).scalar_one()
    assert row.choice == "against"
    newer = _v(payload={"proposal": pr.hash, "choice": "abstain"}, ts=now + 1)
    assert (await portal.vote(ctx, db, pr, newer)).choice == "abstain"


# ---- XE-0034: fee finality and settlement ------------------------------------------------------

async def test_unfinalised_fee_block_is_refused(db):
    h = "e" * 64
    ctx = _ctx(FakeChain({h: _send(False)}))
    with pytest.raises(HTTPException) as e:
        await portal._verify_fee(ctx, db, h, AUTHOR, 1000)
    assert e.value.status_code == 400 and "finalised" in e.value.detail
    ctx = _ctx(FakeChain({h: _send(True)}))
    assert (await portal._verify_fee(ctx, db, h, AUTHOR, 1000))["amount"] == 1000
    ctx = _ctx(FakeChain({h: {**_send(True), "finalized": "true"}}))  # only a real boolean counts
    with pytest.raises(HTTPException):
        await portal._verify_fee(ctx, db, h, AUTHOR, 1000)


def _fee_ctx(funded=0, **chain_kw):
    """A context whose node keeps real account chains (`LedgerChain`), the fee account holding `funded` XE."""
    chain = LedgerChain(**chain_kw)
    ctx = _ctx(chain)
    fee = ctx.signer.address("fee")
    if funded:
        chain.fund(fee, funded, source="9" * 64)
    return ctx, chain, fee


async def _fee_row(db, state, amount=1000, n="1", received=True):
    db.add(FeeLedger(fee_block_hash=n * 64, proposal_hash=n * 64, payer=AUTHOR, amount=amount, state=state,
                     tx_hashes={"receive": "9" * 64} if received else {}))
    await db.commit()


async def _fee(db, n="1"):
    row = (await db.execute(select(FeeLedger).where(FeeLedger.fee_block_hash == n * 64))).scalar_one()
    await db.refresh(row)
    return row


async def test_settlement_refuses_fees_never_received(db):
    ctx, chain, fee = _fee_ctx(funded=5000)   # other payers' XE is in the account; none of it is these rows'
    db.add(FeeLedger(fee_block_hash="1" * 64, proposal_hash="2" * 64, payer=AUTHOR, amount=1000, state="due_refund", tx_hashes={}))
    db.add(FeeLedger(fee_block_hash="3" * 64, proposal_hash="4" * 64, payer=AUTHOR, amount=1000, state="due_burn", tx_hashes={}))
    await db.flush()
    assert await fees.settle_due(ctx, db) == 0
    assert chain.submits == [], "must not pay out an unreceived fee"
    rows = (await db.execute(select(FeeLedger).order_by(FeeLedger.fee_block_hash))).scalars().all()
    # the rows stay due with the reason on them, and are looked at again every pass; the event fires once
    assert [r.state for r in rows] == ["due_refund", "due_burn"] and all(r.error == fees.UNRECEIVED_ERROR for r in rows)
    assert await fees.settle_due(ctx, db) == 0
    kinds = (await db.execute(select(Event.kind))).scalars().all()
    assert kinds.count("fee.unreceived") == 2
    # once for a fee, whatever has been written on the row since: a node failure between two passes leaves
    # its own words there, and the next clean pass does not announce the same fee again
    rows[0].error = "ConnectError: the node was down for a pass"
    await db.commit()
    assert await fees.settle_due(ctx, db) == 0
    rows = (await db.execute(select(FeeLedger).order_by(FeeLedger.fee_block_hash))).scalars().all()
    assert all(r.error == fees.UNRECEIVED_ERROR for r in rows)
    assert (await db.execute(select(Event.kind))).scalars().all().count("fee.unreceived") == 2
    # a fee on its way in is not "never received": a receive on the chain that is not final yet, and a
    # send the node still holds pending, both wait without a word on the log
    chain.fund(fee, 1000, source="5" * 64, finalized=False)
    chain.pending.append({"send_hash": "7" * 64, "amount": 1000, "asset": "XE"})
    for n in ("5", "7"):
        db.add(FeeLedger(fee_block_hash=n * 64, proposal_hash=n * 64, payer=AUTHOR, amount=1000, state="due_refund", tx_hashes={}))
    await db.commit()
    assert await fees.settle_due(ctx, db) == 0 and chain.submits == []
    for n in ("5", "7"):
        row = await _fee(db, n)
        assert row.state == "due_refund" and row.error == fees.ARRIVING_NOTE, n
    assert (await db.execute(select(Event.kind))).scalars().all().count("fee.unreceived") == 2
    # and once the receive is final the fee is received, and settles
    chain.finalize()
    assert await fees.settle_due(ctx, db) == 1
    assert (await _fee(db, "5")).state == "refunded" and (await _fee(db, "7")).error == fees.ARRIVING_NOTE
    kinds = (await db.execute(select(Event.kind))).scalars().all()
    assert kinds.count("fee.unreceived") == 2 and kinds.count("fee.received") == 1


# ---- XE-0486 / XE-0488: fee writes are exactly-once and every receive is recorded as it lands ----

# The rule (XE-0486, XE-2043, XE-2380): a settlement is one block, on the row before it is offered, and
# the row is settled when the chain holds that block final. Each test below holds the same three things
# at every step, for a refund and for a burn: the chain never carries two settlements for a row, the row
# is terminal only when the chain holds its block, and the hash on the row is the block on the chain.

SETTLEMENTS = [("due_refund", "send", "refund", "refunded"), ("due_burn", "burn", "burn", "burned")]


async def _settled_right(db, chain, fee, type_, key, done, *, on_chain):
    row = await _fee(db)
    out = chain.of(fee, type_)
    assert len(out) == on_chain, f"{len(out)} settlement blocks on the chain"
    final = [b for b in out if b["finalized"]]
    assert (row.state == done) == bool(final), f"row is {row.state}; the chain holds {len(final)} final"
    if final:
        assert row.tx_hashes == {"receive": "9" * 64, key: final[0]["hash"]}
    kinds = (await db.execute(select(Event.kind))).scalars().all()
    assert kinds.count(f"fee.{done}") == len(final)
    return row


@pytest.mark.parametrize("state,type_,key,done", SETTLEMENTS)
async def test_a_settlement_is_offered_as_the_same_block_until_the_chain_holds_it(db, state, type_, key, done):
    ctx, chain, fee = _fee_ctx(funded=1000)
    await _fee_row(db, state)
    sm = async_sessionmaker(db.bind, expire_on_commit=False)
    on_disk = []
    answers = iter(["drop", XeError(503, "service unavailable"), "lose-answer"])

    async def node(block):
        async with sm() as other:   # what another connection sees at the moment the block is offered
            row = (await other.execute(select(FeeLedger))).scalar_one()
            on_disk.append((row.state, (row.tx_hashes.get("settle_block") or {}).get("hash")))
        answer = next(answers)
        if isinstance(answer, Exception):
            raise answer
        return answer
    chain.on_submit = node

    # 1. the node says yes and keeps nothing: nothing is recorded on its word
    assert await fees.settle_due(ctx, db) == 0
    row = await _settled_right(db, chain, fee, type_, key, done, on_chain=0)
    assert row.state == "settling" and row.tx_hashes["settle_block"]["hash"] == chain.submits[0]["hash"]
    # 2. the node refuses without looking: the same block is offered, not a new one, and the row says so
    assert await fees.settle_due(ctx, db) == 0
    row = await _settled_right(db, chain, fee, type_, key, done, on_chain=0)
    assert "did not take it" in row.error, "a block that is not going in is not silent about it"
    # 3. the node takes it and the answer is lost: the chain is asked, and the row is recorded from it
    assert await fees.settle_due(ctx, db) == 1
    row = await _settled_right(db, chain, fee, type_, key, done, on_chain=1)
    assert row.error == ""
    # 4. and nothing more goes out
    assert await fees.settle_due(ctx, db) == 0
    await _settled_right(db, chain, fee, type_, key, done, on_chain=1)
    assert len(chain.submits) == 3 and len({b["hash"] for b in chain.submits}) == 1, "one block, offered three times"
    assert on_disk == [("settling", chain.submits[0]["hash"])] * 3, "the block is on the row before it is offered"
    assert (await chain.balances(fee))["XE"] == 0, "paid once"


@pytest.mark.parametrize("state,type_,key,done", SETTLEMENTS)
async def test_a_settlement_in_flight_is_waited_for_not_paid_again(db, state, type_, key, done):
    """XE-2043: the first block was taken by the node and is not on the chain yet. Not being there is not
    "never sent": the row waits on the same block, and when it lands that is the settlement."""
    ctx, chain, fee = _fee_ctx(funded=1000)
    await _fee_row(db, state)
    in_flight = []

    async def node(block):
        in_flight.append(block)
        return "drop"
    chain.on_submit = node
    assert await fees.settle_due(ctx, db) == 0
    chain.on_submit = None
    chain.land(in_flight[0], finalized=False)             # it arrives, not yet final
    assert await fees.settle_due(ctx, db) == 0
    await _settled_right(db, chain, fee, type_, key, done, on_chain=1)
    # nothing is built on a tip that can still be dropped: a second row waits, with no block of its own
    await _fee_row(db, state, n="2")
    assert await fees.settle_due(ctx, db) == 0
    assert (await _fee(db, "2")).tx_hashes == {"receive": "9" * 64, "settle_as": key}
    chain.finalize()
    assert await fees.settle_due(ctx, db) == 1            # the first row; the second has nothing left to pay from
    await _settled_right(db, chain, fee, type_, key, done, on_chain=1)
    assert len(chain.submits) == 1, "the block that was in flight is the only one ever offered"


@pytest.mark.parametrize("state,type_,key,done", SETTLEMENTS)
async def test_a_settlement_is_rebuilt_only_when_its_block_can_never_land(db, state, type_, key, done):
    ctx, chain, fee = _fee_ctx(funded=1000)
    await _fee_row(db, state)

    async def drop(block):
        return "drop"
    chain.on_submit = drop
    assert await fees.settle_due(ctx, db) == 0
    first = (await _fee(db)).tx_hashes["settle_block"]
    chain.on_submit = None
    # another block takes the tip, not final: the first could still come back, so nothing is built or offered
    chain.fund(fee, 500, source="8" * 64, finalized=False)
    assert await fees.settle_due(ctx, db) == 0
    assert (await _fee(db)).tx_hashes["settle_block"] == first and len(chain.submits) == 1
    # that block is final: the first can never land. It is dropped, and only then is another built
    chain.finalize()
    assert await fees.settle_due(ctx, db) == 0
    row = await _fee(db)
    assert "settle_block" not in row.tx_hashes and "can no longer land" in row.error and len(chain.submits) == 1
    assert await fees.settle_due(ctx, db) == 1
    await _settled_right(db, chain, fee, type_, key, done, on_chain=1)
    second = chain.of(fee, type_)[0]
    assert second["hash"] != first["hash"] and second["previous"] != first["previous"]
    assert (await chain.balances(fee))["XE"] == 500, "the fee went out once; the later receive is untouched"


async def test_a_receive_is_recorded_when_the_chain_holds_it_final_and_from_nothing_else(db):
    """The same rule on the receive (XE-2380, XE-0488): every pending send is offered one, one that fails
    costs itself and nothing behind it, and a fee's receive goes on record when the fee account's chain
    holds it final. Not on the node's word that it took it, and not while it can still be dropped."""
    ctx, chain, fee = _fee_ctx(finalized=False)
    chain.pending = [{"send_hash": h * 64, "source": AUTHOR, "destination": fee, "amount": 1000, "asset": "XE", "timestamp": 0}
                     for h in "12345"]
    for h in "1234":   # the fifth is a send no proposal has named: received, and nothing in the ledger to record it on
        db.add(FeeLedger(fee_block_hash=h * 64, proposal_hash=h * 64, payer=AUTHOR, amount=1000, state="seen", tx_hashes={}))
    await db.commit()

    async def rows():
        got = (await db.execute(select(FeeLedger).execution_options(populate_existing=True))).scalars().all()
        return {r.fee_block_hash[0]: r.tx_hashes for r in got}

    async def received():
        return (await db.execute(select(Event.kind))).scalars().all().count("fee.received")

    async def node(block):
        if block["source"] == "2" * 64:
            raise TimeoutError("anything at all, not only a refusal")
        return {"3" * 64: "drop", "4" * 64: "lose-answer"}.get(block["source"])
    chain.on_submit = node
    assert await fees.receive_all(ctx, db) == 3, "the node said yes to three; one of those it kept nothing of"
    assert {b["source"][0] for b in chain.of(fee, "receive")} == set("145")
    # on the chain and not final: nothing is on record yet, whatever the node answered
    assert await fees.record_receives(ctx, db) == 0
    assert all(v == {} for v in (await rows()).values()) and await received() == 0
    chain.finalize()
    assert await fees.record_receives(ctx, db) == 2
    on_chain = {b["source"][0]: b["hash"] for b in chain.of(fee, "receive")}
    assert await rows() == {"1": {"receive": on_chain["1"]}, "2": {}, "3": {},
                            "4": {"receive": on_chain["4"]}}, "taken with the answer lost: on record; said yes and dropped: not"
    assert await fees.record_receives(ctx, db) == 0 and await received() == 2, "once each"
    # what the node did not take is still pending there, and is received on the next pass
    chain.on_submit = None
    assert await fees.receive_all(ctx, db) == 2
    chain.finalize()
    assert await fees.record_receives(ctx, db) == 2 and await received() == 4
    on_chain = {b["source"][0]: b["hash"] for b in chain.of(fee, "receive")}
    assert await rows() == {k: {"receive": on_chain[k]} for k in "1234"}


async def test_a_settlement_begun_under_the_memo_nonce_scheme_is_not_paid_again(db):
    """A row the release before this one left mid-settlement names its block by a nonce and holds no hash.
    Whether that block went out is not on the row, so nothing is built for it: it stops, saying why."""
    ctx, chain, fee = _fee_ctx(funded=1000)
    db.add(FeeLedger(fee_block_hash="1" * 64, proposal_hash="1" * 64, payer=AUTHOR, amount=1000, state="settling",
                     tx_hashes={"receive": "9" * 64, "settle_as": "refund", "settle_nonce": "ab12cd34"}))
    await db.commit()
    for _ in range(2):
        assert await fees.settle_due(ctx, db) == 0 and chain.submits == []
    row = await _fee(db)
    assert row.state == "settling" and "ab12cd34" in row.error
    assert row.tx_hashes == {"receive": "9" * 64, "settle_as": "refund", "settle_nonce": "ab12cd34"}


async def test_a_due_fee_whose_receive_was_never_recorded_is_found_on_the_chain(db):
    ctx, chain, fee = _fee_ctx()
    recv = chain.fund(fee, 1000, source="1" * 64)
    db.add(FeeLedger(fee_block_hash="1" * 64, proposal_hash="2" * 64, payer=AUTHOR, amount=1000, state="due_burn", tx_hashes={}))
    await db.commit()
    assert await fees.settle_due(ctx, db) == 1
    row = (await db.execute(select(FeeLedger))).scalar_one()
    assert row.state == "burned" and row.tx_hashes == {"receive": recv["hash"], "burn": chain.of(fee, "burn")[0]["hash"]}
    kinds = (await db.execute(select(Event.kind))).scalars().all()
    assert "fee.received" in kinds and "fee.unreceived" not in kinds


# ---- XE-0032 / XE-0080: inbox receipt is private until read; bad bytes are refused --------------

async def test_http_inbox_is_private_until_a_member_reads_it(db):
    ctx = _ctx()
    v = _v(payload={"message": "hello there"})
    m = await inbox.http_submit(ctx, db, v)
    await db.commit()
    ev = (await db.execute(select(Event).where(Event.kind == "inbox.received"))).scalar_one()
    assert ev.public is False and ev.payload["body"] == "hello there"
    assert await EventLog.page(db, kind="inbox.received") == []           # not on the public log
    member = _v(payload={"status": "read"})
    member.seat = SimpleNamespace(id="m1")
    await inbox.set_status(ctx, db, m, member)
    await db.commit()
    pub = (await db.execute(select(Event).where(Event.kind == "inbox.published"))).scalar_one()
    assert pub.public is True and pub.payload["id"] == m.id
    # a second triage does not publish twice
    member2 = _v(payload={"status": "closed"})
    member2.seat = SimpleNamespace(id="m1")
    await inbox.set_status(ctx, db, m, member2)
    await db.commit()
    assert len((await db.execute(select(Event).where(Event.kind == "inbox.published"))).scalars().all()) == 1


async def test_http_inbox_marked_spam_is_never_published(db):
    ctx = _ctx()
    m = await inbox.http_submit(ctx, db, _v(payload={"message": "buy now"}))
    member = _v(payload={"status": "spam"})
    member.seat = SimpleNamespace(id="m1")
    await inbox.set_status(ctx, db, m, member)
    await db.commit()
    assert (await db.execute(select(Event).where(Event.kind == "inbox.published"))).scalar_one_or_none() is None


async def test_http_inbox_refuses_control_characters_and_requires_pow(db):
    ctx = _ctx()
    with pytest.raises(HTTPException) as e:
        await inbox.http_submit(ctx, db, _v(payload={"message": "hi\x00there"}))
    assert e.value.status_code == 400 and "control or format character" in e.value.detail
    ctx.node.chat_pow_difficulty = 0x0100000000000000
    with pytest.raises(HTTPException) as e:
        await inbox.http_submit(ctx, db, _v(payload={"message": "hi"}))
    assert e.value.status_code == 400 and "pow_nonce" in e.value.detail
    assert (await db.execute(select(InboxMessage))).scalar_one_or_none() is None


async def test_http_inbox_stores_a_u64_nonce_and_accepts_real_pow(db):
    from dao.auth import compute_http_pow
    from dao.canonical import DOMAIN_INBOX_HTTP, digest
    ctx = _ctx()
    # upper half of u64: BIGINT would refuse this
    big = _v(payload={"message": "big nonce"})
    big.pow_nonce = 2**64 - 1
    m = await inbox.http_submit(ctx, db, big)
    await db.commit()
    await db.refresh(m)                      # re-read from Postgres, not the identity map
    assert m.pow_nonce == 2**64 - 1
    # a real proof of work over the real signing digest, at a difficulty that keeps the test quick
    ctx.node.chat_pow_difficulty = 0xFF00000000000000
    payload, ts = {"message": "real pow"}, time.time_ns()
    v = _v(payload=payload, ts=ts)
    v.digest = digest(DOMAIN_INBOX_HTTP, {"payload": payload, "timestamp": ts})
    v.pow_nonce = compute_http_pow(v.digest, ctx.node.chat_pow_difficulty)
    m2 = await inbox.http_submit(ctx, db, v)
    await db.commit()
    assert m2.pow_nonce == v.pow_nonce


async def test_proposal_text_with_nul_is_a_400_not_a_500(db):
    ctx = _ctx()
    with pytest.raises(HTTPException) as e:
        await portal.submit(ctx, db, _v(payload={"title": "x\x00y", "body": "fine", "fee_block_hash": "e" * 64}))
    assert e.value.status_code == 400 and "title" in e.value.detail


# ---- XE-0195: the public read surfaces hold an HTTP message back until a member has read it ----

async def test_untriaged_http_messages_are_not_on_the_public_surfaces(db):
    ctx = _ctx()
    m = await inbox.http_submit(ctx, db, _v(payload={"message": "not yet"}))
    chat = InboxMessage(id="chat1", channel="chat", from_account="b" * 64, to_account="d" * 64, body="hi",
                        timestamp=time.time_ns(), verified=True, status="new")
    db.add(chat)
    await db.commit()
    assert [x.id for x in await inbox.list_public(db)] == ["chat1"]      # chat is public on receipt
    assert [x.id for x in await inbox.list_untriaged(db)] == [m.id]
    with pytest.raises(HTTPException) as e:
        await inbox.get_public(db, m.id)
    assert e.value.status_code == 404
    member = _v(payload={"status": "read"})
    member.seat = SimpleNamespace(id="m1")
    await inbox.set_status(ctx, db, m, member)
    await db.commit()
    assert {x.id for x in await inbox.list_public(db)} == {"chat1", m.id}
    assert (await inbox.get_public(db, m.id)).id == m.id
    assert await inbox.list_untriaged(db) == []
    spam = _v(payload={"status": "spam"})
    spam.seat = SimpleNamespace(id="m1")
    await inbox.set_status(ctx, db, chat, spam)
    await db.commit()
    assert [x.id for x in await inbox.list_public(db)] == [m.id]


# ---- XE-0201: a decision follows the tally, names a real resolution, and is recorded once -------

def _closed(ctx, h, outcome, ops=None):
    now = time.time_ns()
    return Proposal(hash=h, title="t", body="b", ops=ops, author_account=AUTHOR, author_pub_key="p" * 64,
                    author_signature="s", author_timestamp=now, fee_block_hash=h, status="closed", opened_at=now - D,
                    closes_at=now - 1, rules=ctx.config.pinned_rules(), analysis=[],
                    result={"outcome": outcome, "participating_wallets": 0, "quorum_wallets": 20})


def _seat(payload, pr=None):
    v = _v(payload={**({"proposal": pr.hash} if pr else {}), **payload})
    v.seat = SimpleNamespace(id="cto")
    return v


def _member(seat, rights=("pause", "sign_resolutions"), key="p" * 64):
    return SimpleNamespace(id=seat, is_member=True, public_key=key, can=lambda r, _rs=frozenset(rights): r in _rs)


async def test_adopt_needs_a_passed_vote_and_is_recorded_once(db):
    from dao.models import Resolution
    ctx = _ctx()
    failed = _closed(ctx, "1" * 64, "no_quorum")
    passed_ops = _closed(ctx, "2" * 64, "passed", ops=[{"action": "set", "key": "dao.test", "value": "1"}])
    db.add_all([failed, passed_ops])
    await db.flush()
    # no quorum: adopt refused, decline recorded, then nothing more
    with pytest.raises(HTTPException) as e:
        await portal.decide(ctx, db, failed, _seat({"decision": "adopt", "reasons": "adopting anyway for the test"}, failed))
    assert e.value.status_code == 409 and "no_quorum" in e.value.detail
    await portal.decide(ctx, db, failed, _seat({"decision": "decline", "reasons": "no quorum was reached"}, failed))
    assert failed.status == "decided" and failed.decision["decision"] == "decline" and failed.decision["outcome"] == "no_quorum"
    with pytest.raises(HTTPException) as e:
        await portal.decide(ctx, db, failed, _seat({"decision": "adopt", "reasons": "flipping the record later"}, failed))
    assert e.value.status_code == 409 and "already recorded" in e.value.detail
    assert failed.decision["decision"] == "decline"
    # passed, carries ops: adopt needs a passed resolution about this proposal with exactly these ops
    with pytest.raises(HTTPException) as e:
        await portal.decide(ctx, db, passed_ops, _seat({"decision": "adopt", "reasons": "adopting without a resolution"}, passed_ops))
    assert e.value.status_code == 409 and "resolution_id" in e.value.detail
    with pytest.raises(HTTPException) as e:
        await portal.decide(ctx, db, passed_ops, _seat({"decision": "adopt", "reasons": "adopting with a fake id",
                                                         "resolution_id": "does-not-exist"}, passed_ops))
    assert e.value.status_code == 400
    res = Resolution(id="r1", number=1, title="adopt", body="b", matter="adopt_open_vote", ops=passed_ops.ops,
                     proposed_by="founder-a", status="open", signatures=[], related_proposal=passed_ops.hash)
    other = Resolution(id="r2", number=2, title="other", body="b", matter="adopt_open_vote", ops=passed_ops.ops,
                       proposed_by="founder-a", status="passed", signatures=[], related_proposal="9" * 64)
    db.add_all([res, other])
    await db.flush()
    for rid, code in (("r1", 409), ("r2", 409)):                           # not passed / not about this proposal
        with pytest.raises(HTTPException) as e:
            await portal.decide(ctx, db, passed_ops, _seat({"decision": "adopt", "reasons": "adopting on a wrong resolution",
                                                             "resolution_id": rid}, passed_ops))
        assert e.value.status_code == code
    res.status = "passed"
    res.ops = [{"action": "set", "key": "dao.other", "value": "1"}]
    await db.flush()
    with pytest.raises(HTTPException) as e:
        await portal.decide(ctx, db, passed_ops, _seat({"decision": "adopt", "reasons": "ops do not match the vote",
                                                         "resolution_id": "r1"}, passed_ops))
    assert "exactly" in e.value.detail
    res.ops = passed_ops.ops
    await db.flush()
    await portal.decide(ctx, db, passed_ops, _seat({"decision": "adopt", "reasons": "passed and resolved",
                                                     "resolution_id": "r1"}, passed_ops))
    await db.commit()
    assert passed_ops.decision["decision"] == "adopt" and passed_ops.decision["resolution_id"] == "r1"
    ev = (await db.execute(select(Event).where(Event.kind == "proposal.decided").order_by(Event.index.desc()))).scalars().first()
    assert ev.payload["outcome"] == "passed" and ev.payload["resolution_id"] == "r1"


# ---- XE-0284: no path to the chain shortens the upgrade timelock -------------------------------

async def test_rebuild_sign_and_submit_wait_for_the_timelock(db):
    ctx = _ctx()

    async def tip():
        return {"index": 0, "hash": "0" * 64, "timestamp": 0}

    ctx.chain.statechain_tip = tip
    now = time.time_ns()
    s = SigningSession(id="s1", kind="parameter", title="R1", ops=[{"action": "set", "key": "dao.test", "value": "1"}],
                       ops_digest="d" * 64, status="approving", approvals=[{"public_key": "k1"}, {"public_key": "k2"}],
                       required_approvals=2, block=None, block_hash="", block_signatures=[], rebuilds=0,
                       not_before=now + 3600 * 1_000_000_000)
    db.add(s)
    await db.flush()
    # the route's own gate passes (approving, threshold met); rebuild itself must refuse
    with pytest.raises(HTTPException) as e:
        await sessions.rebuild(ctx, db, s, actor="seat:cto")
    assert e.value.status_code == 409 and "timelock" in e.value.detail and s.status == "approving" and s.block is None
    # a session somehow in signing with a block is not signed or submitted either
    s.status, s.block, s.block_hash = "signing", {"index": 1, "prev_hash": "0" * 64, "timestamp": now, "hash": "a" * 64}, "a" * 64
    with pytest.raises(HTTPException) as e:
        await sessions.sign(ctx, db, s, "k1", "00" * 64, actor="seat:cto")
    assert e.value.status_code == 409 and "timelock" in e.value.detail
    with pytest.raises(HTTPException) as e:
        await sessions.submit(ctx, db, s)
    assert e.value.status_code == 409 and "timelock" in e.value.detail
    # once the window has run, rebuild goes ahead
    s.status, s.block, s.block_hash = "approving", None, ""
    s.not_before = now - 1
    await sessions.rebuild(ctx, db, s, actor="seat:cto")
    assert s.status == "signing" and s.block["index"] == 1 and s.block_hash
    # no timelock at all (status proposed, mainnet off) is unchanged
    s2 = SigningSession(id="s2", kind="parameter", title="R2", ops=s.ops, ops_digest="e" * 64, status="approving",
                        approvals=s.approvals, required_approvals=2, block=None, block_hash="", block_signatures=[],
                        rebuilds=0, not_before=None)
    db.add(s2)
    await db.flush()
    await sessions.rebuild(ctx, db, s2, actor="seat:cto")
    assert s2.status == "signing"


# ---- a signed payload names what it acts on; approvals are counted against the live keyset -------

async def test_decision_payload_must_name_the_proposal(db):
    ctx = _ctx()
    pr = _closed(ctx, "3" * 64, "no_quorum")
    db.add(pr)
    await db.flush()
    with pytest.raises(HTTPException) as e:
        await portal.decide(ctx, db, pr, _seat({"proposal": "4" * 64, "decision": "decline", "reasons": "signed for another one"}))
    assert e.value.status_code == 400 and "proposal" in e.value.detail and pr.status == "closed"
    await portal.decide(ctx, db, pr, _seat({"decision": "decline", "reasons": "no quorum was reached"}, pr))
    assert pr.status == "decided"


async def test_rebuild_counts_approvals_against_the_live_keyset(db):
    ctx = _ctx()

    async def tip():
        return {"index": 0, "hash": "0" * 64, "timestamp": 0}

    ctx.chain.statechain_tip = tip
    s = SigningSession(id="s3", kind="parameter", title="R3", ops=[{"action": "set", "key": "dao.test", "value": "1"}],
                       ops_digest="f" * 64, status="approving", approvals=[{"public_key": "k1"}, {"public_key": "gone"}],
                       required_approvals=2, block=None, block_hash="", block_signatures=[], rebuilds=0, not_before=None)
    db.add(s)
    await db.flush()
    # two approvals on record, one from a key no longer in the keyset: not enough
    with pytest.raises(HTTPException) as e:
        await sessions.rebuild(ctx, db, s, actor="seat:cto")
    assert e.value.status_code == 409 and "live keyset" in e.value.detail and s.status == "approving"
    s.approvals = [*s.approvals, {"public_key": "k2"}]
    await db.flush()
    await sessions.rebuild(ctx, db, s, actor="seat:cto")
    assert s.status == "signing"


async def test_proposal_ops_are_validated_at_submit(db):
    ctx = _ctx(FakeChain(blocks={"c" * 64: _send(True)}))
    for ops in ([], "x", [{"action": "set"}], [{"action": "delete", "key": "sys.dao_keyset"}],
                [{"action": "set", "key": "not a key!", "value": {"a": 1}}]):
        with pytest.raises(HTTPException) as e:
            await portal.submit(ctx, db, _v(payload={"title": "t", "body": "b", "fee_block_hash": "c" * 64, "ops": ops}))
        assert e.value.status_code == 400, ops


# ---- XE-0600: a resolution counts only current members' signatures --------------------------------

async def test_resolution_counts_only_current_members(db):
    from dao.models import Resolution
    from dao.services import resolutions
    ctx = _ctx()
    ctx.config.members = [_member("founder-a"), _member("founder-b")]
    ctx.config.windows = {}
    # an ordinary matter needs a majority of two: 2. "gone" signed for while a member, then left.
    r = Resolution(id="r9", number=9, title="note", body="b", matter="note", ops=None, proposed_by="founder-a",
                   status="open", signatures=[{"seat": "gone", "public_key": "g", "signature": "s", "decision": "for", "timestamp": 1}])
    db.add(r)
    await db.flush()

    def member(seat, decision):
        v = _v(payload={"resolution_id": "r9", "body_hash": resolutions.body_hash(r), "decision": decision})
        v.seat = _member(seat)
        return v

    await resolutions.decide(ctx, db, r, member("founder-a", "for"), "for")
    assert r.status == "open", "one live vote plus a departed member's vote is not a majority"
    ev = (await db.execute(select(Event).where(Event.kind == "resolution.signed"))).scalars().all()[-1]
    assert ev.payload["for"] == 1 and ev.payload["set_aside"] == ["gone"]
    await resolutions.decide(ctx, db, r, member("founder-b", "for"), "for")
    assert r.status == "passed" and sorted(s["seat"] for s in r.signatures) == ["founder-a", "founder-b"], \
        "passed, and the record holds the signatures that passed it: not the one that never counted"


# ---- XE-0646: a pause counts only current members' signatures -----------------------------------

async def test_pause_lift_ignores_a_departed_members_signature(db):
    from dao.models import PauseRecord
    from dao.services import pause
    ctx = _ctx()
    ctx.config.members = [_member("founder-a"), _member("founder-b")]
    ctx.config.pause = {}
    now = time.time_ns()
    r = PauseRecord(id="p1", determined_by="founder-a", ground="g", determination="d" * 20, started_at=now,
                    expires_at=now + 10 ** 12, indefinite=False, extensions=[], status="active",
                    lifted_by=[{"seat": "gone", "public_key": "g", "signature": "s", "timestamp": 1}])
    db.add(r)
    await db.flush()

    def member(seat):
        v = _v(payload={"pause_id": "p1"})
        v.seat = _member(seat)
        return v

    await pause.lift(ctx, db, r, member("founder-a"))
    assert r.status == "active", "a departed member's signature plus one current member is not every member"
    ev = (await db.execute(select(Event).where(Event.kind == "pause.lift_signed"))).scalars().all()[-1]
    assert ev.payload["signatures"] == 1 and ev.payload["set_aside"] == ["gone"]
    await pause.lift(ctx, db, r, member("founder-b"))
    assert r.status == "lifted" and sorted(s["seat"] for s in r.lifted_by) == ["founder-a", "founder-b"], \
        "lifted, and the record holds the signatures it was lifted with: not the one that never counted"
    # the same rule for an extension
    r2 = PauseRecord(id="p2", determined_by="founder-a", ground="g", determination="d" * 20, started_at=now,
                     expires_at=now + 10 ** 12, indefinite=False, lifted_by=[], status="active",
                     extensions=[{"applied": False, "signatures": [{"seat": "gone", "public_key": "g", "signature": "s", "timestamp": 1}]}])
    db.add(r2)
    await db.flush()
    before = r2.expires_at
    await pause.extend(ctx, db, r2, member("founder-a"))
    assert r2.expires_at == before and not r2.extensions[-1]["applied"]


# ---- XE-0672: a withdrawn resolution takes its session with it -----------------------------------

async def test_withdrawing_a_resolution_cancels_the_session_it_opened(db):
    from dao.models import Resolution
    from dao.services import resolutions
    ctx = _ctx()
    ctx.config.members = [_member("founder-a")]
    s = SigningSession(id="s1", kind="parameter", title="t", ops=[], ops_digest="d", status="approving", approvals=[],
                       required_approvals=2, block=None, block_hash="", block_signatures=[], rebuilds=0, resolution_id="r1")
    r = Resolution(id="r1", number=1, title="t", body="b", matter="note", ops=None, proposed_by="founder-a",
                   status="open", signatures=[], session_id="s1")
    db.add_all([s, r])
    await db.flush()
    v = _v(payload={"resolution_id": "r1"})
    v.seat = _member("founder-a")
    await resolutions.withdraw(ctx, db, r, v)
    assert r.status == "withdrawn" and s.status == "cancelled" and s.error == "resolution withdrawn"
    # and a cancelled session cannot be rebuilt back to life
    with pytest.raises(HTTPException) as e:
        await sessions.rebuild(ctx, db, s)
    assert e.value.status_code == 409


# ---- XE-0740: a burn takes the fee; what was sent above it goes back -----------------------------

async def test_an_overpaid_fee_burns_the_fee_and_returns_the_rest(db):
    ctx, chain, fee = _fee_ctx(funded=1500)
    now = time.time_ns()
    pr = Proposal(hash="a" * 64, title="t", body="b", ops=None, author_account=AUTHOR, author_pub_key="p" * 64,
                  author_signature="s", author_timestamp=now, fee_block_hash="1" * 64, status="closed", opened_at=now - D,
                  closes_at=now - 1, rules=ctx.config.pinned_rules(), analysis=[])
    db.add(pr)
    db.add(FeeLedger(fee_block_hash="1" * 64, proposal_hash="a" * 64, payer=AUTHOR, amount=1500, state="due_burn",
                     tx_hashes={"receive": "9" * 64}))
    await db.commit()
    assert await fees.settle_due(ctx, db) == 1
    (burn,), (back,) = chain.of(fee, "burn"), chain.of(fee, "send")
    assert burn["amount"] == 1000 and burn["memo"].split()[1] == "burn"
    assert (back["destination"], back["amount"]) == (AUTHOR, 500) and back["memo"].split()[1] == "excess"
    assert back["previous"] == burn["hash"], "each phase is its own block, the second built on the first"
    row = (await db.execute(select(FeeLedger))).scalar_one()
    assert row.state == "burned" and row.tx_hashes == {"receive": "9" * 64, "burn": burn["hash"], "excess": back["hash"]}
    kinds = (await db.execute(select(Event.kind))).scalars().all()
    assert kinds.count("fee.burned") == 1 and kinds.count("fee.excess_returned") == 1
    assert (await chain.balances(fee))["XE"] == 0


# ---- XE-0349: keyset rotation runs through a keyset session; nothing can jam at the deciding vote -----

async def test_change_keyset_opens_a_keyset_session_and_bad_ops_are_refused_when_proposed(db):
    from dao.services import resolutions
    ctx = _ctx()
    ctx.config.members = [_member("founder-a")]
    ctx.config.windows = {}
    k1, k2, k3 = (KeyPair.generate().pub_key_hex for _ in range(3))
    k5 = KeyPair.generate().pub_key_hex
    # k3 is nobody's; k5 is held by a seat that may not sign a state-chain block, which is the same thing (XE-2028)
    ctx.config.human_seats = [_member("a", ("sign_statechain",), k1), _member("b", ("sign_statechain",), k2),
                              _member("c", ("pause", "sign_resolutions"), k5)]
    good = [{"action": "set", "key": "sys.dao_keyset", "value": {"keys": [k1, k2, k3], "threshold": 2}}]

    def proposer(payload):
        v = _v(payload=payload)
        v.seat = _member("founder-a")
        return v

    async def refused(matter, ops, why):
        with pytest.raises(HTTPException) as e:
            await resolutions.propose(ctx, db, proposer({"title": "t", "body": "b", "matter": matter, "ops": ops}))
        assert e.value.status_code == 400 and why in e.value.detail, e.value.detail

    await refused("parameter", good, "dao.* keys")                                   # sys.* only through change_keyset
    await refused("change_treasury_policy", [{"action": "set", "key": "sys.treasury_policy", "value": 1}], "dao.* keys")
    await refused("change_keyset", [{"action": "set", "key": "dao.x", "value": 1}], "exactly one op")
    await refused("change_keyset", good + [{"action": "set", "key": "dao.x", "value": 1}], "exactly one op")
    await refused("change_keyset", [{"action": "set", "key": "sys.dao_keyset", "value": {"keys": [k1, k1], "threshold": 2}}], "duplicate")
    await refused("change_keyset", [{"action": "set", "key": "sys.dao_keyset", "value": {"keys": [k1, k2], "threshold": 3}}], "threshold")
    # the node floors the threshold at MIN_DAO_THRESHOLD; the gate states the same rule (XE-1447)
    await refused("change_keyset", [{"action": "set", "key": "sys.dao_keyset", "value": {"keys": [k1, k2], "threshold": 1}}], ">= 2")
    await refused("change_keyset", [{"action": "set", "key": "sys.dao_keyset", "value": {"keys": [k1, k2], "threshold": True}}], "integer")
    await refused("change_keyset", [{"action": "set", "key": "sys.dao_keyset", "value": {"keys": [k1, "0" * 64], "threshold": 2}}], "usable")
    await refused("change_keyset", [{"action": "set", "key": "sys.dao_keyset", "value": {"keys": [k1, k2[:-1] + "G"], "threshold": 2}}], "hex")
    # a keyset the seats cannot meet would end every later session, including the one to change it back (XE-1705)
    await refused("change_keyset", [{"action": "set", "key": "sys.dao_keyset", "value": {"keys": [k1, k3], "threshold": 2}}], "held by a seat")
    k4 = KeyPair.generate().pub_key_hex
    await refused("change_keyset", [{"action": "set", "key": "sys.dao_keyset", "value": {"keys": [k3, k4], "threshold": 2}}], "held by a seat")
    await refused("change_keyset", [{"action": "set", "key": "sys.dao_keyset", "value": {"keys": [k1, k5], "threshold": 2}}], "held by a seat")
    assert sessions.seat_keys_of(ctx.config) == {k1, k2}

    r = await resolutions.propose(ctx, db, proposer({"title": "rotate", "body": "b", "matter": "change_keyset", "ops": good}))
    await db.flush()
    v = proposer({"resolution_id": r.id, "body_hash": resolutions.body_hash(r), "decision": "for"})
    await resolutions.decide(ctx, db, r, v, "for")
    assert r.status == "passed" and r.session_id
    s = await sessions.get(db, r.session_id)
    assert s.kind == "keyset" and s.ops[0]["key"] == "sys.dao_keyset" and s.required_approvals == 2


# ---- XE-0882: a member rebuild only when the tip has moved ---------------------------------------

async def test_member_rebuild_is_refused_at_an_unchanged_tip_so_signatures_stand(db):
    ctx = _ctx()
    tip_hash = ["0" * 64]

    async def tip():
        return {"index": 0, "hash": tip_hash[0], "timestamp": 0}

    ctx.chain.statechain_tip = tip
    s = SigningSession(id="s1", kind="parameter", title="R1", ops=[{"action": "set", "key": "dao.test", "value": "1"}],
                       ops_digest="d" * 64, status="approving", approvals=[{"public_key": "k1"}, {"public_key": "k2"}],
                       required_approvals=2, block=None, block_hash="", block_signatures=[], rebuilds=0)
    db.add(s)
    await db.flush()
    # first build of an approved session: fine
    await sessions.rebuild_if_stale(ctx, db, s, actor="seat:b")
    assert s.status == "signing" and s.block_hash
    s.block_signatures = [{"public_key": "k1", "signature": "00" * 64}]
    h = s.block_hash
    # same tip: refused, the collected signature stays, the hash does not change
    with pytest.raises(HTTPException) as e:
        await sessions.rebuild_if_stale(ctx, db, s, actor="seat:b")
    assert e.value.status_code == 409 and "signatures stand" in e.value.detail
    assert s.block_hash == h and len(s.block_signatures) == 1 and s.rebuilds == 0
    # tip moved: rebuilt, signatures reset as they must be
    tip_hash[0] = "1" * 64
    await sessions.rebuild_if_stale(ctx, db, s, actor="seat:b")
    assert s.block_hash != h and s.block_signatures == [] and s.rebuilds == 1


# ---- XE-0891/0907/0908: health compares against the chain's timestamps and the members' records; fails closed; goes stale

def _health_ctx():
    ctx = _ctx()
    ctx.settings = SimpleNamespace(xe_node_url="http://node")
    ctx.node.network_id = "testnet-x"
    ctx.config.cadence = {"health_check_minutes": 10}
    state = {"ready": True, "tip": {"index": 5, "hash": "5" * 64, "timestamp": time.time_ns()},
             "keyset": {"keys": ["k1", "k2", "k3"], "threshold": 2}, "fail": set()}

    async def ready():
        if "ready" in state["fail"]:
            raise XeError(500, "boom")
        return state["ready"], {"status": "ready"}

    async def tip():
        if "tip" in state["fail"]:
            raise XeError(500, "boom")
        return dict(state["tip"])

    async def keyset():
        if "keyset" in state["fail"]:
            raise XeError(500, "boom")
        return dict(state["keyset"])

    async def directory(_addr):
        return None

    ctx.chain.ready, ctx.chain.statechain_tip, ctx.chain.dao_keyset, ctx.chain.directory = ready, tip, keyset, directory
    return ctx, state


async def _check(ctx, db):
    from dao.services import records
    EventLog._verify_cache = None
    d = await records.health(ctx, db, record=True)
    await db.commit()
    return d


async def test_health_degrades_on_unexpected_keyset_log_tamper_stale_tip_faults_anchor_and_reports_aging(db):
    from datetime import datetime, timedelta, timezone
    from dao.services import records
    ctx, state = _health_ctx()
    await ctx.events.append(db, "x", "harness", {}, public=True)
    await db.commit()

    d = await _check(ctx, db)
    assert d["ok"] and d["keyset"] == {"keys": ["k1", "k2", "k3"], "threshold": 2} and d["log_verified"]
    assert d["sessions_aging"] == [] and d["last_anchor"] is None and "errors" not in d
    # the keyset changes with no keyset session of ours behind it: not ok, on every check, until it is written back
    state["keyset"] = {"keys": ["K9", "k2", "k3"], "threshold": 3}
    d = await _check(ctx, db)
    assert not d["ok"] and d["keyset_unexpected"]["expected"]["threshold"] == 2 and d["keyset_unexpected"]["live"]["threshold"] == 3
    assert (await db.execute(select(Event).where(Event.kind == "keyset.changed"))).scalars().first() is not None
    assert not (await _check(ctx, db))["ok"]
    # a keyset fetch fault fails closed on its own
    state["fail"].add("keyset")
    d = await _check(ctx, db)
    assert not d["ok"] and d["errors"] == ["keyset_error"] and "keyset" not in d
    state["fail"].discard("keyset")
    # reverting clears it
    state["keyset"] = {"keys": ["k3", "k2", "k1"], "threshold": 2}
    assert (await _check(ctx, db))["ok"]
    # a keyset the members wrote through a keyset session is the expected one from then on
    db.add(SigningSession(id="ks1", kind="keyset", title="rotate", status="submitted", ops_digest="a" * 64,
                          ops=[{"action": "set", "key": "sys.dao_keyset",
                                "value": '{"keys":["k2","k3"],"threshold":2}'}],
                          approvals=[], required_approvals=2, block=None, block_hash="", block_signatures=[], rebuilds=0))
    await db.flush()
    assert not (await _check(ctx, db))["ok"]          # session submitted, chain not yet showing it
    state["keyset"] = {"keys": ["k3", "k2"], "threshold": 2}
    assert (await _check(ctx, db))["ok"]
    # a tampered event fails the replay
    ev = (await db.execute(select(Event).where(Event.index == 0))).scalar_one()
    original = ev.payload
    ev.payload = {"tampered": True}
    await db.flush()
    d = await _check(ctx, db)
    assert not d["ok"] and d["log_verified"] is False and d["log_first_error"]
    ev.payload = original
    await db.flush()
    assert (await _check(ctx, db))["ok"]
    # a tip older than the allowance is a chain that is not advancing
    state["tip"]["timestamp"] = time.time_ns() - (records.TIP_STALE_S + 60) * 1_000_000_000
    d = await _check(ctx, db)
    assert not d["ok"] and d["tip_stale"]
    state["tip"]["timestamp"] = time.time_ns()
    assert (await _check(ctx, db))["ok"]
    # every fetch fault fails closed (XE-0907)
    for leg, err in (("ready", "node_error"), ("tip", "statechain_error"), ("keyset", "keyset_error")):
        state["fail"] = {leg}
        d = await _check(ctx, db)
        assert not d["ok"] and d["errors"] == [err], (leg, d)
    state["fail"] = set()
    assert (await _check(ctx, db))["ok"]
    # an anchor older than the allowance degrades
    db.add(Anchor(n=1, event_index=0, head_hash="h" * 64, session_id="a1",
                  created_at=datetime.now(timezone.utc) - timedelta(seconds=records.ANCHOR_OVERDUE_S + 60)))
    await db.flush()
    d = await _check(ctx, db)
    assert not d["ok"] and d["anchor_overdue"] and d["last_anchor"]["n"] == 1
    db.add(Anchor(n=2, event_index=1, head_hash="i" * 64, session_id="a2"))
    await db.flush()
    assert (await _check(ctx, db))["ok"]
    # a session approving for longer than a day is reported
    old = SigningSession(id="old1", kind="parameter", title="R", ops=[{"action": "set", "key": "dao.t", "value": "1"}],
                         ops_digest="b" * 64, status="signing", approvals=[], required_approvals=2, block=None,
                         block_hash="h", block_signatures=[{"public_key": "k1", "signature": "s"}], rebuilds=0,
                         created_at=datetime.now(timezone.utc) - timedelta(days=30))
    db.add(old)
    await db.flush()
    d = await _check(ctx, db)
    assert d["ok"] and d["sessions_aging"] == [{"id": "old1", "kind": "parameter", "status": "signing", "signatures": 1, "required": 2}]


async def test_health_endpoint_goes_stale_when_the_worker_stops_and_uptime_counts_missing_checks(db):
    from dao.services import records
    ctx, state = _health_ctx()
    assert records.health_is_stale(ctx, None)
    d = await _check(ctx, db)
    assert not records.health_is_stale(ctx, d) and records.health_age_s(d) == 0
    up = await records.uptime_30d(ctx, db)
    assert up["checks"] == 1 and up["expected"] == 1 and up["fraction"] == 1.0
    # the worker stops: the last row is ok, the endpoint is not
    row = (await db.execute(select(HealthCheck).order_by(HealthCheck.ts.desc()).limit(1))).scalar_one()
    row.ts = time.time_ns() - 48 * 3600 * 1_000_000_000
    row.detail = {**row.detail, "ts": row.ts}
    await db.flush()
    last = await records.last_health(db)
    assert last["ok"] and records.health_is_stale(ctx, last) and records.health_age_s(last) >= 48 * 3600
    up = await records.uptime_30d(ctx, db)
    assert up["checks"] == 1 and up["expected"] == 48 * 6 and up["fraction"] < 0.01


# ---- XE-0960: a vote is written under the proposal's row lock, read without it ------------------

async def test_vote_write_sees_a_close_that_landed_during_the_snapshot_read(db):
    """The node read happens on an unlocked copy of the proposal; the write re-loads it FOR UPDATE and
    re-checks the window, so a proposal closed while the snapshot was in flight takes no vote, and the
    account's existing vote is compared under the same lock."""
    ctx = _ctx()
    now = time.time_ns()
    pr = Proposal(hash="c" * 64, title="t", body="b", ops=None, author_account=AUTHOR, author_pub_key="p" * 64,
                  author_signature="s", author_timestamp=now, fee_block_hash="c" * 64, status="open", opened_at=now,
                  closes_at=now + D, rules=ctx.config.pinned_rules(), analysis=[])
    db.add(pr)
    await db.commit()
    stale = await portal.get(db, pr.hash)            # the unlocked copy the route loads

    async def closing_chain(account):
        # the worker closes the proposal while the voter's chain is being read
        sm = async_sessionmaker(db.bind, expire_on_commit=False)
        async with sm() as other:
            row = await portal.get(other, pr.hash, lock=True)
            row.status = "closed"
            await other.commit()
        return [{"timestamp": 0, "asset": "XE", "balance": 5_000_000, "hash": "b" * 64}]

    ctx.chain.full_chain = closing_chain
    with pytest.raises(HTTPException) as e:
        await portal.vote(ctx, db, stale, _v(payload={"proposal": pr.hash, "choice": "for"}))
    assert e.value.status_code == 409 and "closed" in e.value.detail
    await db.rollback()
    assert (await db.execute(select(Vote))).scalars().all() == []


# ---- XE-0988: a signing session the keyset moved under goes back to approving --------------------

async def test_signing_session_short_of_live_approvals_returns_to_approving(db):
    ctx = _ctx()
    ctx.chain.statechain_tip = lambda: _tip_at(1)
    s = SigningSession(id="s9", kind="parameter", title="R", ops=[{"action": "set", "key": "dao.test", "value": "1"}],
                       ops_digest="f" * 64, status="signing", approvals=[{"public_key": "k1"}, {"public_key": "gone"}],
                       required_approvals=2, block={"index": 1, "prev_hash": "0" * 64, "timestamp": 0, "hash": "h" * 64},
                       block_hash="h" * 64, block_signatures=[{"public_key": "k1", "signature": "s"}], rebuilds=0, not_before=None)
    db.add(s)
    await db.flush()
    await sessions.rebuild(ctx, db, s)
    assert s.status == "approving" and s.block is None and s.block_hash == "" and s.block_signatures == []
    ev = (await db.execute(select(Event).where(Event.kind == "session.reapproval_needed"))).scalars().one()
    assert ev.payload["live_approvals"] == 1 and ev.payload["required"] == 2
    # an approving session short of approvals is still refused, as before
    with pytest.raises(HTTPException) as e:
        await sessions.rebuild(ctx, db, s)
    assert e.value.status_code == 409


async def _tip_at(index):
    return {"index": index, "hash": str(index) * 64, "timestamp": 0}


# ---- XE-1176 / XE-1013 / XE-0991 / XE-1172: the pause ------------------------------------------

async def test_one_active_pause_is_enforced_by_the_database(db):
    from dao.models import PauseRecord
    from dao.services import pause
    ctx = _ctx()
    ctx.config.members = [_member("founder-a"), _member("founder-b")]
    ctx.config.pause = {"grounds": ["g"]}

    def det(seat):
        v = _v(payload={"ground": "g", "determination": "d" * 20})
        v.seat = _member(seat)
        return v

    r = await pause.start(ctx, db, det("founder-a"))
    await db.commit()
    # a second start in another session, as two members pausing at once would be, is a 409 from the index
    sm = async_sessionmaker(db.bind, expire_on_commit=False)
    async with sm() as other:
        with pytest.raises(HTTPException) as e:
            await pause.start(ctx, other, det("founder-b"))
        assert e.value.status_code == 409
        await other.rollback()
    assert len((await db.execute(select(PauseRecord).where(PauseRecord.status == "active"))).scalars().all()) == 1
    # a lapsed pause is expired by the start that follows it, not left to the worker
    r.expires_at = time.time_ns() - 1
    await db.commit()
    r2 = await pause.start(ctx, db, det("founder-b"))
    await db.commit()
    assert r.status == "expired" and r2.status == "active"


async def test_pause_consent_counts_only_members_who_hold_the_right_and_post_needs_an_active_pause(db):
    from dao.models import PauseRecord
    from dao.services import pause
    ctx = _ctx()
    ctx.config.members = [_member("founder-a"), _member("founder-b"), _member("founder-c", rights=())]
    ctx.config.pause = {}
    now = time.time_ns()
    r = PauseRecord(id="p1", determined_by="founder-a", ground="g", determination="d" * 20, started_at=now,
                    expires_at=now + 10 ** 12, indefinite=False, extensions=[], lifted_by=[], status="active")
    db.add(r)
    await db.flush()

    def member(seat):
        v = _v(payload={"pause_id": "p1", "text": "the public post text"})
        v.seat = _member(seat)
        return v

    await pause.lift(ctx, db, r, member("founder-a"))
    assert r.status == "active"
    await pause.lift(ctx, db, r, member("founder-b"))
    assert r.status == "lifted", "the member without the pause right cannot sign, so is not counted"
    with pytest.raises(HTTPException) as e:
        await pause.set_post(ctx, db, r, member("founder-a"))
    assert e.value.status_code == 409


async def test_settlement_receives_and_outbox_read_the_pause_right_before_the_chain_write(db, monkeypatch):
    from dao.models import OutboxMessage, PauseRecord
    ctx, chain, fee = _fee_ctx(funded=1000)
    now = time.time_ns()
    db.add(FeeLedger(fee_block_hash="1" * 64, proposal_hash="2" * 64, payer=AUTHOR, amount=1000, state="due_burn",
                     tx_hashes={"receive": "r" * 64}))
    db.add(Proposal(hash="2" * 64, title="t", body="b", ops=None, author_account=AUTHOR, author_pub_key="p" * 64,
                    author_signature="s", author_timestamp=now, fee_block_hash="2" * 64, status="closed", opened_at=now,
                    closes_at=now, rules=ctx.config.pinned_rules(), analysis=[]))
    db.add(OutboxMessage(id="o1", to_account="d" * 64, body="hello", status="queued", in_reply_to="m1", from_seat="cto",
                         envelope={}, error=""))
    await db.commit()
    sent = []
    pauses = (f"p{i}" for i in range(1, 9))

    async def pause_now():
        # a pause committed after the job began and before the chain write
        db.add(PauseRecord(id=next(pauses), determined_by="founder-a", ground="g", determination="d" * 20, started_at=now,
                           expires_at=now + 10 ** 12, indefinite=False, extensions=[], lifted_by=[], status="active"))
        await db.commit()

    async def lift():
        for r in (await db.execute(select(PauseRecord).where(PauseRecord.status == "active"))).scalars().all():
            r.status = "lifted"
        await db.commit()

    ctx.signer._kp["dao"] = KeyPair.generate()
    fee_due = fees._fee_due

    async def fee_due_then_pause(db_, f):
        await pause_now()
        return await fee_due(db_, f)

    # 1. the pause lands on the last await before the burn is built: the row is marked, nothing is signed
    monkeypatch.setattr(fees, "_fee_due", fee_due_then_pause)
    assert await fees.settle_due(ctx, db) == 0
    f = (await db.execute(select(FeeLedger))).scalar_one()
    assert f.state == "settling" and "settle_block" not in f.tx_hashes and not f.error and chain.submits == []
    # 2. the pause lands while the block is being built and worked: it is on the row, and is not offered
    monkeypatch.setattr(fees, "_fee_due", fee_due)
    await lift()
    build = fees.chainops.build_burn

    async def build_then_pause(*a, **k):
        block = await build(*a, **k)
        await pause_now()
        return block
    monkeypatch.setattr(fees.chainops, "build_burn", build_then_pause)
    assert await fees.settle_due(ctx, db) == 0
    stored = f.tx_hashes["settle_block"]["hash"]
    assert stored and chain.submits == [], "built before the pause, not offered under it"
    monkeypatch.setattr(fees.chainops, "build_burn", build)
    await lift()

    # 3. a block already on the row is not offered again while a pause is in force
    async def drop(block):
        return "drop"
    chain.on_submit = drop
    assert await fees.settle_due(ctx, db) == 0 and [b["hash"] for b in chain.submits] == [stored]
    await pause_now()
    assert await fees.settle_due(ctx, db) == 0 and len(chain.submits) == 1, "the stored block waits for the pause to end"
    await lift()

    # 4. a run of receives: the pause lands while the first is at the node, and the two behind it are not offered (XE-2483)
    chain.pending = [{"send_hash": h * 64, "source": AUTHOR, "destination": fee, "amount": 10, "asset": "XE", "timestamp": 0}
                     for h in "567"]

    async def take_then_pause(block):
        await pause_now()
    chain.on_submit = take_then_pause
    assert await fees.receive_all(ctx, db) == 1 and len(chain.submits) == 2
    await lift()

    # 5. the same for a queued reply: the pause lands while the envelope's proof of work is being computed
    async def work_then_pause(fn, *a):
        env = fn(*a)
        await pause_now()
        return env

    async def wrote(env):
        sent.append(env)
    ctx.chain.chat_send = wrote
    monkeypatch.setattr(inbox, "asyncio", SimpleNamespace(to_thread=work_then_pause))
    assert await inbox.flush_outbox(ctx, db) == 0
    o = (await db.execute(select(OutboxMessage))).scalar_one()
    assert o.status == "queued" and o.envelope == {} and not sent, "no envelope is in play: nothing was offered"


# ---- XE-0990: an anchor that never reached the chain leaves no row ---------------------------------

async def test_cancelled_or_failed_anchor_session_removes_its_anchor_row(db):
    from dao.services import records
    ctx = _ctx()
    ctx.settings = SimpleNamespace(public_base_url="http://dao")
    ctx.config.members = [_member("founder-a")]
    await ctx.events.append(db, "x", "harness", {}, public=True)
    out = await records.open_anchor_session(ctx, db)
    s = await sessions.get(db, out["id"])
    assert (await records.latest_anchor(db)).n == 1 and await records.latest_anchor(db, written=True) is None
    v = _v(payload={"session_id": s.id})
    v.seat = _member("founder-a")
    await sessions.cancel(ctx, db, s, v, "not this week")
    await db.commit()
    db.expunge_all()
    assert await records.latest_anchor(db) is None
    # the next session takes n = 1 again, and only a submitted one is seen by health
    out2 = await records.open_anchor_session(ctx, db)
    assert (await records.latest_anchor(db)).n == 1
    await records.note_anchor_submitted(db, out2["id"], 7, "7" * 64)
    assert (await records.latest_anchor(db, written=True)).n == 1


# ---- XE-1003: the snapshot carries tainted XE forward and spends it first ------------------------

async def test_snapshot_taint_is_spent_by_later_sends_and_other_assets_are_not_looked_up(db):
    from dao.chainops import CAUSAL_CHECK_NS, account_snapshot
    at = 10 ** 15
    blocks = {"late": {"timestamp": at + 1}, "early": {"timestamp": at - 10}}
    chain = FakeChain(blocks=blocks, chains={
        "v": [{"timestamp": at - CAUSAL_CHECK_NS - 1, "asset": "XE", "balance": 500, "hash": "b0", "type": "open"},
              {"timestamp": at - 5, "asset": "XE", "balance": 1500, "hash": "b1", "type": "receive", "source": "late"},
              {"timestamp": at - 4, "asset": "XE", "balance": 500, "hash": "b2", "type": "send"},
              {"timestamp": at - 3, "asset": "XE", "balance": 700, "hash": "b3", "type": "receive", "source": "early"},
              {"timestamp": at - 2, "asset": "XE", "balance": 1700, "hash": "b4", "type": "receive", "source": "late"},
              {"timestamp": at + 1, "asset": "XE", "balance": 1, "hash": "b5", "type": "send"}],
        "w": [{"timestamp": at - 1, "asset": "XUSD", "balance": 9, "hash": "c0", "type": "receive", "source": "late"}],
    })
    v = await account_snapshot(chain, "v", at)
    # 500 clean; +1000 tainted; the 1000 send spends the taint; +200 clean; +1000 tainted again
    assert v["balance"] == 700 and v["excluded_receives"] == ["b1", "b4"] and v["snapshot_block"] == "b3" and v["exists"]
    # a receive of another asset carries no weight and costs no lookup: the wallet exists, holds no XE (XE-1589)
    looked = []

    async def counting(h):
        looked.append(h)
        return blocks[h]
    chain.block = counting
    w = await account_snapshot(chain, "w", at)
    assert w["exists"] and w["balance"] == 0 and w["excluded_receives"] == [] and looked == []


# ---- XE-1290 / XE-1435: values computed then inserted are serialised; a unique collision is a 409 ---------

async def test_concurrent_allocations_take_consecutive_numbers_and_a_reused_fee_block_is_a_clean_409(db):
    import asyncio

    from dao.db import serialize
    from dao.services import records, resolutions
    ctx = _ctx()
    ctx.settings = SimpleNamespace(public_base_url="http://dao")
    ctx.config.members = [_member("founder-a")]
    await ctx.events.append(db, "x", "harness", {}, public=True)
    await db.commit()
    sm = async_sessionmaker(db.bind, expire_on_commit=False)

    # anchors: the first open holds the number until it commits; the second waits, then takes the next one
    async def open_other():
        async with sm() as other:
            out = await records.open_anchor_session(ctx, other, actor="founder-b")
            await other.commit()
            return out["title"]
    first = await records.open_anchor_session(ctx, db)
    second = asyncio.create_task(open_other())
    await asyncio.sleep(0.3)
    assert not second.done(), "the second open must wait for the first to commit"
    await db.commit()
    assert first["title"].startswith("Anchor 1:") and (await second).startswith("Anchor 2:")
    ns = sorted(a.n for a in (await db.execute(select(Anchor))).scalars().all())
    assert ns == [1, 2]

    # resolution numbers: the same, through _next_number
    async def number_other():
        async with sm() as other:
            n = await resolutions._next_number(other)
            await other.commit()
            return n
    assert await resolutions._next_number(db) == 1
    db.add(Resolution(id="r1", number=1, title="t", body="b", matter="parameter", ops=[], proposed_by="founder-a"))
    task = asyncio.create_task(number_other())
    await asyncio.sleep(0.3)
    assert not task.done()
    await db.commit()
    assert await task == 2

    # a fee block: the second submit waits for the first, then sees its row and gets the 409 it would have got
    # had it arrived later, not an IntegrityError at the insert
    now = time.time_ns()
    ctx.chain.blocks["c" * 64] = _send(True)
    await serialize(db, "fee:" + "c" * 64)
    db.add(Proposal(hash="9" * 64, title="t", body="b", ops=None, author_account=AUTHOR, author_pub_key="p" * 64,
                    author_signature="s", author_timestamp=now, fee_block_hash="c" * 64, status="open", opened_at=now,
                    closes_at=now + D, rules=ctx.config.pinned_rules(), analysis=[]))

    async def verify_other():
        async with sm() as other:
            try:
                await portal._verify_fee(ctx, other, "c" * 64, AUTHOR, 1000)
            except HTTPException as e:
                return e.status_code, e.detail
            return None
    task = asyncio.create_task(verify_other())
    await asyncio.sleep(0.3)
    assert not task.done()
    await db.commit()
    assert await task == (409, "this fee block has already been used")


async def test_a_unique_key_collision_answers_409_on_every_route():
    """The rule in one place: the app maps IntegrityError to 409 before StatementError can make it a 500."""
    from sqlalchemy.exc import IntegrityError, StatementError

    from dao.main import app
    assert issubclass(IntegrityError, StatementError), "the ordering this test guards"
    handler = app.exception_handlers[IntegrityError]
    req = SimpleNamespace(method="POST", url=SimpleNamespace(path="/v1/proposals"), headers={})
    resp = await handler(req, IntegrityError("INSERT", {}, Exception('duplicate key value violates unique constraint "fee_ledger_pkey"')))
    assert resp.status_code == 409


# ---- XE-1445: the pause stops every node write the worker can make, bar the one that keeps it addressable --

async def test_no_worker_job_writes_to_the_node_while_paused_except_directory_reregistration(db, monkeypatch):
    from contextlib import asynccontextmanager
    from pathlib import Path

    from dao import worker as worker_mod
    from dao.models import PauseRecord

    # the chain's write methods, read from the client so a new one cannot arrive unlisted
    src = Path(worker_mod.__file__).parent.parent.joinpath("xe", "client.py").read_text()
    chunks = src.split("    async def ")[1:]
    writers = {c.split("(", 1)[0] for c in chunks if "self._post_" in c and not c.startswith("_")}
    assert writers == {"submit_block", "submit_statechain_block", "directory_register", "chat_send"}, writers

    calls = []

    class Chain(FakeChain):
        def __getattr__(self, name):
            if name in writers:
                async def record(*a, **k):
                    calls.append(name)
                return record
            raise AttributeError(name)

        async def chat_messages(self, *a, **k):
            return []

        async def statechain_tip(self):
            return None

        # a fee account with a send waiting to be received and XE to settle from, so the fee job has both
        # of its writes to make and is quiet under the pause for no other reason
        tip_block = {"hash": "7" * 64, "finalized": True}

        async def pending_for(self, account):
            return [{"send_hash": "5" * 64, "source": AUTHOR, "destination": account, "amount": 10, "asset": "XE", "timestamp": 0}]

        async def chain(self, account, offset=0, limit=1000):
            return {"blocks": [self.tip_block][offset:offset + limit], "total": 1}

        async def chain_end(self, account):
            return 1, self.tip_block

        async def tip(self, account):
            return self.tip_block["hash"]

        async def balances(self, account):
            return {"XE": 5000}

    ctx = _ctx(chain=Chain())
    ctx.signer = FakeSigner(("harness", "fee", "dao"))
    ctx.node = SimpleNamespace(chat_pow_difficulty=0, pow_difficulty=0, network_id="xe-test")
    ctx.directory_node_peer = "12D3KooWTestPeer"
    ctx.settings = SimpleNamespace(public_base_url="http://dao")
    ctx.config.members = [_member("founder-a")]
    ctx.config.pause = {}
    sm = async_sessionmaker(db.bind, expire_on_commit=False)

    @asynccontextmanager
    async def fake_session():
        async with sm() as s:
            yield s
    monkeypatch.setattr(worker_mod, "session", fake_session)
    now = time.time_ns()
    db.add(PauseRecord(id="p1", determined_by="founder-a", ground="g", determination="d" * 20, started_at=now,
                       expires_at=now + 10 ** 12, indefinite=False, extensions=[], lifted_by=[], status="active",
                       post_text="posted", posted_at=now))
    await _fee_row(db, "due_burn")
    # and the outbox has both of its sends to make: a reply not yet built, and one whose envelope is in play
    from dao.models import OutboxMessage
    db.add_all([OutboxMessage(id="q1", to_account="c" * 64, body="queued", status="queued", in_reply_to="m", from_seat="harness",
                              envelope={}, error=""),
                OutboxMessage(id="s1", to_account="c" * 64, body="in play", status="sending", in_reply_to="m", from_seat="harness",
                              envelope={"id": "e" * 64, "timestamp": now, "message": "in play", "to": "c" * 64}, error="")])
    await db.commit()

    w = worker_mod.Worker(ctx)
    for job in (w.job_fees, w.job_outbox, w.job_timers, w.job_sessions, w.job_anchor):
        await job()
    assert calls == [], f"node writes under pause: {calls}"
    # the directory entry is addressability, not action: it is kept alive through the pause so the inbox,
    # which the pause keeps open, can still be reached
    await w.job_directory()
    assert calls == ["directory_register"]

    # The fee job had work it did not do. With the pause over it makes both writes, a receive and a
    # settlement; and never while another fee pass is running, here or in another process.
    from dao.db import only_one
    calls.clear()
    (await db.execute(select(PauseRecord))).scalar_one().status = "lifted"
    await db.commit()
    async with only_one(db, "worker:fees") as first, only_one(db, "worker:fees") as second:
        assert first and not second
        await w.job_fees()
    assert calls == [], "a second fee pass does nothing while the first holds the job"
    await w.job_fees()
    assert calls == ["submit_block", "submit_block"]
    # the outbox the same: one pass at a time, and with the pause over the envelope in play is offered again
    # as it is and the queued reply is built and sent
    calls.clear()
    async with only_one(db, "worker:outbox") as first:
        assert first
        await w.job_outbox()
    assert calls == [], "a second outbox pass does nothing while the first holds the job"
    await w.job_outbox()
    assert calls == ["chat_send", "chat_send"]
    left = {o.id: o.status for o in (await db.execute(select(OutboxMessage).execution_options(populate_existing=True))).scalars().all()}
    assert left == {"q1": "sent", "s1": "sent"}


# ---- XE-1254: the public surfaces carry only what the harness verified ----------------------------------

async def test_an_envelope_that_fails_verification_is_kept_but_never_public(db):
    import dataclasses

    from xe.chat import new_envelope
    ctx = _ctx()
    kp = KeyPair.generate()
    good = new_envelope(kp, "d" * 64, "hello from a verified key", difficulty=0)
    forged = dataclasses.replace(new_envelope(kp, "d" * 64, "statement attributed to a member", difficulty=0),
                                 from_="m" * 64)    # the id and signature no longer match the claimed sender
    m_good = await inbox.store_envelope(ctx, db, good)
    m_bad = await inbox.store_envelope(ctx, db, forged)
    await db.commit()
    assert m_good.verified and not m_bad.verified and m_bad.status == "new"
    # stored (so the id is never fetched again), but not on the public list, the public thread, or the public log
    assert await inbox.store_envelope(ctx, db, forged) is None
    assert inbox.is_public(m_good) and not inbox.is_public(m_bad)
    assert [m.id for m in await inbox.list_public(db)] == [good.id]
    with pytest.raises(HTTPException) as e:
        await inbox.get_public(db, forged.id)
    assert e.value.status_code == 404
    public = {ev.payload["id"]: ev.public for ev in (await db.execute(select(Event).where(Event.kind == "inbox.received"))).scalars().all()}
    assert public == {good.id: True, forged.id: False}
    # members still see it, marked
    assert {m.id: m.verified for m in await inbox.list_messages(db)} == {good.id: True, forged.id: False}


# ---- XE-1487: a delivered reply is committed before the next is built ------------------------------------

async def test_each_outbox_row_is_committed_as_it_is_sent(db, monkeypatch):
    from dao.models import OutboxMessage
    ctx = _ctx()
    ctx.signer = FakeSigner(("harness", "fee", "dao"))
    for i in range(3):
        db.add(OutboxMessage(id=f"o{i}", to_account="d" * 64, body="hi", status="queued", in_reply_to="m", from_seat="cto",
                             envelope={}, error=""))
    await db.commit()
    on_disk = []
    sm = async_sessionmaker(db.bind, expire_on_commit=False)

    async def send(env):
        # what another connection sees at the moment each envelope goes out: every earlier row already `sent`
        async with sm() as other:
            rows = (await other.execute(select(OutboxMessage.status).where(OutboxMessage.status == "sent"))).scalars().all()
        on_disk.append(len(rows))
        if len(on_disk) == 2:
            raise RuntimeError("channel closed")
    ctx.chain.chat_send = send
    assert await inbox.flush_outbox(ctx, db) == 2
    assert on_disk == [0, 1, 1], "each delivered row was committed before the next envelope was built"
    rows = (await db.execute(select(OutboxMessage))).scalars().all()
    assert sorted(o.status for o in rows) == ["sending", "sent", "sent"]
    # the send that raised says nothing about delivery: the row keeps its envelope and is not `queued` again
    stuck = next(o for o in rows if o.status == "sending")
    assert stuck.envelope["id"] and "channel closed" in stuck.error


# ---- XE-1511: a session whose block is on the chain is submitted, whatever the node said ------------------

async def _signing(db, sid, index=1, n=1):
    s = SigningSession(id=sid, kind="anchor", title="A", ops=[{"action": "set", "key": "dao.anchor.1", "value": "1"}],
                       ops_digest="f" * 64, status="signing", approvals=[{"public_key": "k1"}, {"public_key": "k2"}],
                       required_approvals=2, block={"index": index, "prev_hash": "0" * 64, "timestamp": 0, "hash": "h" * 64},
                       block_hash="h" * 64, block_signatures=[{"public_key": "k1", "signature": "s"}, {"public_key": "k2", "signature": "s"}],
                       rebuilds=0, not_before=None)
    db.add(s)
    db.add(Anchor(n=n, event_index=0, head_hash="0" * 64, session_id=sid))
    await db.flush()
    return s


async def test_a_refused_submit_whose_block_landed_is_submitted_and_a_rebuild_never_rewrites_it(db):
    from dao.services import records
    ctx = _ctx()

    async def refuse(blk):
        raise XeError(400, "block rejected: publish: context canceled")
    ctx.chain.submit_statechain_block = refuse
    # 1. the node refused, and the chain does not have the block: failed, as before, and the anchor row goes
    s1 = await _signing(db, "s1")
    await sessions.submit(ctx, db, s1)
    assert s1.status == "failed" and await records.latest_anchor(db) is None
    # 2. the node refused, but the chain has the block at its index: submitted, the anchor row stays
    s2 = await _signing(db, "s2")
    ctx.chain.state_blocks[1] = {"index": 1, "hash": "h" * 64}
    await sessions.submit(ctx, db, s2)
    assert s2.status == "submitted" and s2.submitted_index == 1 and s2.submitted_hash == "h" * 64
    assert (await records.latest_anchor(db)).session_id == "s2"
    # 3. the node refused and the chain cannot be read: the session stays signing with the error on record
    s3 = await _signing(db, "s3", index=2, n=2)

    async def down(i):
        raise XeError(503, "node down")
    ctx.chain.statechain_block = down
    await sessions.submit(ctx, db, s3)
    assert s3.status == "signing" and "could not confirm" in s3.error
    assert (await db.execute(select(Event).where(Event.kind == "session.submit_deferred"))).scalars().first() is not None
    # 4. the tip moved because this block is the tip: a rebuild marks it submitted rather than building the ops again
    ctx.chain.statechain_block = FakeChain.statechain_block.__get__(ctx.chain)
    ctx.chain.state_blocks[2] = {"index": 2, "hash": "h" * 64}
    await sessions.rebuild(ctx, db, s3)
    assert s3.status == "submitted" and s3.submitted_index == 2


# ---- XE-1561 / XE-1565: pending work is asked of the table, not of a page -----------------------------------

async def test_pending_sessions_and_untriaged_messages_are_found_past_any_page(db):
    from datetime import datetime, timedelta, timezone
    now = time.time_ns()
    # dated: rows made in one transaction share one `created_at`, and which hundred of them a page holds
    # is then the database's choice
    old = SigningSession(id="anchor-old", kind="anchor", title="A", ops=[], ops_digest="f" * 64, status="approving", approvals=[],
                         required_approvals=2, block=None, block_hash="", block_signatures=[], rebuilds=0, not_before=None,
                         created_at=datetime.now(timezone.utc) - timedelta(days=1))
    db.add(old)
    await db.flush()
    for i in range(120):
        db.add(SigningSession(id=f"r{i}", kind="registry", title="R", ops=[], ops_digest="f" * 64, status="cancelled", approvals=[],
                              required_approvals=2, block=None, block_hash="", block_signatures=[], rebuilds=0, not_before=None))
    for i in range(120):
        db.add(InboxMessage(id=f"m{i}", channel="http", from_account="a" * 64, to_account="d" * 64, pub_key="p" * 64, body="x",
                            timestamp=now + i, signature="s", pow_nonce=0, verified=True, status="new"))
    await db.commit()
    page = await sessions.list_sessions(db)
    assert len(page) == 100 and "anchor-old" not in {s.id for s in page}, "the page cannot see it"
    assert [s.id for s in await sessions.open_sessions(db, kind="anchor")] == ["anchor-old"]
    assert await sessions.count_sessions(db) == 121 and await sessions.count_sessions(db, "approving") == 1
    # the untriaged queue: oldest first, counted in full, pageable
    first = await inbox.list_untriaged(db, 100)
    assert [m.id for m in first[:3]] == ["m0", "m1", "m2"] and len(first) == 100
    assert [m.id for m in await inbox.list_untriaged(db, 100, offset=100)] == [f"m{i}" for i in range(100, 120)]
    assert await inbox.count_untriaged(db) == 120


# ---- XE-1617: a vote row derived under another snapshot is re-derived before it is tallied ------------------

async def test_stale_vote_rows_are_rederived_at_close(db):
    from dao.chainops import SNAPSHOT_RULE, snapshot_time
    ctx = _ctx()
    now = time.time_ns()
    pr = Proposal(hash="5" * 64, title="t", body="b", ops=None, author_account=AUTHOR, author_pub_key="p" * 64,
                  author_signature="s", author_timestamp=now, fee_block_hash="5" * 64, status="open", opened_at=now - D,
                  closes_at=now - 1, rules=ctx.config.pinned_rules(), analysis=[])
    db.add(pr)
    at = snapshot_time(pr.opened_at)
    # a wallet funded after the pinned snapshot, recorded under the old rule (snapshot at opened_at) as participating
    ctx.chain.chains["late"] = [{"timestamp": at + 1000, "asset": "XE", "balance": 1_000_000, "hash": "l0", "type": "open"}]
    ctx.chain.chains["early"] = [{"timestamp": at - 1000, "asset": "XE", "balance": 2_000_000, "hash": "e0", "type": "open"}]
    for acct, weight, snap in (("late", 1_000_000, {"at": pr.opened_at, "rule": 1}), ("early", 2_000_000, {"at": at, "rule": SNAPSHOT_RULE})):
        db.add(Vote(proposal_hash=pr.hash, account=acct, pub_key="p" * 64, choice="for", reason="", timestamp=now, signature=os.urandom(8).hex(),
                    weight=weight, participating=True, is_agent=False, eligibility={"snapshot": snap, "not_participating_because": []}))
    await db.commit()
    closed = await portal.close_due(ctx, db)
    assert [p.hash for p in closed] == [pr.hash]
    rows = {v.account: v for v in await portal.votes_for(db, pr.hash)}
    assert not rows["late"].participating and rows["late"].weight == 0, "re-derived under the proposal's snapshot"
    assert rows["early"].participating and rows["early"].weight == 2_000_000 and rows["early"].eligibility["snapshot"]["rule"] == SNAPSHOT_RULE
    assert pr.result["participating_wallets"] == 1 and pr.result["weight"]["for"] == 2_000_000
    assert (await db.execute(select(Event).where(Event.kind == "vote.rederived"))).scalars().one().payload["account"] == "late"
    # a node fault during re-derivation leaves the proposal open for the next pass
    pr2 = Proposal(hash="6" * 64, title="t", body="b", ops=None, author_account=AUTHOR, author_pub_key="p" * 64,
                   author_signature="s", author_timestamp=now, fee_block_hash="6" * 64, status="open", opened_at=now - D,
                   closes_at=now - 1, rules=ctx.config.pinned_rules(), analysis=[])
    db.add(pr2)
    db.add(Vote(proposal_hash=pr2.hash, account="late", pub_key="p" * 64, choice="for", reason="", timestamp=now, signature=os.urandom(8).hex(),
                weight=1, participating=True, is_agent=False, eligibility={}))
    await db.commit()

    async def boom(a):
        raise XeError(503, "down")
    ctx.chain.full_chain = boom
    assert await portal.close_due(ctx, db) == [] and pr2.status == "open"


# ---- XE-1618 / XE-1620: health legs measure from the DAO's start ------------------------------------------

async def test_health_measures_an_unanchored_dao_and_a_late_worker_from_the_first_event(db):
    from dao.services import records
    ctx, state = _health_ctx()
    # the DAO's first event is 20 days old; no anchor was ever written; no health check was ever recorded
    first = await ctx.events.append(db, "worker.started", "harness", {}, ts=time.time_ns() - 20 * D)
    await db.commit()
    assert await records.started_at(db) == first.ts
    up = await records.uptime_30d(ctx, db)
    assert up["checks"] == 0 and up["expected"] == 20 * 24 * 6 and up["fraction"] == 0.0
    d = await _check(ctx, db)
    assert d["last_anchor"] is None and d["anchor_overdue"] and not d["ok"]


# ---- XE-1689 / XE-1710 / XE-1713: a member's signature survives a node that does not answer --------------

async def test_a_members_signature_survives_a_node_that_does_not_answer(db):
    from dao.services import resolutions
    ctx = _ctx()
    ctx.config.members = [_member("founder-a"), _member("founder-b")]
    ctx.config.windows = {}
    down = XeError(0, "ConnectError: connection refused")
    assert down.transient and "unreachable" in str(down)

    async def no_answer(*a, **k):
        raise down
    # 1. the deciding signature on a resolution with ops: passed, session owed, opened when the node is back
    ctx.chain.dao_keyset = no_answer
    r = Resolution(id="r1", number=1, title="t", body="b", matter="parameter", proposed_by="founder-a", status="open",
                   signatures=[], ops=[{"action": "set", "key": "dao.x", "value": "1"}])
    db.add(r)
    await db.flush()

    def member(seat, decision):
        v = _v(payload={"resolution_id": r.id, "body_hash": resolutions.body_hash(r), "decision": decision})
        v.seat = _member(seat)
        return v
    await resolutions.decide(ctx, db, r, member("founder-a", "for"), "for")
    await resolutions.decide(ctx, db, r, member("founder-b", "for"), "for")
    assert r.status == "passed" and len(r.signatures) == 2 and r.session_id == ""
    assert (await db.execute(select(Event).where(Event.kind == "resolution.session_deferred"))).scalars().one()
    ctx.chain.dao_keyset = FakeChain.dao_keyset.__get__(ctx.chain)
    assert await resolutions.open_deferred_sessions(ctx, db) == 1 and r.session_id
    assert (await sessions.get(db, r.session_id)).kind == "parameter"
    assert await resolutions.open_deferred_sessions(ctx, db) == 0
    # 2. the deciding approval: recorded, the build owed
    ctx.chain.statechain_tip = no_answer
    s = SigningSession(id="s2", kind="parameter", title="t", ops=[{"action": "set", "key": "dao.x", "value": "1"}],
                       ops_digest=sessions.ops_digest([{"action": "set", "key": "dao.x", "value": "1"}]), status="approving",
                       approvals=[{"public_key": "k1"}], required_approvals=2, block=None, block_hash="", block_signatures=[], rebuilds=0)
    db.add(s)
    await db.flush()
    v = _v(payload={"session_id": "s2", "ops_digest": s.ops_digest})
    v.pub_key = "k2"
    await sessions.approve(ctx, db, s, v)
    assert s.status == "approving" and len(s.approvals) == 2
    assert (await db.execute(select(Event).where(Event.kind == "session.build_deferred"))).scalars().one()
    # and whatever else stops the build (here, a fault that is not the node's): the approval still stands
    async def broken():
        raise KeyError("a bug in the build")
    ctx.chain.statechain_tip = broken
    s3 = SigningSession(id="s3", kind="parameter", title="t", ops=s.ops, ops_digest=s.ops_digest, status="approving",
                        approvals=[{"public_key": "k1"}], required_approvals=2, block=None, block_hash="", block_signatures=[], rebuilds=0)
    db.add(s3)
    await db.flush()
    v3 = _v(payload={"session_id": "s3", "ops_digest": s3.ops_digest})
    v3.pub_key = "k2"
    await sessions.approve(ctx, db, s3, v3)
    assert s3.status == "approving" and len(s3.approvals) == 2
    owed = (await db.execute(select(Event).where(Event.kind == "session.build_deferred").order_by(Event.index))).scalars().all()
    assert [e.payload["session_id"] for e in owed] == ["s2", "s3"] and "a bug in the build" in owed[1].payload["error"]
    s3.status = "cancelled"
    ctx.chain.statechain_tip = lambda: _tip_at(0)
    await sessions.rebuild(ctx, db, s)          # what the worker's timer pass does
    assert s.status == "signing" and s.block
    # 3. the deciding block signature: the session stays signing with the error on record, and is submitted later
    ctx.chain.submit_statechain_block = no_answer
    ctx.chain.statechain_block = no_answer
    s.block_signatures = [{"public_key": "k1", "signature": "s"}, {"public_key": "k2", "signature": "s"}]
    await sessions.submit(ctx, db, s)
    assert s.status == "signing" and "unreachable" in s.error
    ks = await sessions.live_keyset(ctx)
    assert sessions.ready_to_submit(s, ks)

    async def accepted(blk):
        return {"ok": True}
    ctx.chain.submit_statechain_block = accepted
    # the node says yes and the chain cannot be read, or does not hold the block: a yes is not a write (XE-2361)
    await sessions.submit(ctx, db, s)
    assert s.status == "signing" and "could not confirm" in s.error
    ctx.chain.statechain_block = FakeChain.statechain_block.__get__(ctx.chain)
    await sessions.submit(ctx, db, s)
    assert s.status == "signing" and "does not hold the block" in s.error and s.submitted_index is None
    assert not (await db.execute(select(Event).where(Event.kind == "session.submitted"))).scalars().all()
    # the chain holds it: submitted, whichever way the node answered
    ctx.chain.state_blocks[s.block["index"]] = {"index": s.block["index"], "hash": s.block_hash}
    await sessions.submit(ctx, db, s)
    assert s.status == "submitted" and s.submitted_index == s.block["index"]


# ---- XE-1677 / XE-1817 / XE-2216: what a refused submit means is asked of the chain, not read off the refusal ----

async def test_a_refused_submit_is_classified_by_the_state_of_the_chain_whatever_the_refusal_says(db):
    ctx = _ctx()
    tip = {"at": 0}
    keyset = {"keys": ["k1", "k2", "k3"], "threshold": 2}

    async def refuse(blk):
        raise answers["e"]

    async def live():
        return dict(keyset)
    ctx.chain.submit_statechain_block = refuse
    ctx.chain.statechain_tip = lambda: _tip_at(tip["at"])
    ctx.chain.dao_keyset = live
    answers = {}
    # a rate limit, a server error: the node never looked at the block, whatever state the chain is in
    s1 = await _signing(db, "s1", index=1, n=1)
    for e in (XeError(429, "rate limit exceeded"), XeError(503, "service unavailable")):
        answers["e"] = e
        await sessions.submit(ctx, db, s1)
        assert s1.status == "signing" and str(e.status) in s1.error and len(s1.block_signatures) == 2

    # The same four refusals are given in each state of the chain. Two are worded like a moved tip or a
    # moved keyset, one is about the block, one is in words nobody has seen: the outcome follows the state.
    wordings = ("block rejected: signer k9 not in keyset", "block rejected: prev_hash mismatch",
                "block rejected: epoch key already exists", "block rejected: some new wording in a later node")
    n = iter(range(2, 100))

    async def refused_with(words, **over):
        i = next(n)
        s = await _signing(db, f"s{i}", index=1, n=i)
        for k, v in over.items():
            setattr(s, k, v)
        answers["e"] = XeError(400, words)
        await sessions.submit(ctx, db, s)
        return s

    async def events(kind, s):
        return (await db.execute(select(Event).where(Event.kind == kind, Event.ref == f"session:{s.id}"))).scalars().all()

    for words in wordings:
        # nothing moved: the tip is the block's parent and its signatures meet the live keyset. The refusal
        # is about the block, and the session ends with the node's words on the record
        s = await refused_with(words)
        assert s.status == "failed" and words in s.error, words
        # the tip moved: rebuilt on the live tip
        tip["at"] = 7
        s = await refused_with(words)
        assert s.status == "signing" and s.block_signatures == [] and s.rebuilds == 1 and s.block["index"] == 8, words
        assert await events("session.tip_moved", s) and not await events("session.failed", s)
        tip["at"] = 0
        # the keyset moved under the block's signatures; the approvals still meet it: rebuilt for the new signers
        keyset["keys"] = ["k1", "k2", "k9"]
        s = await refused_with(words, block_signatures=[{"public_key": "k1", "signature": "s"}, {"public_key": "k3", "signature": "s"}])
        assert s.status == "signing" and s.block_signatures == [] and s.rebuilds == 1, words
        assert await events("session.keyset_moved", s)
        # the keyset moved and the approvals no longer meet it either: back to approving (XE-0988), not failed
        keyset["keys"] = ["k7", "k8", "k9"]
        s = await refused_with(words)
        assert s.status == "approving" and s.block is None, words
        assert await events("session.keyset_moved", s) and await events("session.reapproval_needed", s)
        keyset["keys"] = ["k1", "k2", "k3"]
    # and a chain that cannot be asked decides nothing
    async def down():
        raise XeError(0, "ReadTimeout")
    ctx.chain.statechain_tip = down
    s = await refused_with(wordings[0])
    assert s.status == "signing" and "could not confirm" in s.error and len(s.block_signatures) == 2


# ---- XE-1843: a cancel asks the chain first ------------------------------------------------------------

async def test_cancelling_a_session_whose_block_landed_records_it_submitted(db):
    from dao.services import records
    ctx = _ctx()
    v = _v()
    v.seat = _member("founder-a")
    s = await _signing(db, "c1", index=3, n=3)
    ctx.chain.state_blocks[3] = {"index": 3, "hash": "h" * 64}
    out = await sessions.cancel(ctx, db, s, v, "looks stuck")
    assert out.status == "submitted" and s.submitted_index == 3
    assert (await records.latest_anchor(db)).session_id == "c1", "the anchor row stays"
    # a block not on the chain: cancelled, and its anchor row goes
    s2 = await _signing(db, "c2", index=4, n=4)
    await sessions.cancel(ctx, db, s2, v, "withdrawn")
    assert s2.status == "cancelled" and (await records.latest_anchor(db)).session_id == "c1"


# ---- XE-1651 / XE-1666 / XE-1768: the chat cursor is derived from the stored inbox ----------------------

async def test_chat_cursor_comes_from_the_stored_inbox_with_a_margin(db, monkeypatch):
    ctx = _ctx()
    ctx.signer = FakeSigner(("harness", "fee", "dao"))
    now = time.time_ns()
    assert abs(await inbox.chat_cursor(db) - (now - inbox.CURSOR_START_NS)) < 5 * inbox.NS
    # an envelope dated five minutes ahead by its sender moves the cursor only to fifteen minutes before it
    db.add(InboxMessage(id="e1", channel="chat", from_account="a" * 64, to_account="d" * 64, pub_key="p" * 64, body="x",
                        timestamp=now + 300 * inbox.NS, signature="s", pow_nonce=0, verified=True, status="new"))
    db.add(InboxMessage(id="h1", channel="http", from_account="a" * 64, to_account="d" * 64, pub_key="p" * 64, body="x",
                        timestamp=now + 3600 * inbox.NS, signature="s", pow_nonce=0, verified=True, status="new"))
    await db.commit()
    cursor = await inbox.chat_cursor(db)
    assert cursor == now + 300 * inbox.NS - inbox.CURSOR_MARGIN_NS, "http rows do not move the chat cursor"
    assert cursor <= now - 600 * inbox.NS, "an honest message dated inside the skew window is still fetched"
    asked = []

    async def messages(proof, since):
        asked.append(since)
        return []

    async def proof(ctx_):
        return {}
    ctx.chain.chat_messages = messages
    monkeypatch.setattr(inbox, "read_proof", proof)
    await inbox.backfill(ctx, db)
    assert asked == [cursor]
    assert inbox.CURSOR_MARGIN_NS >= 3 * 300 * inbox.NS


# ---- XE-1729 / XE-1776 / XE-1846 / XE-1845: the outbox --------------------------------------------------------

async def test_outbox_sends_at_most_once_in_priority_order_and_the_message_follows_delivery(db, monkeypatch):
    from datetime import datetime, timedelta, timezone
    from dao.models import OutboxMessage
    ctx = _ctx()
    ctx.signer = FakeSigner(("harness", "fee", "dao"))
    now = time.time_ns()
    m = InboxMessage(id="m1", channel="chat", from_account="a" * 64, to_account="d" * 64, pub_key="p" * 64, body="q",
                     timestamp=now, signature="s", pow_nonce=0, verified=True, status="new")
    db.add(m)
    await db.flush()
    ack = await inbox.queue_reply(ctx, db, m, "ack", from_seat="harness", kind="ack")
    assert m.status == "new", "an acknowledgement is not an answer"
    reply = await inbox.queue_reply(ctx, db, m, "the answer", from_seat="cto")
    assert m.status == "replying" and m.reply_id == reply.id
    await db.commit()
    sm = async_sessionmaker(db.bind, expire_on_commit=False)
    sent, seen = [], []

    async def send(env):
        async with sm() as other:   # what is on disk at the moment the node is handed the envelope
            row = (await other.execute(select(OutboxMessage).where(OutboxMessage.body == env["message"]))).scalar_one()
            seen.append((row.status, row.envelope == env))
        sent.append(env["message"])
    ctx.chain.chat_send = send
    assert await inbox.flush_outbox(ctx, db) == 2
    assert sent == ["the answer", "ack"], "a member's reply goes before an acknowledgement queued earlier"
    assert seen == [("sending", True)] * 2, "the envelope is on the row before it is offered"
    await db.refresh(m)
    assert m.status == "answered" and reply.status == "sent" and ack.status == "sent"
    named = {e.payload["id"]: e.payload["envelope_id"] for e in (await db.execute(select(Event).where(Event.kind == "outbox.sent"))).scalars().all()}
    assert named == {reply.id: reply.envelope["id"], ack.id: ack.envelope["id"]}, "the record names the envelope that went out"
    # a reply given up after a week returns its message to `new`
    m2 = InboxMessage(id="m2", channel="chat", from_account="c" * 64, to_account="d" * 64, pub_key="p" * 64, body="q",
                      timestamp=now, signature="s", pow_nonce=0, verified=True, status="new")
    db.add(m2)
    await db.flush()
    old = await inbox.queue_reply(ctx, db, m2, "late", from_seat="cto")
    old.created_at = datetime.now(timezone.utc) - timedelta(days=8)
    await db.commit()
    await inbox.flush_outbox(ctx, db)
    await db.refresh(m2)
    assert old.status == "failed" and m2.status == "new" and m2.reply_id == "" and "late" not in sent
    # acknowledgements are rationed per correspondent
    assert await inbox._acked_recently(db, "a" * 64) and not await inbox._acked_recently(db, "z" * 64)
    # the by-hand statuses do not include the two that delivery sets
    bad = _v(payload={"status": "answered"})
    bad.seat = _member("cto")
    with pytest.raises(HTTPException):
        await inbox.set_status(ctx, db, m, bad)


# ---- XE-1726 / XE-1893: a lapsed pause is not active, whatever its row says --------------------------------

async def test_a_lapsed_pause_cannot_be_extended_lifted_or_posted(db):
    from dao.models import PauseRecord
    from dao.services import pause
    ctx = _ctx()
    ctx.config.members = [_member("founder-a")]
    ctx.config.pause = {}
    now = time.time_ns()
    r = PauseRecord(id="p1", determined_by="founder-a", ground="g", determination="d" * 20, started_at=now - 10 * 3600 * 10**9,
                    expires_at=now - 3600 * 10**9, indefinite=False, extensions=[], lifted_by=[], status="active")
    db.add(r)
    await db.flush()
    assert not pause.in_force(r) and await pause.active(db) is None

    def member(payload):
        v = _v(payload={"pause_id": "p1", **payload})
        v.seat = _member("founder-a")
        return v
    for action in (pause.extend, pause.lift, pause.set_post):
        with pytest.raises(HTTPException) as e:
            await action(ctx, db, r, member({"text": "the public post text", "reason": "more"}))
        assert e.value.status_code == 409 and "expired" in e.value.detail, action.__name__
    assert r.status == "active" and r.posted_at is None and r.extensions == [] and r.lifted_by == []
    # the worker marks it expired and publishes no post for it
    await pause.tick(ctx, db)
    assert r.status == "expired" and r.posted_at is None


# ---- XE-1761: a signature counts only while its seat holds the key it was made with -----------------------

async def test_signatures_from_a_rotated_key_are_set_aside(db):
    from dao.models import PauseRecord
    from dao.services import pause, resolutions
    ctx = _ctx()
    ctx.config.members = [_member("founder-a", key="a" * 64), _member("founder-b", key="b" * 64)]
    ctx.config.windows = {}
    ctx.config.pause = {}
    # founder-a signed with a key the seat no longer holds
    r = Resolution(id="r1", number=1, title="t", body="b", matter="note", ops=None, proposed_by="founder-a", status="open",
                   signatures=[{"seat": "founder-a", "public_key": "0" * 64, "signature": "s", "decision": "for", "timestamp": 1}])
    db.add(r)
    await db.flush()
    v = _v(payload={"resolution_id": "r1", "body_hash": resolutions.body_hash(r), "decision": "for"})
    v.seat, v.pub_key = _member("founder-b", key="b" * 64), "b" * 64
    await resolutions.decide(ctx, db, r, v, "for")
    assert r.status == "open", "one live signature plus one from a rotated key is not a majority of two"
    ev = (await db.execute(select(Event).where(Event.kind == "resolution.signed"))).scalars().all()[-1]
    assert ev.payload["for"] == 1 and ev.payload["set_aside"] == ["founder-a"]
    # the pause: a lift signed with the old key does not count either
    now = time.time_ns()
    p = PauseRecord(id="p1", determined_by="founder-a", ground="g", determination="d" * 20, started_at=now, expires_at=now + 10**12,
                    indefinite=False, extensions=[], lifted_by=[{"seat": "founder-a", "public_key": "0" * 64, "signature": "s", "timestamp": 1}],
                    status="active")
    db.add(p)
    await db.flush()
    lv = _v(payload={"pause_id": "p1"})
    lv.seat, lv.pub_key = _member("founder-b", key="b" * 64), "b" * 64
    await pause.lift(ctx, db, p, lv)
    assert p.status == "active"
    met, n_live, set_aside = pause._consent(ctx, p.lifted_by)
    assert not met and n_live == 1 and set_aside == ["founder-a"]


# ---- XE-1649 / XE-1725 / XE-1847 / XE-1770: the decision record ------------------------------------------------

async def test_decide_compares_ops_by_meaning_names_a_referral_and_closes_analysis(db):
    ctx = _ctx()
    ops_a = [{"action": "set", "key": "dao.x", "value": '{"b":1,"a":2}'}]
    ops_b = [{"action": "set", "key": "dao.x", "value": '{"a":2,"b":1}'}]
    pr = _closed(ctx, "7" * 64, "passed", ops=ops_a)
    db.add(pr)
    db.add(Resolution(id="rp", number=1, title="t", body="b", matter="parameter", ops=ops_b, proposed_by="cto", status="passed",
                      signatures=[], related_proposal=pr.hash))
    db.add(Resolution(id="ro", number=2, title="t", body="b", matter="note", ops=None, proposed_by="cto", status="open",
                      signatures=[], related_proposal=pr.hash))
    await db.flush()
    # a referral must name a resolution
    with pytest.raises(HTTPException) as e:
        await portal.decide(ctx, db, pr, _seat({"decision": "refer_to_resolution", "reasons": "needs a resolution first"}, pr))
    assert e.value.status_code == 400 and "resolution_id" in e.value.detail
    await portal.decide(ctx, db, pr, _seat({"decision": "refer_to_resolution", "reasons": "needs a resolution first", "resolution_id": "ro"}, pr))
    assert pr.decision["resolution_id"] == "ro"
    # analysis is still open while the decision is interim
    await portal.add_analysis(ctx, db, pr, _seat({"text": "a note before the final decision"}, pr))
    # the same ops written with the keys in another order authorise the adoption
    await portal.decide(ctx, db, pr, _seat({"decision": "adopt", "reasons": "the vote passed and R1 authorises it", "resolution_id": "rp"}, pr))
    assert pr.decision["decision"] == "adopt"
    # and once final, analysis is closed
    with pytest.raises(HTTPException) as e:
        await portal.add_analysis(ctx, db, pr, _seat({"text": "a note after the fact"}, pr))
    assert e.value.status_code == 409 and len(pr.analysis) == 1


# ---- XE-1706 / XE-1724 / XE-1664: unreadable chains, agent class, and the open tally -------------------------

async def test_unreadable_chain_weighs_nothing_agent_class_is_live_and_open_tallies_count_only_current_rows(db):
    from dao.chainops import SNAPSHOT_RULE, snapshot_time
    ctx = _ctx()
    ctx.config.agent_accounts = {"ag"}
    now = time.time_ns()
    pr = Proposal(hash="8" * 64, title="t", body="b", ops=None, author_account=AUTHOR, author_pub_key="p" * 64, author_signature="s",
                  author_timestamp=now, fee_block_hash="8" * 64, status="open", opened_at=now - D, closes_at=now - 1,
                  rules=ctx.config.pinned_rules(), analysis=[])
    db.add(pr)
    at = snapshot_time(pr.opened_at)
    chains = {"ag": [{"timestamp": at - 1000, "asset": "XE", "balance": 5_000_000, "hash": "g0", "type": "open"}],
              "ok": [{"timestamp": at - 1000, "asset": "XE", "balance": 1_000_000, "hash": "o0", "type": "open"}]}

    async def full_chain(account):
        if account == "big":
            raise XeError(413, "account chain exceeds 100000 blocks")
        return chains[account]
    ctx.chain.full_chain = full_chain
    current = {"at": at, "rule": SNAPSHOT_RULE}
    for acct, is_agent, snap in (("big", False, {}), ("ag", False, current), ("ok", False, current)):
        db.add(Vote(proposal_hash=pr.hash, account=acct, pub_key="p" * 64, choice="for", reason="", timestamp=now,
                    signature=os.urandom(8).hex(), weight=1_000_000, participating=True, is_agent=is_agent,
                    eligibility={"snapshot": snap, "not_participating_because": []}))
    await db.commit()
    votes = await portal.votes_for(db, pr.hash)
    open_t = portal.tally(pr, votes, ctx)
    assert open_t["stale_rows"] == 2 and open_t["votes"] == 1 and open_t["weight"]["for"] == 1_000_000, \
        "the row with no snapshot and the row whose account became an agent seat are not counted while stale"
    assert portal.tally(pr, votes)["stale_rows"] == 0, "without a context nothing is filtered (the close path re-derives first)"
    # the worker's pass re-derives them
    assert await portal.rederive_open(ctx, db) == 2
    rows = {v.account: v for v in await portal.votes_for(db, pr.hash)}
    assert rows["big"].weight == 0 and not rows["big"].participating and "could not be read" in rows["big"].eligibility["not_participating_because"][0]
    assert rows["big"].eligibility["snapshot"]["unreadable"]
    assert rows["ag"].is_agent and not rows["ag"].participating
    assert portal.tally(pr, await portal.votes_for(db, pr.hash), ctx)["stale_rows"] == 0
    # and the close is not held by the unreadable chain
    closed = await portal.close_due(ctx, db)
    assert [p.hash for p in closed] == [pr.hash] and pr.result["participating_wallets"] == 1
    # a transient fault still waits
    pr2 = Proposal(hash="9" * 64, title="t", body="b", ops=None, author_account=AUTHOR, author_pub_key="p" * 64, author_signature="s",
                   author_timestamp=now, fee_block_hash="9" * 64, status="open", opened_at=now - D, closes_at=now - 1,
                   rules=ctx.config.pinned_rules(), analysis=[])
    db.add(pr2)
    db.add(Vote(proposal_hash=pr2.hash, account="ok", pub_key="p" * 64, choice="for", reason="", timestamp=now, signature=os.urandom(8).hex(),
                weight=1, participating=True, is_agent=False, eligibility={}))
    await db.commit()

    async def down(a):
        raise XeError(0, "ReadTimeout")
    ctx.chain.full_chain = down
    assert await portal.close_due(ctx, db) == [] and pr2.status == "open"
    # a proposal that cannot be closed, whatever stops it, does not hold up the one behind it (XE-1967's rule here)
    pr3 = Proposal(hash="a" * 64, title="t", body="b", ops=None, author_account=AUTHOR, author_pub_key="p" * 64, author_signature="s",
                   author_timestamp=now, fee_block_hash="a" * 64, status="open", opened_at=now - D, closes_at=now - 1,
                   rules=ctx.config.pinned_rules(), analysis=[])
    db.add(pr3)
    await db.commit()
    for stops_it in (XeError(0, "ReadTimeout"), RuntimeError("not the node")):
        async def stopped(a, e=stops_it):
            raise e
        ctx.chain.full_chain = stopped
        pr3.status, pr3.result = "open", None
        await db.commit()
        assert [p.hash for p in await portal.close_due(ctx, db)] == [pr3.hash], stops_it
        await db.commit()
        await db.refresh(pr2)
        assert pr2.status == "open" and pr3.status == "closed", stops_it


# ---- XE-1650: a proposal's ops are ones a resolution could carry -------------------------------------------

async def test_proposal_ops_must_be_ones_some_resolution_could_authorise(db):
    ctx = _ctx()
    k1, k2, k3 = (KeyPair.generate().pub_key_hex for _ in range(3))
    ctx.config.human_seats = [_member("a", ("sign_statechain",), k1), _member("b", ("sign_statechain",), k2)]
    seat_keys = sessions.seat_keys_of(ctx.config)
    sessions.check_proposal_ops(sessions.normalise_ops([{"action": "set", "key": "dao.param.x", "value": 1}]), seat_keys)
    sessions.check_proposal_ops(sessions.normalise_ops([{"action": "set", "key": "sys.dao_keyset", "value": {"keys": [k1, k2], "threshold": 2}}]), seat_keys)
    for ops, why in (([{"action": "set", "key": "sys.tokenomics", "value": {"r": 1}}], "dao.* keys"),
                     ([{"action": "set", "key": "sys.dao_keyset", "value": {"keys": [k1, k2], "threshold": 2}},
                       {"action": "set", "key": "dao.x", "value": 1}], "exactly one op"),
                     ([{"action": "set", "key": "sys.dao_keyset", "value": {"keys": [k1, k3], "threshold": 2}}], "held by a seat")):
        with pytest.raises(HTTPException) as e:
            sessions.check_proposal_ops(sessions.normalise_ops(ops), seat_keys)
        assert e.value.status_code == 400 and why in e.value.detail, e.value.detail
        with pytest.raises(HTTPException) as e:
            await portal.submit(ctx, db, _v(payload={"title": "t", "body": "b", "fee_block_hash": "c" * 64, "ops": ops}))
        assert e.value.status_code == 400


# ---- XE-1966: a seat whose stored signature no longer counts has not signed ----------------------------------

def _signed_by(seat, key, payload, rights=("pause",)):
    v = _v(payload=payload)
    v.seat, v.pub_key = _member(seat, rights, key), key
    return v


async def test_a_set_aside_signature_is_replaced_by_the_seats_next_one_and_a_live_one_is_not(db):
    """The rule on every record that keeps member signatures (a resolution, a pause extension, a pause
    lift): the seat whose stored signature was set aside signs again and the new one takes its place; a
    seat whose signature counts cannot sign twice; and the threshold is then reachable."""
    from dao.models import PauseRecord
    from dao.services import pause, resolutions
    ctx = _ctx()
    old, new, kb = "0" * 64, "a" * 64, "b" * 64
    ctx.config.members = [_member("founder-a", key=new), _member("founder-b", key=kb)]
    ctx.config.windows, ctx.config.pause = {}, {}
    now = time.time_ns()
    stale = {"seat": "founder-a", "public_key": old, "signature": "made-with-the-old-key", "timestamp": 1}
    r = Resolution(id="r1", number=1, title="t", body="b", matter="note", ops=None, proposed_by="founder-a", status="open",
                   signatures=[{**stale, "decision": "against"}])
    p = PauseRecord(id="p1", determined_by="founder-a", ground="g", determination="d" * 20, started_at=now, expires_at=now + 10**12,
                    indefinite=False, status="active", lifted_by=[stale], extensions=[{"applied": False, "signatures": [stale]}])
    db.add_all([r, p])
    await db.flush()
    sites = [
        ("resolutions.decide", lambda v: resolutions.decide(ctx, db, r, v, "for"),
         {"resolution_id": "r1", "body_hash": resolutions.body_hash(r), "decision": "for"},
         lambda: r.signatures, lambda: r.status == "passed"),
        ("pause.extend", lambda v: pause.extend(ctx, db, p, v), {"pause_id": "p1", "reason": "more time"},
         lambda: p.extensions[-1]["signatures"], lambda: p.extensions[-1]["applied"]),
        ("pause.lift", lambda v: pause.lift(ctx, db, p, v), {"pause_id": "p1"},
         lambda: p.lifted_by, lambda: p.status == "lifted"),
    ]
    for name, sign, payload, sigs, done in sites:
        assert [s["public_key"] for s in sigs()] == [old], name
        await sign(_signed_by("founder-a", new, payload))
        assert [(s["seat"], s["public_key"]) for s in sigs()] == [("founder-a", new)], f"{name}: replaced, not added beside"
        assert not done(), name
        with pytest.raises(HTTPException) as e:
            await sign(_signed_by("founder-a", new, payload))
        assert e.value.status_code == 409 and len(sigs()) == 1, f"{name}: a signature that counts is not given twice"
        await sign(_signed_by("founder-b", kb, payload))
        assert done(), f"{name}: every member has signed, so it is decided"
        assert sorted(s["seat"] for s in sigs()) == ["founder-a", "founder-b"], name
    # the same seat rotating again after it signed: the signature it gave is set aside and it signs once more
    r2 = Resolution(id="r2", number=2, title="t", body="b", matter="note", ops=None, proposed_by="founder-a", status="open", signatures=[])
    db.add(r2)
    await db.flush()
    payload = {"resolution_id": "r2", "body_hash": resolutions.body_hash(r2), "decision": "for"}
    await resolutions.decide(ctx, db, r2, _signed_by("founder-a", new, payload), "for")
    newer = "c" * 64
    ctx.config.members = [_member("founder-a", key=newer), _member("founder-b", key=kb)]
    assert resolutions.live_signatures(ctx, r2.signatures) == ([], ["founder-a"])
    await resolutions.decide(ctx, db, r2, _signed_by("founder-a", newer, payload), "for")
    assert [(s["seat"], s["public_key"]) for s in r2.signatures] == [("founder-a", newer)] and r2.status == "open"
    await resolutions.decide(ctx, db, r2, _signed_by("founder-b", kb, payload), "for")
    assert r2.status == "passed"
    # What is shown is what is counted. An open record shows the signatures that count now and names the
    # seats set aside; a decided one shows the signatures it was decided with.
    r3 = Resolution(id="r3", number=3, title="t", body="b", matter="amend_articles", ops=None, proposed_by="founder-a", status="open",
                    signatures=[{**stale, "decision": "for"}, {"seat": "founder-b", "public_key": kb, "signature": "s", "decision": "for", "timestamp": 2}])
    shown = resolutions.to_dict(r3, ctx.config)
    assert [s["seat"] for s in shown["signatures"]] == ["founder-b"] and shown["set_aside"] == ["founder-a"] and shown["needed"] == 2
    assert [s["seat"] for s in resolutions.to_dict(r2, ctx.config)["signatures"]] == ["founder-a", "founder-b"]
    p2 = PauseRecord(id="p2", determined_by="founder-a", ground="g", determination="d" * 20, started_at=now, expires_at=now + 10**12,
                     indefinite=False, status="active", lifted_by=[stale, {**stale, "seat": "founder-b", "public_key": kb}],
                     extensions=[{"applied": True, "signatures": [stale, stale]}, {"applied": False, "signatures": [stale]}])
    shown = pause.to_dict(ctx, p2)
    assert shown["lift_signatures"] == 1 and [e["signatures"] for e in shown["extensions"]] == [2, 0]
    assert pause.to_dict(ctx, p)["lift_signatures"] == 2, "a lifted pause shows what it was lifted with"
    # The seats counted are the seats the route lets sign (as for a pause, XE-1013). A member without the
    # right to sign resolutions is not waited for, and a signature from a seat that has since lost the
    # right is set aside like one from a seat that has left.
    ctx.config.members = [_member("founder-a", key=newer), _member("founder-b", key=kb), _member("founder-c", rights=("pause",))]
    assert resolutions.to_dict(r3, ctx.config)["needed"] == 2, "every member who can sign, not every member"
    r4 = Resolution(id="r4", number=4, title="t", body="b", matter="amend_articles", ops=None, proposed_by="founder-a", status="open", signatures=[])
    db.add(r4)
    await db.flush()
    payload = {"resolution_id": "r4", "body_hash": resolutions.body_hash(r4), "decision": "for"}
    await resolutions.decide(ctx, db, r4, _signed_by("founder-a", newer, payload), "for")
    ctx.config.members = [_member("founder-a", rights=("pause",), key=newer), _member("founder-b", key=kb)]
    await resolutions.decide(ctx, db, r4, _signed_by("founder-b", kb, payload), "for")
    assert r4.status == "passed" and [s["seat"] for s in r4.signatures] == ["founder-b"], \
        "the one member who can sign has signed; the signature from the seat that lost the right is not what passed it, and is not shown as if it had"
    assert [s["seat"] for s in resolutions.to_dict(r4, ctx.config)["signatures"]] == ["founder-b"]


# ---- XE-1967: a passed resolution is passed; a step that fails is one step ------------------------------------

async def test_a_passed_resolution_stays_passed_and_a_failed_step_stops_nothing_behind_it(db, monkeypatch):
    from contextlib import asynccontextmanager

    from dao import worker as worker_mod
    from dao.models import PauseRecord
    from dao.services import resolutions
    from dao.worker_schedule import last_runs
    ctx = _ctx()
    k1, k2 = KeyPair.generate().pub_key_hex, KeyPair.generate().pub_key_hex
    both = ("sign_statechain", "pause", "sign_resolutions")
    ctx.config.members = ctx.config.human_seats = [_member("founder-a", both, k1), _member("founder-b", both, k2)]
    ctx.config.windows, ctx.config.pause = {}, {}
    keyset_ops = sessions.normalise_ops([{"action": "set", "key": "sys.dao_keyset", "value": {"keys": [k1, k2], "threshold": 2}}])
    param_ops = sessions.normalise_ops([{"action": "set", "key": "dao.x", "value": 1}])
    r1 = Resolution(id="r1", number=1, title="rotate", body="b", matter="change_keyset", ops=keyset_ops, proposed_by="founder-a",
                    status="open", signatures=[])
    r2 = Resolution(id="r2", number=2, title="param", body="b", matter="parameter", ops=param_ops, proposed_by="founder-a",
                    status="open", signatures=[])
    db.add_all([r1, r2])
    await db.flush()

    def vote(r, seat, key):
        return _signed_by(seat, key, {"resolution_id": r.id, "body_hash": resolutions.body_hash(r), "decision": "for"}, both)

    async def events(kind):
        return (await db.execute(select(Event).where(Event.kind == kind).order_by(Event.index))).scalars().all()

    # 1. between the proposal and the deciding signature founder-b's seat loses the right to sign blocks, so
    # the keyset the resolution writes is one the seats can no longer meet. The deciding signature is
    # refused with the cause (XE-2030: left as it is, by decision), and the route records none of it
    await resolutions.decide(ctx, db, r1, vote(r1, "founder-a", k1), "for")
    await db.commit()
    as_proposed = ctx.config.human_seats
    changed = [_member("founder-a", both, k1), _member("founder-b", ("pause", "sign_resolutions"), k2)]
    ctx.config.human_seats = changed
    with pytest.raises(HTTPException) as e:
        await resolutions.decide(ctx, db, r1, vote(r1, "founder-b", k2), "for")
    assert e.value.status_code == 400 and "held by a seat" in e.value.detail
    await db.rollback()   # what the route does with a handler that raised
    await db.refresh(r1), await db.refresh(r2)
    assert r1.status == "open" and [s["seat"] for s in r1.signatures] == ["founder-a"] and await events("resolution.passed") == []
    assert (await db.execute(select(SigningSession))).scalars().all() == [], "nothing half-made is left behind"

    # 2. the node not answering is not a refusal: the pass and the signature stand, and the session is owed
    async def no_answer(*a, **k):
        raise XeError(0, "ConnectError: connection refused")
    ctx.config.human_seats = as_proposed
    ctx.chain.dao_keyset = no_answer
    await resolutions.decide(ctx, db, r1, vote(r1, "founder-b", k2), "for")
    await resolutions.decide(ctx, db, r2, vote(r2, "founder-a", k1), "for")
    await resolutions.decide(ctx, db, r2, vote(r2, "founder-b", k2), "for")
    assert r1.status == r2.status == "passed" and r1.session_id == r2.session_id == ""
    assert len(r1.signatures) == 2 and len(await events("resolution.session_deferred")) == 2

    # 3. the seats change while r1's session is still owed, so it is now one that cannot be opened. The worker
    # tries each on its own, every pass: that one does not hold up the one behind it (XE-1967), and what is
    # owed is written once, not once a pass
    ctx.config.human_seats = changed
    assert await resolutions.open_deferred_sessions(ctx, db) == 0
    refused = await events("resolution.session_refused")
    assert [x.payload["resolution_id"] for x in refused] == ["r1"] and "held by a seat" in refused[0].payload["error"]
    ctx.chain.dao_keyset = FakeChain.dao_keyset.__get__(ctx.chain)
    assert await resolutions.open_deferred_sessions(ctx, db) == 1 and r2.session_id and r1.session_id == ""
    assert await resolutions.open_deferred_sessions(ctx, db) == 0
    assert len(await events("resolution.session_refused")) == 1 and len(await events("resolution.session_deferred")) == 2
    # a failure the node words differently each time is still one thing owed, written once; and a failure
    # that is neither the node's nor a refusal (a bug, a bad row) is recorded and stops nothing either
    said = iter(range(100))

    async def reworded(*a, **k):
        raise XeError(0, f"ConnectError: request {next(said)} refused")

    async def broken(*a, **k):
        raise KeyError("a bug in opening the session")
    r3 = Resolution(id="r3", number=3, title="param", body="b", matter="parameter", ops=param_ops, proposed_by="founder-a",
                    status="passed", signatures=[])
    db.add(r3)
    await db.flush()
    ctx.chain.dao_keyset = reworded
    for _ in range(3):
        assert await resolutions.open_deferred_sessions(ctx, db) == 0
    assert [x.payload["resolution_id"] for x in await events("resolution.session_deferred")] == ["r1", "r2", "r3"]
    ctx.chain.dao_keyset = broken
    assert await resolutions.open_deferred_sessions(ctx, db) == 0 and await resolutions.open_deferred_sessions(ctx, db) == 0
    refused = await events("resolution.session_refused")
    assert [e.payload["resolution_id"] for e in refused] == ["r1", "r3"] and "KeyError" in refused[1].payload["error"]
    ctx.chain.dao_keyset = FakeChain.dao_keyset.__get__(ctx.chain)
    assert await resolutions.open_deferred_sessions(ctx, db) == 1 and r3.session_id
    # the seats change back: the session it was owed all along
    ctx.config.human_seats = ctx.config.members
    assert await resolutions.open_deferred_sessions(ctx, db) == 1
    assert (await sessions.get(db, r1.session_id)).kind == "keyset"
    await db.commit()

    # 4. a job step: committed if it returns, rolled back if it raises anything, and the job goes on
    async def half_done():
        db.add(HealthCheck(ts=1, ok=True, detail={}))
        await db.flush()
        raise ValueError("after a write")

    async def whole():
        db.add(HealthCheck(ts=2, ok=True, detail={}))
        return "done"
    assert await worker_mod.Worker._step(db, "half", half_done) is None
    assert await worker_mod.Worker._step(db, "whole", whole) == "done"
    await db.rollback()
    assert [h.ts for h in (await db.execute(select(HealthCheck))).scalars().all()] == [2]

    sm = async_sessionmaker(db.bind, expire_on_commit=False)

    @asynccontextmanager
    async def fake_session():
        async with sm() as s:
            yield s
    monkeypatch.setattr(worker_mod, "session", fake_session)
    now = time.time_ns()
    db.add(PauseRecord(id="p1", determined_by="founder-a", ground="g", determination="d" * 20, started_at=now - 10 * 3600 * 10**9,
                       expires_at=now - 3600 * 10**9, indefinite=False, extensions=[], lifted_by=[], status="active"))
    db.add(SeenSignature(sig="e" * 128, timestamp=now - 10 * MAX_SKEW_NS))
    await db.commit()
    ran = []

    def failing(name, exc):
        async def step(*a, **k):
            ran.append(name)
            raise exc
        return step
    # the first three steps of the timers job each fail a different way; the three behind them still run
    monkeypatch.setattr(portal, "close_due", failing("close", HTTPException(400, "a step that answers like a route")))
    monkeypatch.setattr(portal, "rederive_open", failing("rederive", KeyError("a bug")))
    monkeypatch.setattr(resolutions, "open_deferred_sessions", failing("owed", XeError(0, "node down")))
    await worker_mod.Worker(ctx).job_timers()
    assert ran == ["close", "rederive", "owed"]
    lapsed = (await db.execute(select(PauseRecord).where(PauseRecord.id == "p1").execution_options(populate_existing=True))).scalar_one()
    assert lapsed.status == "expired", "the pause clock ran"
    assert (await db.execute(select(SeenSignature))).scalars().all() == [], "the purge ran"
    assert "timers" in await last_runs(db)


# ---- XE-2148: one envelope per reply; the node's store is the record of whether it went ---------------------

async def test_a_reply_has_one_envelope_and_the_nodes_store_says_whether_it_went(db, monkeypatch):
    from dao.models import OutboxMessage
    ctx = _ctx()
    ctx.signer = FakeSigner(("harness", "fee", "dao"))
    store, offered, mode = [], [], {"send": "ok", "read": "ok"}

    async def send(env):
        offered.append(env["id"])
        if mode["send"] == "refuse":
            raise XeError(503, "peer unreachable")
        if env["id"] not in [e["id"] for e in store]:   # a node keeps one copy per envelope id
            store.append(env)
        if mode["send"] == "lose-answer":
            raise XeError(0, "ReadTimeout")

    async def messages(proof, since):
        if mode["read"] != "ok":
            raise XeError(0, "ConnectError")
        return [e for e in store if e["timestamp"] > since]

    async def proof(ctx_):
        return {}
    ctx.chain.chat_send, ctx.chain.chat_messages = send, messages
    monkeypatch.setattr(inbox, "read_proof", proof)

    def row(oid, status="queued", envelope=None):
        o = OutboxMessage(id=oid, to_account="c" * 64, body=oid, status=status, in_reply_to="m", from_seat="harness",
                          envelope=envelope or {}, error="")
        db.add(o)
        return o

    # 1. the node took the envelope and its answer was lost: the reply went once, and is recorded once
    o1 = row("o1")
    await db.commit()
    mode["send"] = "lose-answer"
    assert await inbox.flush_outbox(ctx, db) == 0
    first = o1.envelope["id"]
    assert o1.status == "sending" and offered == [first] and "ReadTimeout" in o1.error
    mode["send"] = "ok"
    assert await inbox.flush_outbox(ctx, db) == 1
    assert o1.status == "sent" and o1.envelope["id"] == first and offered == [first] and len(store) == 1, \
        "the store held it, so nothing was built or offered a second time"
    named = [e.payload["envelope_id"] for e in (await db.execute(select(Event).where(Event.kind == "outbox.sent"))).scalars().all()]
    assert named == [first]

    # 2. every way a `sending` row can stand, by the age of its envelope and what the store holds
    now = time.time_ns()

    def sending(oid, age_s, held=False):
        env = {"id": f"env-{oid}", "timestamp": now - age_s * inbox.NS, "message": oid, "to": "c" * 64}
        if held:
            store.append(env)
        return row(oid, "sending", env)
    rows = {o.id: o for o in (sending("held", 3600, held=True), sending("fresh", 30), sending("limbo", 300),
                              sending("expired", 3600), row("blank", "sending"))}
    await db.commit()
    assert inbox.FRESH_NS < 300 * inbox.NS < inbox.EXPIRED_NS
    # the store cannot be read: nothing is concluded from that, in either direction. No row is called sent
    # or given a new envelope; the fresh one is offered again as it is, which needs no reading of the store
    offered.clear()
    mode["read"] = "down"
    assert await inbox.flush_outbox(ctx, db) == 2
    assert {k: rows[k].status for k in ("held", "limbo", "expired")} == dict.fromkeys(("held", "limbo", "expired"), "sending")
    assert rows["fresh"].status == "sent" and rows["fresh"].envelope["id"] == "env-fresh", \
        "still fresh: the same envelope again, which the node keeps one copy of"
    assert rows["blank"].status == "sent" and offered == ["env-fresh", rows["blank"].envelope["id"]], \
        "a row marked sending with no envelope had nothing offered: it is built and sent like a queued one"
    # the store answers
    offered.clear()
    mode["read"] = "ok"
    assert await inbox.flush_outbox(ctx, db) == 2
    assert rows["held"].status == "sent" and "env-held" not in offered, "in the store: sent, however old, and not offered"
    assert rows["limbo"].status == "sending" and "env-limbo" not in offered, \
        "too old to be sure a node takes it, too young to be sure none did: left for the store to answer"
    assert rows["expired"].status == "sent" and rows["expired"].envelope["id"] != "env-expired" and "env-expired" not in offered, \
        "never held and past any node's window: only now is a second envelope built"
    assert len(offered) == 1 and len({e["id"] for e in store}) == len(store)
    # an item in the store whose id is not a string matches nothing and breaks nothing
    store.append({"id": ["env-limbo"], "timestamp": now, "message": "x", "to": "c" * 64})
    assert await inbox.flush_outbox(ctx, db) == 0 and rows["limbo"].status == "sending"
    store.pop()
    # an envelope's age is its age when the store was asked. The pass here is slow enough for this envelope
    # to cross from fresh to expired while it runs; judged afterwards it would be given up and replaced on
    # the word of a store that was asked while a node would still have taken it
    slow = sending("slow", 0)
    slow.envelope = {**slow.envelope, "timestamp": time.time_ns() - inbox.FRESH_NS + 30 * inbox.NS}
    await db.commit()

    async def slow_messages(proof, since):
        monkeypatch.setattr(inbox, "time", SimpleNamespace(time_ns=lambda: time.time_ns() + 10 * 60 * inbox.NS))
        return []
    ctx.chain.chat_messages = slow_messages
    offered.clear()
    mode["send"] = "refuse"
    assert await inbox.flush_outbox(ctx, db) == 0
    monkeypatch.setattr(inbox, "time", time)
    ctx.chain.chat_messages = messages
    assert slow.status == "sending" and slow.envelope["id"] == "env-slow" and offered == ["env-slow"], \
        "not replaced on that reading: the envelope it was asked about is the one still in play"
    slow.status = "sent"
    await db.commit()
    # a fresh envelope the node refuses keeps its id for the next pass
    again = sending("again", 30)
    await db.commit()
    offered.clear()
    mode["send"] = "refuse"
    assert await inbox.flush_outbox(ctx, db) == 0 and await inbox.flush_outbox(ctx, db) == 0
    assert again.status == "sending" and again.envelope["id"] == "env-again" and offered == ["env-again"] * 2
    assert "peer unreachable" in again.error


# ---- XE-2357: delivery moves a message only out of the status delivery set ---------------------------------

async def test_a_members_status_on_a_message_is_not_undone_by_its_reply_going_out_or_being_given_up(db):
    from datetime import datetime, timedelta, timezone
    ctx = _ctx()
    ctx.signer = FakeSigner(("harness", "fee", "dao"))
    now = time.time_ns()
    cases, sent = [], []
    for delivered in (True, False):   # both callers: the send that succeeds, the reply given up after a week
        for status in ("replying", "new", "read", "closed", "spam"):
            m = InboxMessage(id=f"{status}-{'sent' if delivered else 'given-up'}", channel="chat", from_account="a" * 64,
                             to_account="d" * 64, pub_key="p" * 64, body="q", timestamp=now, signature="s", pow_nonce=0,
                             verified=True, status="new")
            db.add(m)
            await db.flush()
            o = await inbox.queue_reply(ctx, db, m, f"answer to {m.id}", from_seat="cto")
            assert m.status == "replying" and m.reply_id == o.id
            m.status = status   # what a member did with the message after the reply was queued
            if not delivered:
                o.created_at = datetime.now(timezone.utc) - timedelta(days=inbox.OUTBOX_RETRY_DAYS + 1)
            cases.append((m, o, delivered, status))
    await db.commit()

    async def send(env):
        sent.append(env["message"])
    ctx.chain.chat_send = send
    assert await inbox.flush_outbox(ctx, db) == 5
    for m, o, delivered, status in cases:
        assert o.status == ("sent" if delivered else "failed"), m.id
        assert (o.body in sent) == delivered, m.id
        was_replying = status == "replying"
        assert m.status == (("answered" if delivered else "new") if was_replying else status), m.id
        assert m.reply_id == (o.id if delivered else ""), f"{m.id}: reply_id names only a reply that went out"
    moved = sorted(e.payload["id"] for e in (await db.execute(select(Event).where(Event.kind == "inbox.status"))).scalars().all())
    assert moved == ["replying-given-up", "replying-sent"], "the record shows only the moves delivery made"
    # a reply that is no longer the message's reply moves nothing either way
    m, o = cases[0][0], cases[0][1]
    m.status, m.reply_id = "replying", "a-later-reply"
    await db.flush()
    for delivered in (True, False):
        await inbox._reply_outcome(ctx, db, o, delivered=delivered)
        assert m.status == "replying" and m.reply_id == "a-later-reply"
    # XE-2629: a follow-up that is given up does not unsend the answer before it. The message is answered,
    # by the reply that went out; given up with nothing delivered before it, it is new again.
    m, first = cases[0][0], cases[0][1]
    m.status, m.reply_id = "answered", first.id
    second = await inbox.queue_reply(ctx, db, m, "a follow-up", from_seat="cto")
    assert m.status == "replying" and m.reply_id == second.id
    second.created_at = datetime.now(timezone.utc) - timedelta(days=inbox.OUTBOX_RETRY_DAYS + 1)
    await db.commit()
    assert await inbox.flush_outbox(ctx, db) == 0
    assert second.status == "failed" and m.status == "answered" and m.reply_id == first.id
    last = (await db.execute(select(Event).where(Event.kind == "inbox.status").order_by(Event.index.desc()).limit(1))).scalar_one()
    assert last.payload == {"id": m.id, "status": "answered", "reply": first.id}
    # the status delivery reads is the one on disk: a member's change made in another session since this
    # one loaded the message is not overwritten from a stale copy
    third = await inbox.queue_reply(ctx, db, m, "another", from_seat="cto")
    await db.commit()
    async with async_sessionmaker(db.bind, expire_on_commit=False)() as other:
        await other.execute(text("UPDATE inbox_messages SET status = 'closed' WHERE id = :id"), {"id": m.id})
        await other.commit()
    assert m.status == "replying", "this session still holds what it loaded"
    assert await inbox.flush_outbox(ctx, db) == 1
    assert third.status == "sent" and m.status == "closed" and m.reply_id == third.id


# ---- XE-2209: one bad item from the node costs one item ----------------------------------------------------

async def test_a_chat_item_that_is_not_an_envelope_is_skipped_by_both_readers(db, monkeypatch):
    import inspect

    from dao import worker as worker_mod
    from xe.chat import new_envelope
    ctx = _ctx()
    ctx.signer = FakeSigner(("harness", "fee", "dao"))
    me = ctx.signer.address("dao")
    kp = KeyPair.generate()
    good1, good2 = (new_envelope(kp, me, f"hello {i}", difficulty=0).to_json() for i in range(2))
    elsewhere = new_envelope(kp, "e" * 64, "not for the dao", difficulty=0).to_json()
    bad = [{"id": 5}, {**good1, "id": "x1", "timestamp": "soon"}, {**good1, "id": "x2", "message": ["a"]},
           {**good1, "id": "x3", "pow_nonce": -1}, {**good1, "id": "x4", "timestamp": 2**70}, {**good1, "id": "x" * 65},
           {**good1, "id": "x5", "from": None, "to": 7}, {}, None, [good1], "envelope"]
    for item in bad + [elsewhere]:
        assert await inbox.receive(ctx, db, item) is None, item
    assert (await db.execute(select(InboxMessage))).scalars().all() == []

    async def messages(proof, since):
        return [bad[0], good1, *bad[1:], elsewhere, good2, good1]

    async def proof(ctx_):
        return {}
    ctx.chain.chat_messages = messages
    monkeypatch.setattr(inbox, "read_proof", proof)
    assert await inbox.backfill(ctx, db) == 2
    assert {m.id for m in (await db.execute(select(InboxMessage))).scalars().all()} == {good1["id"], good2["id"]}
    assert await inbox.backfill(ctx, db) == 0, "what is held is not stored again"
    # the stream reader hands each item to the same function and parses nothing itself
    assert "inbox.receive(" in inspect.getsource(worker_mod.Worker.chat_loop) and not hasattr(worker_mod, "Envelope")


