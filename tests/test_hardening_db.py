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
from dao.models import Event, FeeLedger, InboxMessage, Proposal, SeenSignature, Vote
from dao.services import fees, inbox, portal
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
        self.blocks, self.chains = blocks or {}, chains or {}

    async def block(self, h):
        if h not in self.blocks:
            raise XeError(404, "not found")
        return self.blocks[h]

    async def full_chain(self, account):
        return self.chains.get(account, [{"timestamp": 0, "asset": "XE", "balance": 5_000_000, "hash": "b" * 64}])


class FakeSigner:
    def __init__(self, scopes=("harness",)):
        self._kp = {s: KeyPair.generate() for s in scopes}

    def has(self, s):
        return s in self._kp

    def address(self, s):
        return FEE_ACCT if s == "fee" else self._kp[s].address

    def public_key(self, s):
        return self._kp[s].pub_key_hex

    def sign(self, s, _scope, data):
        return self._kp[s].sign_hex(data)


def _ctx(chain=None, fee=True):
    signer = FakeSigner(("harness", "fee") if fee else ("harness",))
    events = EventLog(Signer({"harness": signer._kp["harness"]}, {"harness": {"event.sign"}}))
    config = SimpleNamespace(agent_accounts=set(), accounts={"dao": "d" * 64, "fee": FEE_ACCT},
                             pinned_rules=lambda: {"fee_micro_xe": 1000, "window_days": 7, "participating_wallet": {},
                                                   "excluded_accounts": [], "agents": {}})
    return SimpleNamespace(chain=chain or FakeChain(), signer=signer, events=events, config=config,
                           node=SimpleNamespace(chat_pow_difficulty=0))


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


async def test_settlement_refuses_fees_never_received(db, monkeypatch):
    ctx = _ctx()
    sent = []

    async def no_send(*a, **k):
        sent.append(a)
        raise AssertionError("must not pay out an unreceived fee")

    monkeypatch.setattr(fees.chainops, "send", no_send)
    monkeypatch.setattr(fees.chainops, "burn", no_send)
    db.add(FeeLedger(fee_block_hash="1" * 64, proposal_hash="2" * 64, payer=AUTHOR, amount=1000, state="due_refund", tx_hashes={}))
    db.add(FeeLedger(fee_block_hash="3" * 64, proposal_hash="4" * 64, payer=AUTHOR, amount=1000, state="due_burn", tx_hashes={}))
    await db.flush()
    assert await fees.settle_due(ctx, db) == 0
    assert not sent
    rows = (await db.execute(select(FeeLedger).order_by(FeeLedger.fee_block_hash))).scalars().all()
    assert [r.state for r in rows] == ["unreceived", "unreceived"]
    kinds = (await db.execute(select(Event.kind))).scalars().all()
    assert kinds.count("fee.unreceived") == 2


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
    assert e.value.status_code == 400 and "control character" in e.value.detail
    ctx.node.chat_pow_difficulty = 0x0100000000000000
    with pytest.raises(HTTPException) as e:
        await inbox.http_submit(ctx, db, _v(payload={"message": "hi"}))
    assert e.value.status_code == 400 and "pow_nonce" in e.value.detail
    assert (await db.execute(select(InboxMessage))).scalar_one_or_none() is None


async def test_proposal_text_with_nul_is_a_400_not_a_500(db):
    ctx = _ctx()
    with pytest.raises(HTTPException) as e:
        await portal.submit(ctx, db, _v(payload={"title": "x\x00y", "body": "fine", "fee_block_hash": "e" * 64}))
    assert e.value.status_code == 400 and "title" in e.value.detail
