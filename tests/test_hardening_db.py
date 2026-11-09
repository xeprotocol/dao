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


class FakeSigner:
    def __init__(self, scopes=("harness",)):
        self._kp = {s: KeyPair.generate() for s in scopes}

    def has(self, s):
        return s in self._kp

    def address(self, s):
        return FEE_ACCT if s == "fee" else self._kp[s].address

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
    # the rows stay due with the reason on them, and are looked at again every pass; the event fires once
    assert [r.state for r in rows] == ["due_refund", "due_burn"] and all(r.error == fees.UNRECEIVED_ERROR for r in rows)
    assert await fees.settle_due(ctx, db) == 0
    kinds = (await db.execute(select(Event.kind))).scalars().all()
    assert kinds.count("fee.unreceived") == 2


# ---- XE-0486 / XE-0488: fee writes are exactly-once and every receive is recorded as it lands ----

def _fee_chain(blocks):
    """A FakeChain whose fee account carries `blocks`."""
    return FakeChain(chains={FEE_ACCT: blocks})


async def test_settlement_is_marked_before_the_send_and_reconciled_after_a_crash(db, monkeypatch):
    ctx = _ctx(_fee_chain([]))
    seen: list[dict] = []

    async def send(ctx_, key, scope, dest, amount, memo=""):
        # what the database says at the moment the XE leaves: already `settling`, nonce committed, in the memo
        sm = async_sessionmaker(db.bind, expire_on_commit=False)
        async with sm() as other:
            row = (await other.execute(select(FeeLedger))).scalar_one()
            seen.append({"state": row.state, "memo": memo, "nonce": row.tx_hashes.get("settle_nonce")})
        return SimpleNamespace(hash="5" * 64)

    monkeypatch.setattr(fees.chainops, "send", send)
    db.add(FeeLedger(fee_block_hash="1" * 64, proposal_hash="2" * 64, payer=AUTHOR, amount=1000, state="due_refund",
                     tx_hashes={"receive": "9" * 64}))
    await db.commit()
    assert await fees.settle_due(ctx, db) == 1
    assert seen[0]["state"] == "settling" and seen[0]["memo"].endswith(" " + seen[0]["nonce"])
    row = (await db.execute(select(FeeLedger))).scalar_one()
    assert row.state == "refunded" and row.tx_hashes == {"receive": "9" * 64, "refund": "5" * 64}

    # a crash after the send and before the record: the row is `settling`, the block is on the chain
    nonce = "deadbeef"
    row.state, row.tx_hashes = "settling", {"receive": "9" * 64, "settle_as": "refund", "settle_nonce": nonce}
    await db.commit()
    ctx = _ctx(_fee_chain([{"type": "send", "memo": f"fee refund {'2' * 12} {nonce}", "hash": "6" * 64}]))
    seen.clear()
    assert await fees.settle_due(ctx, db) == 1
    assert not seen, "a settlement already on the chain is never paid again"
    row = (await db.execute(select(FeeLedger))).scalar_one()
    assert row.state == "refunded" and row.tx_hashes["refund"] == "6" * 64
    kinds = (await db.execute(select(Event.kind))).scalars().all()
    assert kinds.count("fee.refunded") == 2

    # a crash before the send: `settling` with no block on the chain goes back to due and is paid once, now
    row.state, row.tx_hashes = "settling", {"receive": "9" * 64, "settle_as": "refund", "settle_nonce": "00000000"}
    await db.commit()
    ctx = _ctx(_fee_chain([]))
    assert await fees.settle_due(ctx, db) == 1
    row = (await db.execute(select(FeeLedger))).scalar_one()
    assert len(seen) == 1 and seen[0]["nonce"] != "00000000" and row.state == "refunded"


async def test_each_receive_is_committed_as_it_lands_and_a_bad_one_is_skipped(db, monkeypatch):
    ctx = _ctx()
    pending = [{"send_hash": h * 64, "source": AUTHOR, "destination": FEE_ACCT, "amount": 1000, "asset": "XE", "timestamp": 0}
               for h in "123"]
    for h in "123":
        db.add(FeeLedger(fee_block_hash=h * 64, proposal_hash=h * 64, payer=AUTHOR, amount=1000, state="seen", tx_hashes={}))
    await db.commit()

    async def pending_for(_addr):
        return pending

    async def tip(_chain, _acct):
        return "0", {"XE": 0}

    async def submit(ctx_, b, kp):
        if b.source == "2" * 64:
            raise XeError(409, "node refused this one")
        b.hash = "f" + b.source[1:]
        return b

    monkeypatch.setattr(ctx.chain, "pending_for", pending_for, raising=False)
    monkeypatch.setattr(fees.chainops, "_tip", tip)
    monkeypatch.setattr(fees.chainops, "submit_signed", submit)
    assert await fees.receive_all(ctx, db) == 2
    rows = {r.fee_block_hash[0]: r for r in (await db.execute(select(FeeLedger))).scalars().all()}
    assert rows["1"].tx_hashes.get("receive") == "f" + "1" * 63
    assert rows["3"].tx_hashes.get("receive") == "f" + "3" * 63, "the entry behind the failed one was still received"
    assert "receive" not in rows["2"].tx_hashes


async def test_a_due_fee_whose_receive_was_never_recorded_is_found_on_the_chain(db, monkeypatch):
    recv = {"type": "receive", "source": "1" * 64, "hash": "8" * 64, "balance": 1000, "asset": "XE"}
    ctx = _ctx(_fee_chain([recv]))

    async def burn(ctx_, key, scope, amount, memo=""):
        return SimpleNamespace(hash="7" * 64)

    monkeypatch.setattr(fees.chainops, "burn", burn)
    db.add(FeeLedger(fee_block_hash="1" * 64, proposal_hash="2" * 64, payer=AUTHOR, amount=1000, state="due_burn", tx_hashes={}))
    await db.commit()
    assert await fees.settle_due(ctx, db) == 1
    row = (await db.execute(select(FeeLedger))).scalar_one()
    assert row.state == "burned" and row.tx_hashes == {"receive": "8" * 64, "burn": "7" * 64}
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
    assert e.value.status_code == 400 and "control character" in e.value.detail
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


def _member(seat, rights=("pause",), key="p" * 64):
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
    assert r.status == "passed"


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
    assert r.status == "lifted"
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

async def test_an_overpaid_fee_burns_the_fee_and_returns_the_rest(db, monkeypatch):
    ctx = _ctx(_fee_chain([]))
    now = time.time_ns()
    pr = Proposal(hash="a" * 64, title="t", body="b", ops=None, author_account=AUTHOR, author_pub_key="p" * 64,
                  author_signature="s", author_timestamp=now, fee_block_hash="1" * 64, status="closed", opened_at=now - D,
                  closes_at=now - 1, rules=ctx.config.pinned_rules(), analysis=[])
    db.add(pr)
    db.add(FeeLedger(fee_block_hash="1" * 64, proposal_hash="a" * 64, payer=AUTHOR, amount=1500, state="due_burn",
                     tx_hashes={"receive": "9" * 64}))
    await db.commit()
    moved: list[tuple] = []

    async def burn(ctx_, key, scope, amount, memo=""):
        moved.append(("burn", amount, memo))
        return SimpleNamespace(hash="b" * 64)

    async def send(ctx_, key, scope, dest, amount, memo=""):
        moved.append(("send", dest, amount, memo))
        return SimpleNamespace(hash="e" * 64)

    monkeypatch.setattr(fees.chainops, "burn", burn)
    monkeypatch.setattr(fees.chainops, "send", send)
    assert await fees.settle_due(ctx, db) == 1
    assert moved[0][:2] == ("burn", 1000) and moved[1][:3] == ("send", AUTHOR, 500)
    assert moved[0][2].split()[1] == "burn" and moved[1][3].split()[1] == "excess"
    row = (await db.execute(select(FeeLedger))).scalar_one()
    assert row.state == "burned" and row.tx_hashes["burn"] == "b" * 64 and row.tx_hashes["excess"] == "e" * 64
    kinds = (await db.execute(select(Event.kind))).scalars().all()
    assert kinds.count("fee.burned") == 1 and kinds.count("fee.excess_returned") == 1


# ---- XE-0349: keyset rotation runs through a keyset session; nothing can jam at the deciding vote -----

async def test_change_keyset_opens_a_keyset_session_and_bad_ops_are_refused_when_proposed(db):
    from dao.services import resolutions
    ctx = _ctx()
    ctx.config.members = [_member("founder-a")]
    ctx.config.windows = {}
    k1, k2, k3 = (KeyPair.generate().pub_key_hex for _ in range(3))
    ctx.config.human_seats = [SimpleNamespace(public_key=k1), SimpleNamespace(public_key=k2)]   # k3 is nobody's
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


async def test_settlement_and_outbox_read_the_pause_right_before_the_chain_write(db, monkeypatch):
    from dao.models import OutboxMessage, PauseRecord
    ctx = _ctx()
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
    pauses = iter(["p1", "p2"])

    async def pause_then(*a, **k):
        # the pause is committed after the job began and before the chain write
        db.add(PauseRecord(id=next(pauses), determined_by="founder-a", ground="g", determination="d" * 20, started_at=now,
                           expires_at=now + 10 ** 12, indefinite=False, extensions=[], lifted_by=[], status="active"))
        await db.commit()
        return SimpleNamespace(hash="x" * 64, id="e", to_json=lambda: {})

    async def wrote(*a, **k):
        sent.append(1)

    ctx.signer = FakeSigner(("harness", "fee", "dao"))
    monkeypatch.setattr(fees.chainops, "burn", wrote)
    monkeypatch.setattr(fees.chainops, "send", wrote)
    monkeypatch.setattr(fees, "_fee_due", pause_then)      # the last await before the burn
    await fees.settle_due(ctx, db)
    f = (await db.execute(select(FeeLedger))).scalar_one()
    assert f.state == "settling" and not f.error and not sent, "marked, but the burn did not go out under the pause"
    # the same for a queued reply: the pause lands while the envelope's proof of work is being computed
    (await db.execute(select(PauseRecord))).scalar_one().status = "lifted"
    await db.commit()
    ctx.chain.chat_send = wrote
    monkeypatch.setattr(inbox, "asyncio", SimpleNamespace(to_thread=pause_then))
    assert await inbox.flush_outbox(ctx, db) == 0
    o = (await db.execute(select(OutboxMessage))).scalar_one()
    assert o.status == "queued" and not sent


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

    ctx = _ctx(chain=Chain())
    ctx.signer = FakeSigner(("harness", "fee", "dao"))
    ctx.node = SimpleNamespace(chat_pow_difficulty=0, network_id="xe-test")
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
    await db.commit()

    w = worker_mod.Worker(ctx)
    for job in (w.job_fees, w.job_outbox, w.job_timers, w.job_sessions, w.job_anchor):
        await job()
    assert calls == [], f"node writes under pause: {calls}"
    # the directory entry is addressability, not action: it is kept alive through the pause so the inbox,
    # which the pause keeps open, can still be reached
    await w.job_directory()
    assert calls == ["directory_register"]


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
    monkeypatch.setattr(inbox, "new_envelope", lambda kp, to, body, *a: SimpleNamespace(id="e", to_json=lambda: {"to": to}))
    assert await inbox.flush_outbox(ctx, db) == 2
    assert on_disk == [0, 1, 1], "each delivered row was committed before the next envelope was built"
    rows = {o.id: o for o in (await db.execute(select(OutboxMessage))).scalars().all()}
    assert rows["o0"].status == "sent" and rows["o2"].status == "sent"
    assert rows["o1"].status == "queued" and "channel closed" in rows["o1"].error


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
    now = time.time_ns()
    old = SigningSession(id="anchor-old", kind="anchor", title="A", ops=[], ops_digest="f" * 64, status="approving", approvals=[],
                         required_approvals=2, block=None, block_hash="", block_signatures=[], rebuilds=0, not_before=None)
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
    await sessions.submit(ctx, db, s)
    assert s.status == "submitted" and s.submitted_index == s.block["index"]


# ---- XE-1677 / XE-1817: only a refusal about the block ends a session -------------------------------------

async def test_a_refusal_that_says_nothing_about_the_block_defers_and_a_keyset_refusal_rebuilds(db):
    ctx = _ctx()
    ctx.chain.statechain_tip = lambda: _tip_at(0)
    answers = {}

    async def refuse(blk):
        raise answers["e"]
    ctx.chain.submit_statechain_block = refuse
    # a rate limit: the node never looked at the block
    s1 = await _signing(db, "s1", index=1, n=1)
    answers["e"] = XeError(429, "rate limit exceeded")
    await sessions.submit(ctx, db, s1)
    assert s1.status == "signing" and "429" in s1.error and len(s1.block_signatures) == 2
    # a server error: the same
    answers["e"] = XeError(503, "service unavailable")
    await sessions.submit(ctx, db, s1)
    assert s1.status == "signing"
    # the keyset moved under the block, approvals still meet the live keyset: rebuilt for the new signers
    s2 = await _signing(db, "s2", index=1, n=2)
    answers["e"] = XeError(400, "block rejected: signer k9 not in keyset")
    await sessions.submit(ctx, db, s2)
    assert s2.status == "signing" and s2.block_signatures == [] and s2.rebuilds == 1
    assert (await db.execute(select(Event).where(Event.kind == "session.keyset_moved"))).scalars().first()
    # the keyset moved and the approvals no longer meet it: back to approving (XE-0988), not failed
    s3 = await _signing(db, "s3", index=1, n=3)
    s3.approvals = [{"public_key": "old1"}, {"public_key": "old2"}]
    answers["e"] = XeError(400, "block rejected: insufficient signatures: got 1, need 2")
    await sessions.submit(ctx, db, s3)
    assert s3.status == "approving" and s3.block is None
    # a refusal about the block itself, from a node that answered: failed, as before
    s4 = await _signing(db, "s4", index=1, n=4)
    answers["e"] = XeError(400, "block rejected: epoch key already exists")
    await sessions.submit(ctx, db, s4)
    assert s4.status == "failed"


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
            row = (await other.execute(select(OutboxMessage).where(OutboxMessage.body == env["body"]))).scalar_one()
            seen.append(row.status)
        sent.append(env["body"])
    ctx.chain.chat_send = send
    monkeypatch.setattr(inbox, "new_envelope", lambda kp, to, body, *a: SimpleNamespace(id="e" + body, to_json=lambda: {"to": to, "body": body}))
    assert await inbox.flush_outbox(ctx, db) == 2
    assert sent == ["the answer", "ack"], "a member's reply goes before an acknowledgement queued earlier"
    assert seen == ["sending", "sending"], "the intent to send is on disk before the send"
    await db.refresh(m)
    assert m.status == "answered" and reply.status == "sent" and ack.status == "sent"
    # a row the last pass left `sending`: not sent again, settled as unconfirmed
    db.add(OutboxMessage(id="u1", to_account="b" * 64, body="maybe", status="sending", in_reply_to="m1", from_seat="cto", envelope={}, error=""))
    await db.commit()
    assert await inbox.flush_outbox(ctx, db) == 0 and "maybe" not in sent
    u = (await db.execute(select(OutboxMessage).where(OutboxMessage.id == "u1"))).scalar_one()
    assert u.status == "sent" and "unconfirmed" in u.error
    assert (await db.execute(select(Event).where(Event.kind == "outbox.unconfirmed"))).scalars().one()
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


# ---- XE-1650: a proposal's ops are ones a resolution could carry -------------------------------------------

async def test_proposal_ops_must_be_ones_some_resolution_could_authorise(db):
    ctx = _ctx()
    k1, k2, k3 = (KeyPair.generate().pub_key_hex for _ in range(3))
    ctx.config.human_seats = [SimpleNamespace(public_key=k1), SimpleNamespace(public_key=k2)]
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
