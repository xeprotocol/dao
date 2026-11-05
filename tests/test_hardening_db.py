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
from dao.models import Event, FeeLedger, InboxMessage, Proposal, SeenSignature, SigningSession, Vote
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
        self.blocks, self.chains = blocks or {}, chains or {}

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

    def keypair(self, s, _scope=None):
        return self._kp[s]

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
    ctx.config.members = [SimpleNamespace(id="founder-a", is_member=True), SimpleNamespace(id="founder-b", is_member=True)]
    ctx.config.windows = {}
    # an ordinary matter needs a majority of two: 2. "gone" signed for while a member, then left.
    r = Resolution(id="r9", number=9, title="note", body="b", matter="note", ops=None, proposed_by="founder-a",
                   status="open", signatures=[{"seat": "gone", "public_key": "g", "signature": "s", "decision": "for", "timestamp": 1}])
    db.add(r)
    await db.flush()

    def member(seat, decision):
        v = _v(payload={"resolution_id": "r9", "body_hash": resolutions.body_hash(r), "decision": decision})
        v.seat = SimpleNamespace(id=seat, is_member=True)
        return v

    await resolutions.decide(ctx, db, r, member("founder-a", "for"), "for")
    assert r.status == "open", "one live vote plus a departed member's vote is not a majority"
    ev = (await db.execute(select(Event).where(Event.kind == "resolution.signed"))).scalars().all()[-1]
    assert ev.payload["for"] == 1 and ev.payload["set_aside"] == ["gone"]
    await resolutions.decide(ctx, db, r, member("founder-b", "for"), "for")
    assert r.status == "passed"
