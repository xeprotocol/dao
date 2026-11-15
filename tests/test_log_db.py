"""Event-log chain against a real Postgres. Skipped unless DAO_TEST_DATABASE_URL is set, e.g.
DAO_TEST_DATABASE_URL=postgresql+asyncpg://dao:pw@db:5432/dao_test (a scratch database; it is wiped)."""

import os
import time

import pytest
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from dao.db import Base
from dao.log import SEAL_KIND, EventLog, event_hash
from dao.models import Event, LogHead
from dao.signer import Signer
from xe.keys import KeyPair, exact_hex

URL = os.environ.get("DAO_TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(not URL, reason="DAO_TEST_DATABASE_URL not set")


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


def _signer():
    kp = KeyPair.generate()
    return Signer({"harness": kp}, {"harness": {"event.sign"}})


async def test_append_chain_and_verify(db):
    log = EventLog(_signer())
    for i in range(5):
        await log.append(db, "test", "harness", {"i": i})
    await db.commit()
    res = await EventLog.verify(db)
    assert res["ok"] and res["count"] == 5
    head = await EventLog.head(db)
    assert head.index == 4


async def test_a_session_that_has_appended_chains_to_the_head_as_it_is_now(db):
    """Two processes write one log. A session that appended and committed (a worker pass commits between
    events) appends again after another session has: its next event follows the other's, not its own."""
    log = EventLog(_signer())
    await log.append(db, "test", "worker", {"i": 0})
    await db.commit()
    # held, as a long-lived session's own objects are: without this the head is garbage-collected out of the
    # session's identity map and read afresh, and the test passes whatever `append` does
    held = (await db.execute(select(LogHead))).scalar_one()
    assert held.index == 0
    async with async_sessionmaker(db.bind, expire_on_commit=False)() as other:
        await log.append(other, "test", "app", {"i": 1})
        await other.commit()
    ev = await log.append(db, "test", "worker", {"i": 2})
    await db.commit()
    assert ev.index == 2
    res = await EventLog.verify(db)
    assert res["ok"] and res["count"] == 3


async def test_tamper_is_detected(db):
    log = EventLog(_signer())
    for i in range(3):
        await log.append(db, "test", "harness", {"i": i})
    await db.commit()
    await db.execute(text("UPDATE events SET payload = '{\"i\": 99}'::jsonb WHERE index = 1"))
    await db.commit()
    res = await EventLog.verify(db)
    assert not res["ok"] and "hash mismatch at 1" in res["first_error"]


# ---- XE-0462 / XE-0494: public and ref are in the hash; the signer is pinned; no unsigned rows ------

async def test_public_and_ref_are_covered_by_the_hash(db):
    log = EventLog(_signer())
    await log.append(db, "inbox.received", "harness", {"id": 1}, public=False, ref="inbox:1")
    await db.commit()
    await db.execute(text("UPDATE events SET public = true WHERE index = 0"))
    await db.commit()
    assert "hash mismatch at 0" in (await EventLog.verify(db))["first_error"]
    await db.execute(text("UPDATE events SET public = false, ref = 'proposal:other' WHERE index = 0"))
    await db.commit()
    assert "hash mismatch at 0" in (await EventLog.verify(db))["first_error"]


async def test_verify_pins_the_published_signer(db):
    signer = _signer()
    log = EventLog(signer)
    for i in range(3):
        await log.append(db, "test", "harness", {"i": i})
    await db.commit()
    key = signer.public_key("harness")
    assert (await EventLog.verify(db, key))["ok"]
    # a stripped signature verifies without the pin and fails with it
    await db.execute(text("UPDATE events SET signer = '', signature = '' WHERE index = 1"))
    await db.commit()
    assert (await EventLog.verify(db))["ok"]
    assert "event 1 is not signed by the harness key" in (await EventLog.verify(db, key))["first_error"]
    # a chain re-signed throughout by another key is a different log
    other = _signer()
    assert "event 0 is not signed by the harness key" in (await EventLog.verify(db, other.public_key("harness")))["first_error"]


async def test_append_refuses_to_write_unsigned_when_the_key_will_not_sign(db):
    from dao.log import LogError
    from dao.signer import Signer, SignerError

    class Refusing(Signer):
        def sign(self, name, scope, data):
            raise SignerError("hsm away")

    kp = KeyPair.generate()
    log = EventLog(Refusing({"harness": kp}, {"harness": {"event.sign"}}))
    with pytest.raises(LogError):
        await log.append(db, "test", "harness", {})


# ---- XE-2960: a verification is of the chain at one moment -------------------------------------

async def test_an_append_that_lands_during_a_replay_is_not_tampering(db, monkeypatch):
    """The log is written to while it is replayed. The answer is for the head sampled when the replay began:
    an event that commits part-way through is neither counted nor held against the chain."""
    log = EventLog(_signer())
    for i in range(3):
        await log.append(db, "test", "harness", {"i": i})
    await db.commit()
    real = EventLog.iter_all
    landed = []

    async def interleaved(db_, batch=1000, upto=None):
        async for ev in real(db_, batch, upto):
            if not landed:   # another process appends as soon as the replay has started reading
                async with async_sessionmaker(db.bind, expire_on_commit=False)() as other:
                    landed.append(await log.append(other, "test", "app", {"late": True}))
                    await other.commit()
            yield ev

    monkeypatch.setattr(EventLog, "iter_all", staticmethod(interleaved))
    res = await EventLog.verify(db)
    assert landed and res == {"ok": True, "count": 3, "head": res["head"], "first_error": None}
    monkeypatch.undo()
    res = await EventLog.verify(db)
    assert res["ok"] and res["count"] == 4 and res["head"] == landed[0].hash
    # and at every batch size, so the answer does not depend on where a batch boundary falls
    for batch in (1, 2, 3):
        async def small(db_, _batch=1000, upto=None, n=batch):
            async for ev in real(db_, n, upto):
                yield ev
        monkeypatch.setattr(EventLog, "iter_all", staticmethod(small))
        assert (await EventLog.verify(db))["count"] == 4
        monkeypatch.undo()


async def test_a_head_wound_back_or_ahead_of_its_events_fails(db):
    log = EventLog(_signer())
    evs = [await log.append(db, "test", "harness", {"i": i}) for i in range(3)]
    await db.commit()
    await db.execute(text("UPDATE log_head SET index = 1, hash = :h"), {"h": evs[1].hash})
    await db.commit()
    assert (await EventLog.verify(db))["first_error"] == "head row is behind the chain"
    await db.execute(text("UPDATE log_head SET index = 3, hash = :h"), {"h": evs[2].hash})
    await db.commit()
    assert (await EventLog.verify(db))["first_error"] == "head row disagrees with chain"
    await db.execute(text("UPDATE log_head SET index = 2, hash = :h"), {"h": evs[1].hash})
    await db.commit()
    assert (await EventLog.verify(db))["first_error"] == "head row disagrees with chain"
    await db.execute(text("UPDATE log_head SET index = 2, hash = :h"), {"h": evs[2].hash})
    await db.commit()
    assert (await EventLog.verify(db))["ok"]


# ---- XE-4017: a v1 event's public and ref are bound by the seal ------------------------------------

async def _append_v1(db, signer, payload, *, public, ref):
    """An event as it was written before the v2 envelope: hashed without `public` and `ref`, `v` = 1."""
    head = (await db.execute(select(LogHead).execution_options(populate_existing=True))).scalar_one()
    index, ts = head.index + 1, time.time_ns()
    h = event_hash(index, ts, "old", "harness", payload, head.hash, v=1)
    db.add(Event(index=index, ts=ts, kind="old", actor="harness", payload=payload, prev_hash=head.hash, hash=h,
                 signer=signer.public_key("harness"),
                 signature=signer.sign("harness", "event.sign", exact_hex(h, 32, "event hash")), public=public, ref=ref, v=1))
    head.index, head.hash = index, h
    await db.flush()


async def test_a_v1_events_public_and_ref_are_as_they_were_sealed(db):
    """Neither field is in a v1 row's hash, so a writer to the table could show a hidden row or repoint one and
    the replay stayed green. Once the seal is written, each of them on each v1 row is checked by every replay."""
    signer = _signer()
    log, key = EventLog(signer), signer.public_key("harness")
    # a process asks once whether there is anything to seal, so the empty log is asked by one of its own
    assert await EventLog(signer).seal_legacy(db) is None, "an empty log has nothing to seal"
    await db.rollback()
    await _append_v1(db, signer, {"i": 0}, public=False, ref="inbox:1")
    await _append_v1(db, signer, {"i": 1}, public=True, ref="")
    await log.append(db, "test", "harness", {"i": 2})
    await db.commit()
    res = await EventLog.verify(db, key)
    assert not res["ok"] and res["first_error"] == "the v1 events are not sealed"    # XE-14510: said by the replay itself
    assert res["legacy"] == {"rows": 2, "sealed": False}, "the log as it was before there was a seal"

    seal = await log.seal_legacy(db)
    await db.commit()
    assert seal.kind == SEAL_KIND and seal.index == 3 and seal.public and seal.signature
    assert {k: seal.payload[k] for k in ("rows", "through")} == {"rows": 2, "through": 1}
    assert await log.seal_legacy(db) is None, "written once"
    await db.rollback()
    res = await EventLog.verify(db, key)
    assert res["ok"] and res["count"] == 4 and res["legacy"] == {"rows": 2, "sealed": True}

    unsealed = "the v1 events are not as they were sealed at 3"
    for change, back, error in (
            ("UPDATE events SET public = true WHERE index = 0", "UPDATE events SET public = false WHERE index = 0", unsealed),
            ("UPDATE events SET ref = 'proposal:x' WHERE index = 0", "UPDATE events SET ref = 'inbox:1' WHERE index = 0", unsealed),
            ("UPDATE events SET public = false WHERE index = 1", "UPDATE events SET public = true WHERE index = 1", unsealed),
            ("UPDATE events SET ref = 'inbox:1' WHERE index = 1", "UPDATE events SET ref = '' WHERE index = 1", unsealed),
            # the envelope a row says it was hashed under
            ("UPDATE events SET v = 3 WHERE index = 2", "UPDATE events SET v = 2 WHERE index = 2", "unknown envelope at 2"),
            ("UPDATE events SET v = 2 WHERE index = 0", "UPDATE events SET v = 1 WHERE index = 0", "hash mismatch at 0")):
        await db.execute(text(change))
        await db.commit()
        db.expire_all()   # the replay reads the rows, not this session's copies of them
        res = await EventLog.verify(db, key)
        assert not res["ok"] and res["first_error"] == error, change
        await db.execute(text(back))
        await db.commit()
        db.expire_all()
    assert (await EventLog.verify(db, key))["ok"]

    # nothing is written under the old envelope after the seal: a row that says it was is refused
    await _append_v1(db, signer, {"i": 4}, public=True, ref="")
    await db.commit()
    db.expire_all()
    assert (await EventLog.verify(db, key))["first_error"] == "v1 event at 4, after the v1 rows were sealed"

