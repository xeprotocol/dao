"""Event-log chain against a real Postgres. Skipped unless DAO_TEST_DATABASE_URL is set, e.g.
DAO_TEST_DATABASE_URL=postgresql+asyncpg://dao:pw@db:5432/dao_test (a scratch database; it is wiped)."""

import os

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from dao.db import Base
from dao.log import EventLog
from dao.models import LogHead  # noqa: F401  (registers the table on Base.metadata)
from dao.signer import Signer
from xe.keys import KeyPair

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
