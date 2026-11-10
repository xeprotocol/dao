from __future__ import annotations

from contextlib import asynccontextmanager
from typing import AsyncIterator

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from .settings import get_settings


class Base(DeclarativeBase):
    pass


_engine = None
_sessionmaker: async_sessionmaker[AsyncSession] | None = None


def engine():
    global _engine
    if _engine is None:
        _engine = create_async_engine(get_settings().database_url, pool_pre_ping=True, pool_size=10, max_overflow=10)
    return _engine


def sessionmaker() -> async_sessionmaker[AsyncSession]:
    global _sessionmaker
    if _sessionmaker is None:
        _sessionmaker = async_sessionmaker(engine(), expire_on_commit=False)
    return _sessionmaker


@asynccontextmanager
async def session() -> AsyncIterator[AsyncSession]:
    async with sessionmaker()() as s:
        yield s


async def serialize(db: AsyncSession, name: str) -> None:
    """Hold a transaction-scoped advisory lock on `name` until this transaction ends. For a value computed
    from the table and then inserted (the next resolution number, the next anchor number, a fee block's
    first use): the second transaction waits here, then reads what the first committed, so both succeed
    in order rather than one losing on the unique key (XE-1290, XE-1435)."""
    await db.execute(text("SELECT pg_advisory_xact_lock(hashtext(:name))"), {"name": name})


@asynccontextmanager
async def only_one(db: AsyncSession, name: str) -> AsyncIterator[bool]:
    """True inside the block if no other process on this database is inside it under the same `name`; False
    if one is, without waiting. For a job that must not run twice at once and commits as it goes, where the
    transaction-scoped lock above would be let go at the first commit. The lock belongs to a connection
    taken for the purpose and is released by closing that connection, which a dying process also does:
    there is no unlock to miss."""
    conn = await db.bind.connect()
    try:
        got = (await conn.execute(text("SELECT pg_try_advisory_lock(hashtext(:name))"), {"name": name})).scalar()
        await conn.commit()
        yield bool(got)
    finally:
        await conn.invalidate()
        await conn.close()


async def get_db() -> AsyncIterator[AsyncSession]:
    async with sessionmaker()() as s:
        yield s
        # Reached only when the handler returned normally (an exception is raised into the generator at the
        # yield). A handler that read and returned still made one write, its signature claim, so the claim
        # cannot be lost by a missing commit (XE-0647). Handlers that commit themselves make this a no-op.
        await s.commit()
