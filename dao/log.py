"""The ledger of record: an append-only, hash-chained, signed event log.

  v2: event.hash = sha256("xe-dao/event/v2\\0" || canonical_json({index, ts, kind, actor, payload,
                                                                  prev_hash, public, ref}))
  v1: the same without public and ref (rows written before 5 Nov 2026; `events.v` says which)
  event.signature = ed25519(hash_bytes) by the harness key

Appends serialise on a row lock over log_head so two writers can never fork the chain, and refuse rather
than write unsigned when the harness key will not sign (XE-0462). `verify()` replays the whole chain,
recomputes every hash, and with `expected_signer` checks every signature against the one published key, so
a stripped or re-signed chain fails (XE-0494); `/v1/log/head` and the weekly anchor expose the head so
anyone can check the chain against the state chain.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, AsyncIterator

from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from xe.keys import verify_hex_signature

from .canonical import DOMAIN_EVENT, DOMAIN_EVENT_V2, digest
from .models import Event, LogHead
from .signer import Signer, SignerError

ZERO = "0" * 64


@dataclass
class Head:
    index: int
    hash: str


def event_hash(index: int, ts: int, kind: str, actor: str, payload: dict, prev_hash: str, *,
               public: bool = True, ref: str = "", v: int = 2) -> str:
    body: dict[str, Any] = {"index": index, "ts": ts, "kind": kind, "actor": actor, "payload": payload, "prev_hash": prev_hash}
    if v >= 2:
        body["public"] = bool(public)
        body["ref"] = ref
    return digest(DOMAIN_EVENT_V2 if v >= 2 else DOMAIN_EVENT, body).hex()


class LogError(RuntimeError):
    """The log could not be written as the deployment promises (a harness key that will not sign)."""


class EventLog:
    def __init__(self, signer: Signer):
        self.signer = signer
        self._listeners: list[Any] = []

    def subscribe(self, queue: Any) -> None:
        self._listeners.append(queue)

    def unsubscribe(self, queue: Any) -> None:
        if queue in self._listeners:
            self._listeners.remove(queue)

    async def append(self, db: AsyncSession, kind: str, actor: str, payload: dict, *, ref: str = "",
                     public: bool = True, ts: int | None = None) -> Event:
        """Append one event inside the caller's transaction. Caller commits."""
        head = (await db.execute(select(LogHead).where(LogHead.id == 1).with_for_update())).scalar_one()
        index = head.index + 1
        ts = ts if ts is not None else time.time_ns()
        h = event_hash(index, ts, kind, actor, payload, head.hash, public=public, ref=ref, v=2)
        signer_pk, sig = "", ""
        if self.signer.has("harness"):
            try:
                signer_pk = self.signer.public_key("harness")
                sig = self.signer.sign("harness", "event.sign", bytes.fromhex(h))
            except SignerError as e:
                # a configured key that will not sign is an outage, not a reason to write an unsigned row
                raise LogError(f"harness key will not sign: {e}") from e
        ev = Event(index=index, ts=ts, kind=kind, actor=actor, payload=payload, prev_hash=head.hash, hash=h,
                   signer=signer_pk, signature=sig, public=public, ref=ref, v=2)
        db.add(ev)
        head.index = index
        head.hash = h
        await db.flush()
        for q in list(self._listeners):
            try:
                q.put_nowait(ev)
            except Exception:
                pass
        return ev

    @staticmethod
    async def head(db: AsyncSession) -> Head:
        head = (await db.execute(select(LogHead).where(LogHead.id == 1))).scalar_one()
        return Head(head.index, head.hash)

    @staticmethod
    async def count(db: AsyncSession) -> int:
        return int((await db.execute(select(func.count()).select_from(Event))).scalar_one())

    @staticmethod
    async def page(db: AsyncSession, offset: int = 0, limit: int = 100, kind: str | None = None,
                   ref: str | None = None, public_only: bool = True, descending: bool = True) -> list[Event]:
        q = select(Event)
        if public_only:
            q = q.where(Event.public.is_(True))
        if kind:
            q = q.where(Event.kind == kind)
        if ref:
            q = q.where(Event.ref == ref)
        q = q.order_by(Event.index.desc() if descending else Event.index.asc()).offset(offset).limit(min(limit, 1000))
        return list((await db.execute(q)).scalars().all())

    @staticmethod
    async def since(db: AsyncSession, after: int, limit: int = 200, public_only: bool = True) -> list[Event]:
        q = select(Event).where(Event.index > after)
        if public_only:
            q = q.where(Event.public.is_(True))
        return list((await db.execute(q.order_by(Event.index.asc()).limit(limit))).scalars().all())

    @staticmethod
    async def get(db: AsyncSession, index: int) -> Event | None:
        return (await db.execute(select(Event).where(Event.index == index))).scalar_one_or_none()

    @staticmethod
    async def iter_all(db: AsyncSession, batch: int = 1000) -> AsyncIterator[Event]:
        start = 0
        while True:
            rows = list((await db.execute(
                select(Event).where(Event.index >= start).order_by(Event.index.asc()).limit(batch)
            )).scalars().all())
            if not rows:
                return
            for r in rows:
                yield r
            start = rows[-1].index + 1

    _verify_cache: tuple[float, dict] | None = None
    VERIFY_CACHE_S = 60

    @classmethod
    async def verify_cached(cls, db: AsyncSession, expected_signer: str = "") -> dict:
        """`verify()` for the public route: a full replay is O(log); one is kept for a minute per process so
        the route cannot be used to make the database re-read the whole chain on demand."""
        now = time.monotonic()
        if cls._verify_cache and now - cls._verify_cache[0] < cls.VERIFY_CACHE_S:
            return {**cls._verify_cache[1], "cached": True}
        out = await cls.verify(db, expected_signer)
        cls._verify_cache = (now, out)
        return {**out, "cached": False}

    @staticmethod
    async def verify(db: AsyncSession, expected_signer: str = "") -> dict:
        """Replay the chain. Returns {ok, count, head, first_error}. With `expected_signer` (the deployment's
        published harness key) every event must carry a signature by that key: a stripped signature or a
        re-signed chain fails, which is the point of publishing the key."""
        prev = ZERO
        expected_index = 0
        count = 0
        last_hash = ZERO
        async for ev in EventLog.iter_all(db):
            if ev.index != expected_index:
                return {"ok": False, "count": count, "first_error": f"gap at index {expected_index}", "head": last_hash}
            if ev.prev_hash != prev:
                return {"ok": False, "count": count, "first_error": f"prev_hash mismatch at {ev.index}", "head": last_hash}
            h = event_hash(ev.index, ev.ts, ev.kind, ev.actor, ev.payload, ev.prev_hash, public=ev.public, ref=ev.ref, v=ev.v)
            if h != ev.hash:
                return {"ok": False, "count": count, "first_error": f"hash mismatch at {ev.index}", "head": last_hash}
            if expected_signer and (not ev.signature or ev.signer != expected_signer):
                return {"ok": False, "count": count, "first_error": f"event {ev.index} is not signed by the harness key",
                        "head": last_hash}
            if ev.signature:
                try:
                    verify_hex_signature(ev.signer, ev.signature, bytes.fromhex(ev.hash))
                except ValueError:
                    return {"ok": False, "count": count, "first_error": f"bad signature at {ev.index}", "head": last_hash}
            prev = h
            last_hash = h
            expected_index += 1
            count += 1
        head = await EventLog.head(db)
        ok = head.hash == last_hash and head.index == count - 1
        return {"ok": ok, "count": count, "head": last_hash, "first_error": None if ok else "head row disagrees with chain"}


def event_to_dict(ev: Event) -> dict:
    return {
        "index": ev.index, "ts": ev.ts, "kind": ev.kind, "actor": ev.actor, "payload": ev.payload,
        "prev_hash": ev.prev_hash, "hash": ev.hash, "signer": ev.signer, "signature": ev.signature, "ref": ev.ref,
        "public": ev.public, "v": ev.v,
    }
