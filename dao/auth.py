"""Signed requests. Nobody logs in; people sign.

Every write from a human (member, officer, or the public) is a JSON body of the form

    {"payload": {...}, "timestamp": <ns>, "pub_key": <hex>, "signature": <hex>}

where signature = ed25519 over sha256(domain || canonical_json({"payload": payload, "timestamp": timestamp}))
and the account is derived from pub_key. The domain is fixed per endpoint so a vote signature can
never be replayed as a resolution approval. Timestamps must be within ±10 minutes; a (pub_key,
signature) pair is accepted once.
"""

from __future__ import annotations

import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any

from fastapi import HTTPException
from pydantic import BaseModel, Field

from xe.keys import KeyError_, derive_address, verify_hex_signature

from .canonical import digest
from .config import Config, HumanSeat

MAX_SKEW_NS = 10 * 60 * 1_000_000_000


class SignedRequest(BaseModel):
    payload: dict[str, Any] = Field(default_factory=dict)
    timestamp: int
    pub_key: str
    signature: str


@dataclass
class Verified:
    account: str
    pub_key: str
    payload: dict
    timestamp: int
    signature: str
    seat: HumanSeat | None = None

    @property
    def actor(self) -> str:
        return f"seat:{self.seat.id}" if self.seat else f"account:{self.account}"


REPLAY_WINDOW_S: int = 2 * (MAX_SKEW_NS // 1_000_000_000)  # 1200s (20 minutes covers ±10m window)


class _Seen:
    """Bounded, time-window replay cache keyed by signature hex."""
    def __init__(self, cap: int = 50_000, ttl_s: int = REPLAY_WINDOW_S):
        self._d: dict[str, float] = {}
        self.cap = cap
        self.ttl_s = ttl_s

    def _prune(self, now: float) -> None:
        expired = [sig for sig, exp in self._d.items() if exp <= now]
        for sig in expired:
            del self._d[sig]

    def check_and_add(self, sig: str) -> bool:
        now = time.time()
        self._prune(now)
        if sig in self._d:
            return False
        if len(self._d) >= self.cap:
            return False
        self._d[sig] = now + self.ttl_s
        return True


_seen = _Seen()


def signing_target(domain: bytes, payload: dict, timestamp: int) -> bytes:
    return digest(domain, {"payload": payload, "timestamp": timestamp})


def verify_signed(req: SignedRequest, domain: bytes, *, check_replay: bool = True) -> Verified:
    now = time.time_ns()
    if abs(now - req.timestamp) > MAX_SKEW_NS:
        raise HTTPException(400, "signature timestamp is outside the ±10 minute window")
    try:
        account = derive_address(req.pub_key)
        verify_hex_signature(req.pub_key, req.signature, signing_target(domain, req.payload, req.timestamp))
    except KeyError_ as e:
        raise HTTPException(401, f"bad signature: {e}") from e
    if check_replay and not _seen.check_and_add(req.signature.lower()):
        raise HTTPException(409, "this signature has already been used")
    return Verified(account=account, pub_key=req.pub_key.lower(), payload=req.payload, timestamp=req.timestamp,
                    signature=req.signature.lower())


def require_seat(v: Verified, cfg: Config, right: str | None = None, members_only: bool = False) -> Verified:
    seat = cfg.seat_by_key(v.pub_key)
    if seat is None:
        raise HTTPException(403, "this key does not hold a seat")
    if members_only and not seat.is_member:
        raise HTTPException(403, "this action is reserved to members")
    if right and not seat.can(right):
        raise HTTPException(403, f"seat {seat.id} does not hold the right {right!r}")
    v.seat = seat
    return v
