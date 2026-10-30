"""Signed requests. Nobody logs in; people sign.

Every write from a human (member, officer, or the public) is a JSON body of the form

    {"payload": {...}, "timestamp": <ns>, "pub_key": <hex>, "signature": <hex>}

where signature = ed25519 over sha256(domain || canonical_json({"payload": payload, "timestamp": timestamp}))
and the account is derived from pub_key. The domain is fixed per endpoint so a vote signature can
never be replayed as a resolution approval. Timestamps must be within ±10 minutes, and a signature is
accepted once: it is written to `seen_signatures` in the request's own transaction, so the claim lands
with the write it authorised and survives a restart (XE-0033). Rows older than the skew window are
purged by the worker; a signature that old is refused by the timestamp check anyway.
"""

from __future__ import annotations

import hashlib
import os
import struct
import time
from dataclasses import dataclass
from typing import Any

from fastapi import HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import delete
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from xe.keys import KeyError_, derive_address, verify_hex_signature

from .canonical import digest
from .config import Config, HumanSeat
from .models import SeenSignature

MAX_SKEW_NS = 10 * 60 * 1_000_000_000


class SignedRequest(BaseModel):
    payload: dict[str, Any] = Field(default_factory=dict)
    timestamp: int
    pub_key: str
    signature: str
    pow_nonce: int | None = None   # required on routes that cost the sender something (POST /v1/inbox)


@dataclass
class Verified:
    account: str
    pub_key: str
    payload: dict
    timestamp: int
    signature: str
    digest: bytes = b""
    pow_nonce: int | None = None
    seat: HumanSeat | None = None

    @property
    def actor(self) -> str:
        return f"seat:{self.seat.id}" if self.seat else f"account:{self.account}"


def signing_target(domain: bytes, payload: dict, timestamp: int) -> bytes:
    return digest(domain, {"payload": payload, "timestamp": timestamp})


def verify_signed(req: SignedRequest, domain: bytes) -> Verified:
    """Check the window and the signature. Does not claim the signature; see `claim_signature`."""
    now = time.time_ns()
    if abs(now - req.timestamp) > MAX_SKEW_NS:
        raise HTTPException(400, "signature timestamp is outside the ±10 minute window")
    target = signing_target(domain, req.payload, req.timestamp)
    try:
        account = derive_address(req.pub_key)
        verify_hex_signature(req.pub_key, req.signature, target)
    except KeyError_ as e:
        raise HTTPException(401, f"bad signature: {e}") from e
    return Verified(account=account, pub_key=req.pub_key.lower(), payload=req.payload, timestamp=req.timestamp,
                    signature=req.signature.lower(), digest=target, pow_nonce=req.pow_nonce)


# ---- proof of work on signed requests (XE-0032) ------------------------------------------------
#
# Same shape as chat PoW (nonce_LE8 || target, first 8 bytes read big-endian, valid when >= difficulty),
# with SHA-256 in place of BLAKE2b so a browser can compute it with WebCrypto alone. The target is the
# signing digest, so the work is bound to this exact request and cannot be reused. The difficulty is the
# one the node advertises for chat, so an HTTP message costs the sender what a chat message would.

def http_pow_hash(nonce: int, target: bytes) -> int:
    h = hashlib.sha256(struct.pack("<Q", nonce & 0xFFFFFFFFFFFFFFFF) + target).digest()
    return struct.unpack(">Q", h[:8])[0]


def validate_http_pow(target: bytes, nonce: int, difficulty: int) -> bool:
    return difficulty == 0 or http_pow_hash(nonce, target) >= difficulty


def compute_http_pow(target: bytes, difficulty: int) -> int:
    """Brute force; ~2^18 hashes at the chat difficulty. For CLI clients and tests."""
    if difficulty == 0:
        return 0
    nonce = struct.unpack("<Q", os.urandom(8))[0]
    while http_pow_hash(nonce, target) < difficulty:
        nonce = (nonce + 1) & 0xFFFFFFFFFFFFFFFF
    return nonce


def require_pow(v: Verified, difficulty: int) -> None:
    if difficulty == 0:
        return
    if v.pow_nonce is None:
        raise HTTPException(400, "pow_nonce is required: sha256(nonce_le8 || signing_digest) first 8 bytes "
                                 f"big-endian must be >= 0x{difficulty:016x}")
    if not validate_http_pow(v.digest, v.pow_nonce, difficulty):
        raise HTTPException(400, "pow_nonce does not meet the required difficulty")


async def claim_signature(db: AsyncSession, v: Verified) -> None:
    """Record the signature as used, inside the caller's transaction. 409 if it was used before.

    The primary key does the work: two concurrent requests with the same signature cannot both insert,
    and the row is only durable if the write it authorised commits too.
    """
    res = await db.execute(
        pg_insert(SeenSignature).values(sig=v.signature, timestamp=v.timestamp, account=v.account)
        .on_conflict_do_nothing(index_elements=["sig"])
    )
    if res.rowcount == 0:
        raise HTTPException(409, "this signature has already been used")


async def verify_and_claim(db: AsyncSession, req: SignedRequest, domain: bytes) -> Verified:
    v = verify_signed(req, domain)
    await claim_signature(db, v)
    return v


async def purge_seen_signatures(db: AsyncSession) -> int:
    """Drop claims older than the acceptance window; they can never be presented again."""
    cutoff = time.time_ns() - 2 * MAX_SKEW_NS
    res = await db.execute(delete(SeenSignature).where(SeenSignature.timestamp < cutoff))
    return res.rowcount or 0


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
