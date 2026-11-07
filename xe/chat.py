"""Signed chat envelopes (chat/envelope.go).

id        = sha256(field(from) || field(pub_key) || field(to) || field(message) || timestamp u64)
            where field(x) = len u32 || bytes
signature = ed25519(id_bytes)
pow       = nonce such that blake2b_8(nonce_LE || id_bytes) >= chat difficulty
Freshness window is ±5 minutes on the recipient node. Max message 8192 bytes.
"""

from __future__ import annotations

import hashlib
import struct
import time
from dataclasses import dataclass, asdict
from typing import Any

from .keys import KeyPair, verify_hex_signature, verify_payload_key
from .pow import CHAT_POW_DIFFICULTY, compute_pow, validate_pow

MAX_MESSAGE_BYTES = 8192
MAX_ENVELOPE_SKEW_NS = 5 * 60 * 1_000_000_000


class ChatError(ValueError):
    pass


def _field(data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + data


def envelope_canonical(from_: str, pub_key: str, to: str, message: str, timestamp: int) -> bytes:
    return (
        _field(from_.encode("utf-8"))
        + _field(pub_key.encode("utf-8"))
        + _field(to.encode("utf-8"))
        + _field(message.encode("utf-8"))
        + struct.pack(">Q", timestamp & 0xFFFFFFFFFFFFFFFF)
    )


def compute_envelope_id(from_: str, pub_key: str, to: str, message: str, timestamp: int) -> str:
    return hashlib.sha256(envelope_canonical(from_, pub_key, to, message, timestamp)).hexdigest()


@dataclass
class Envelope:
    id: str
    from_: str
    pub_key: str
    to: str
    message: str
    timestamp: int
    signature: str
    pow_nonce: int = 0

    def to_json(self) -> dict[str, Any]:
        d = asdict(self)
        d["from"] = d.pop("from_")
        return d

    @classmethod
    def from_json(cls, d: dict[str, Any]) -> "Envelope":
        return cls(
            id=d.get("id", ""),
            from_=d.get("from", ""),
            pub_key=d.get("pub_key", ""),
            to=d.get("to", ""),
            message=d.get("message", ""),
            timestamp=int(d.get("timestamp", 0)),
            signature=d.get("signature", ""),
            pow_nonce=int(d.get("pow_nonce", 0) or 0),
        )


def new_envelope(kp: KeyPair, to: str, message: str, difficulty: int = CHAT_POW_DIFFICULTY,
                 timestamp_ns: int | None = None, deadline_s: float | None = None) -> Envelope:
    if len(message.encode("utf-8")) > MAX_MESSAGE_BYTES:
        raise ChatError(f"message exceeds {MAX_MESSAGE_BYTES} bytes")
    ts = timestamp_ns if timestamp_ns is not None else time.time_ns()
    from_ = kp.address
    pub = kp.pub_key_hex
    eid = compute_envelope_id(from_, pub, to, message, ts)
    id_bytes = bytes.fromhex(eid)
    sig = kp.sign_hex(id_bytes)
    nonce = compute_pow(id_bytes, difficulty, deadline_s) if difficulty > 0 else 0
    return Envelope(id=eid, from_=from_, pub_key=pub, to=to, message=message,
                    timestamp=ts, signature=sig, pow_nonce=nonce)


def verify_envelope(env: Envelope, difficulty: int = CHAT_POW_DIFFICULTY, check_freshness: bool = True,
                    now_ns: int | None = None) -> None:
    if not all([env.from_, env.pub_key, env.to, env.message, env.timestamp, env.signature]):
        raise ChatError("missing required fields")
    if len(env.message.encode("utf-8")) > MAX_MESSAGE_BYTES:
        raise ChatError("message too long")
    if check_freshness:
        now = now_ns if now_ns is not None else time.time_ns()
        if abs(now - env.timestamp) > MAX_ENVELOPE_SKEW_NS:
            raise ChatError("envelope timestamp outside freshness window")
    expected = compute_envelope_id(env.from_, env.pub_key, env.to, env.message, env.timestamp)
    if env.id != expected:
        raise ChatError("envelope ID mismatch")
    id_bytes = bytes.fromhex(env.id)
    if difficulty > 0 and not validate_pow(id_bytes, env.pow_nonce, difficulty):
        raise ChatError("insufficient proof of work")
    try:
        verify_payload_key(env.pub_key, env.from_)
        verify_hex_signature(env.pub_key, env.signature, id_bytes)
    except ValueError as e:
        raise ChatError(str(e)) from e
