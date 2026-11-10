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
    def from_json(cls, d: Any) -> "Envelope":
        """An envelope from JSON a node served. Shape only: every text field a string no longer than the
        longest honest one, the two numbers integers in range. Whether it is authentic is `verify_envelope`'s
        question; this one is whether it is an envelope at all, and anything that is not raises `ChatError`
        and nothing else, so a reader can skip the one item and keep the rest (XE-2209)."""
        if not isinstance(d, dict):
            raise ChatError("envelope is not an object")
        text = {}
        for name, key, longest in (("id", "id", 64), ("from_", "from", 64), ("pub_key", "pub_key", 64), ("to", "to", 64),
                                   ("signature", "signature", 128)):
            v = d.get(key)
            v = "" if v is None else v
            if not isinstance(v, str) or len(v) > longest:
                raise ChatError(f"envelope {key} is not a string of at most {longest} characters")
            text[name] = v
        message = d.get("message")
        message = "" if message is None else message
        if not isinstance(message, str) or len(message) > MAX_MESSAGE_BYTES:   # characters; bytes are checked on verify
            raise ChatError("envelope message is not a string, or is too long")
        for key, v in (*text.items(), ("message", message)):
            try:
                v.encode("utf-8")
            except UnicodeEncodeError as e:   # an unpaired surrogate: not text, cannot be hashed or stored
                raise ChatError(f"envelope {key} is not text") from e
            if "\x00" in v:
                raise ChatError(f"envelope {key} carries a NUL character")   # no text column takes one
        numbers = {}
        for key, limit in (("timestamp", 2**63), ("pow_nonce", 2**64)):
            v = d.get(key)
            v = 0 if v is None else v
            if isinstance(v, bool) or not isinstance(v, int) or not 0 <= v < limit:
                raise ChatError(f"envelope {key} is not an integer in range")
            numbers[key] = v
        return cls(message=message, **text, **numbers)


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
