"""State-chain blocks: the governance chain every node replays (statechain/encoding.go, crypto.go).

canonical = index u64 || prev_hash[32] || num_ops u32 || ops || timestamp u64
  op      = action byte (set=0x01, delete=0x02) || key_len u16 || key || value_len u32 || value bytes
            (delete writes a zero u32 instead of a value)
hash      = sha256(canonical)         -- no network id, unlike account blocks
signature = ed25519(hash_bytes) by a key in sys.dao_keyset (or sys.oracle for oracle-prefixed ops)

The value bytes are the JSON exactly as they appear on the wire (Go json.RawMessage), so the
DAO always emits compact JSON with no whitespace and escapes <, >, & the way Go's encoder does,
so that what we hash is what every node re-hashes after re-marshalling.
"""

from __future__ import annotations

import hashlib
import json
import re
import struct
from dataclasses import dataclass, field
from typing import Any

from .keys import KeyPair, verify_hex_signature

ACTION_SET = "set"
ACTION_DELETE = "delete"
ACTION_BYTES = {ACTION_SET: 0x01, ACTION_DELETE: 0x02}

MAX_KEY_LENGTH = 128
MAX_VALUE_SIZE = 65536
MAX_BLOCK_SIZE = 262144
MAX_SIGNATURES = 16       # the most keys a DAO keyset may hold (dao.services.sessions.MAX_KEYSET)
MIN_DAO_THRESHOLD = 2
KEY_RE = re.compile(r"^[a-z0-9_.-]+$")
ZERO_HASH = "0" * 64


class StateChainError(ValueError):
    pass


def compact_json(value: Any) -> str:
    """Compact JSON matching Go's encoder output for RawMessage: no spaces, HTML-escaped.

    Go's encoder escapes `<`, `>`, `&` and the line separators U+2028 and U+2029 inside strings; the node
    re-marshals op values on gossip and sync, so a value that differs from this form hashes one way on the
    submitting node and another on every peer (XE-0465). This is the one form every op value takes."""
    try:
        s = json.dumps(value, separators=(",", ":"), ensure_ascii=False, sort_keys=False, allow_nan=False)
    except ValueError as e:   # NaN and the infinities: Python would write `Infinity`, Go's json.Valid refuses it (XE-1919)
        raise StateChainError("value is not JSON: non-finite number") from e
    return (s.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
             .replace("\u2028", "\\u2028").replace("\u2029", "\\u2029"))


def _non_finite(name: str) -> Any:
    raise StateChainError(f"value is not JSON: {name}")


def _finite_float(text: str) -> float:
    f = float(text)
    if f != f or f in (float("inf"), float("-inf")):
        raise StateChainError(f"value is not JSON: {text} is not a finite number")
    return f


def strict_loads(text: str) -> Any:
    """json.loads as Go reads it: `NaN`, `Infinity` and `-Infinity` are not JSON, and neither is a number
    too large to be finite (`1e400`), which Python's parser would otherwise read as infinity (XE-1919)."""
    return json.loads(text, parse_constant=_non_finite, parse_float=_finite_float)


def canonical_value(raw: Any) -> str:
    """The compact text for an op value given either as JSON text or as a parsed object."""
    if isinstance(raw, str) and _looks_like_json(raw):
        raw = strict_loads(raw)
    return compact_json(raw)


@dataclass
class StateOp:
    action: str
    key: str
    value: str | None = None  # raw JSON text for set; None for delete

    @classmethod
    def set(cls, key: str, value: Any) -> "StateOp":
        return cls(ACTION_SET, key, compact_json(value))

    @classmethod
    def delete(cls, key: str) -> "StateOp":
        return cls(ACTION_DELETE, key, None)

    @classmethod
    def from_json(cls, d: dict[str, Any]) -> "StateOp":
        # A value given as JSON text is parsed and re-compacted like any other, never kept as typed: pretty
        # printing or a bare `<` in the text would otherwise be hashed here and compacted by the node (XE-0569).
        value = canonical_value(d.get("value")) if d["action"] == ACTION_SET else None
        return cls(d["action"], d["key"], value)

    def to_json(self) -> dict[str, Any]:
        d: dict[str, Any] = {"action": self.action, "key": self.key}
        if self.action == ACTION_SET and self.value is not None:
            d["value"] = strict_loads(self.value)
        return d

    def validate(self) -> None:
        if self.action not in ACTION_BYTES:
            raise StateChainError(f"unknown action {self.action!r}")
        if not (1 <= len(self.key) <= MAX_KEY_LENGTH) or not KEY_RE.fullmatch(self.key):   # RE2 `$` is end-of-text (XE-1504)
            raise StateChainError(f"invalid key {self.key!r}")
        if self.action == ACTION_SET:
            if not self.value:
                raise StateChainError("set op requires a value")
            raw = self.value.encode("utf-8")
            if len(raw) > MAX_VALUE_SIZE:
                raise StateChainError("value too large")
            try:
                parsed = strict_loads(self.value)
            except json.JSONDecodeError as e:
                raise StateChainError("value is not valid JSON") from e
            if self.value != compact_json(parsed):
                raise StateChainError("value is not in compact form; build ops with StateOp.set or from_json")
        elif self.key.startswith("sys."):
            raise StateChainError("sys.* keys cannot be deleted")


def _looks_like_json(s: str) -> bool:
    try:
        strict_loads(s)
        return True
    except (json.JSONDecodeError, TypeError):
        return False


def check_ops_fit(ops: list["StateOp"]) -> None:
    """The node bounds the whole block (MaxBlockSize), not only each op. Ops that pass one by one can still
    make a block no node accepts, and the harness only finds out at build time, after the vote and the
    resolution (XE-1917). This asks the question at intake, on the largest block these ops could become:
    the widest index and timestamp, a full set of signatures."""
    for op in ops:
        op.validate()
    widest = StateBlock(index=2**63 - 1, prev_hash="f" * 64, ops=list(ops), timestamp=2**63 - 1,
                        signatures=[{"public_key": "f" * 64, "signature": "f" * 128}] * MAX_SIGNATURES, hash="f" * 64)
    if len(widest.to_wire().encode("utf-8")) > MAX_BLOCK_SIZE:
        raise StateChainError(f"ops exceed MaxBlockSize ({MAX_BLOCK_SIZE} bytes) once in a block")


@dataclass
class StateBlock:
    index: int
    prev_hash: str
    ops: list[StateOp]
    timestamp: int
    signatures: list[dict] = field(default_factory=list)  # {"public_key","signature"}
    hash: str = ""

    @classmethod
    def from_json(cls, d: dict[str, Any]) -> "StateBlock":
        return cls(
            index=int(d["index"]),
            prev_hash=d["prev_hash"],
            ops=[_op_from_wire(o) for o in d.get("ops", [])],
            timestamp=int(d["timestamp"]),
            signatures=list(d.get("signatures") or []),
            hash=d.get("hash", ""),
        )

    def to_json(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "prev_hash": self.prev_hash,
            "ops": [o.to_json() for o in self.ops],
            "signatures": self.signatures,
            "hash": self.hash,
            "timestamp": self.timestamp,
        }

    def to_wire(self) -> str:
        """JSON body for POST /statechain/blocks, with op values spliced in as their exact bytes."""
        parts = []
        for o in self.ops:
            if o.action == ACTION_SET:
                parts.append(f'{{"action":"set","key":{json.dumps(o.key)},"value":{o.value}}}')
            else:
                parts.append(f'{{"action":"delete","key":{json.dumps(o.key)}}}')
        ops = "[" + ",".join(parts) + "]"
        sigs = json.dumps(self.signatures, separators=(",", ":"))
        return (
            f'{{"index":{self.index},"prev_hash":{json.dumps(self.prev_hash)},"ops":{ops},'
            f'"signatures":{sigs},"hash":{json.dumps(self.hash)},"timestamp":{self.timestamp}}}'
        )


def _op_from_wire(o: dict[str, Any]) -> StateOp:
    """When a block comes back from a node, re-serialise values compactly. Go compacts RawMessage
    on output, so the node's wire bytes are compact JSON; json.loads/compact_json round-trips them
    only if key order is preserved, which Python dicts do."""
    if o["action"] == ACTION_SET:
        return StateOp(ACTION_SET, o["key"], compact_json(o["value"]))
    return StateOp(ACTION_DELETE, o["key"], None)


def marshal_state_canonical(b: StateBlock) -> bytes:
    buf = bytearray()
    buf += struct.pack(">Q", b.index)
    try:
        prev = bytes.fromhex(b.prev_hash)
    except ValueError as e:
        raise StateChainError("invalid prev_hash hex") from e
    if len(prev) != 32:
        raise StateChainError("prev_hash must be 32 bytes")
    buf += prev
    buf += struct.pack(">I", len(b.ops))
    for op in b.ops:
        if op.action not in ACTION_BYTES:
            raise StateChainError(f"unknown action {op.action!r}")
        buf.append(ACTION_BYTES[op.action])
        key = op.key.encode("utf-8")
        buf += struct.pack(">H", len(key)) + key
        if op.action == ACTION_SET:
            val = (op.value or "").encode("utf-8")
            buf += struct.pack(">I", len(val)) + val
        else:
            buf += b"\x00\x00\x00\x00"
    buf += struct.pack(">Q", b.timestamp & 0xFFFFFFFFFFFFFFFF)
    return bytes(buf)


def hash_state_block(b: StateBlock) -> str:
    return hashlib.sha256(marshal_state_canonical(b)).hexdigest()


def sign_state_block_hash(block_hash: str, kp: KeyPair) -> dict:
    return {"public_key": kp.pub_key_hex, "signature": kp.sign_hex(bytes.fromhex(block_hash))}


def verify_state_signature(block_hash: str, sig: dict) -> None:
    verify_hex_signature(sig["public_key"], sig["signature"], bytes.fromhex(block_hash))


def validate_keyset(value: dict) -> None:
    keys = value.get("keys") or []
    thr = int(value.get("threshold", 0))
    if not keys:
        raise StateChainError("keyset needs at least one key")
    if len(set(keys)) != len(keys):
        raise StateChainError("duplicate keys in keyset")
    for k in keys:
        if len(k) != 64:
            raise StateChainError("keyset key must be 64 hex chars")
        bytes.fromhex(k)
    if thr < MIN_DAO_THRESHOLD:
        raise StateChainError(f"threshold must be >= {MIN_DAO_THRESHOLD}")
    if thr > len(keys):
        raise StateChainError("threshold exceeds number of keys")


def build_block(tip: dict | None, ops: list[StateOp], timestamp_ns: int) -> StateBlock:
    """Assemble an unsigned block on top of `tip` (a node's /statechain/tip JSON)."""
    for op in ops:
        op.validate()
    if tip is None:
        index, prev = 0, ZERO_HASH
        prev_ts = 0
    else:
        index, prev = int(tip["index"]) + 1, tip["hash"]
        prev_ts = int(tip["timestamp"])
    ts = max(timestamp_ns, prev_ts)
    b = StateBlock(index=index, prev_hash=prev, ops=ops, timestamp=ts)
    b.hash = hash_state_block(b)
    if len(b.to_wire().encode("utf-8")) > MAX_BLOCK_SIZE:
        raise StateChainError("block exceeds MaxBlockSize")
    return b
