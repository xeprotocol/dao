"""Account-chain block canonical encoding, hashing and signing (core/encoding.go, core/crypto.go).

Only the block types the DAO builds or verifies are given full tails here: send, receive,
burn, mint, genesis, multisig_open/update, lease_cancel/force_settle. Lease-family
blocks with attestations are decoded for hashing (aux input) but the DAO never builds them.

hash = sha256(network_id || canonical || aux)
  canonical: version 0x02, type byte, asset[8], account[32], previous[32], balance u64, ts u64, tail, representative[32], [memo]
  aux: for open blocks, len-prefixed "xe/block/pubkey/v1" and len-prefixed pub_key hex;
       for lease-family blocks, certificate hash and sorted attestations.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field, asdict
from typing import Any

from .keys import KeyPair, derive_address, verify_hex_signature

VERSION_BYTE = 0x02

TYPE_BYTES = {
    "send": 0x01,
    "receive": 0x02,
    "lease": 0x04,
    "lease_accept": 0x05,
    "lease_settle": 0x06,
    "genesis": 0x07,
    "multisig_open": 0x08,
    "multisig_update": 0x09,
    "lease_cancel": 0x0A,
    "burn": 0x0B,
    "lease_force_settle": 0x0C,
    "mint": 0x0D,
    "lease_renew": 0x0E,
}

AUX_TAG_ACCOUNT_PUBKEY = b"xe/block/pubkey/v1"
MAX_MEMO_BYTES = 64
LEASE_FAMILY = {"lease", "lease_accept", "lease_settle", "lease_force_settle", "lease_renew"}


class EncodingError(ValueError):
    pass


def _u64(v: int) -> bytes:
    return struct.pack(">Q", int(v) & 0xFFFFFFFFFFFFFFFF)


def _u32(v: int) -> bytes:
    return struct.pack(">I", int(v))


def _hex(value: str, what: str, size: int = 32) -> bytes:
    try:
        raw = bytes.fromhex(value)
    except ValueError as e:
        raise EncodingError(f"invalid {what} hex") from e
    if len(raw) != size:
        raise EncodingError(f"{what} must be {size} bytes, got {len(raw)}")
    return raw


def _len_prefixed(data: bytes) -> bytes:
    return _u64(len(data)) + data


def validate_memo(memo: str) -> None:
    if not memo:
        return
    raw = memo.encode("utf-8")
    if len(raw) > MAX_MEMO_BYTES:
        raise EncodingError(f"memo too long: {len(raw)} bytes (max {MAX_MEMO_BYTES})")
    for i, c in enumerate(raw):
        if c in (0x09, 0x0A):
            continue
        if c < 0x20 or c == 0x7F:
            raise EncodingError(f"memo contains disallowed control byte 0x{c:02x} at offset {i}")


@dataclass
class Block:
    type: str
    account: str
    previous: str
    balance: int
    timestamp: int
    asset: str
    representative: str = ""
    destination: str = ""
    amount: int = 0
    source: str = ""
    memo: str = ""
    keyset: dict | None = None  # {"keys": [...], "threshold": n} for multisig_open/update
    pub_key: str = ""
    signature: str = ""
    signatures: list[dict] = field(default_factory=list)
    hash: str = ""
    pow_nonce: int = 0
    # lease-family fields are only needed for hashing foreign blocks
    vcpus: int = 0
    memory_mb: int = 0
    disk_gb: int = 0
    duration: int = 0
    access_pub_key: str = ""
    locked_r: int = 0
    locked_payout_cap: int = 0
    locked_twap_milli: int = 0
    certificate_hash: str = ""
    attestations: list[dict] = field(default_factory=list)
    lease_min_duration_secs: int = 0
    lease_settle_grace_ns: int = 0
    lease_force_settle_gap_ns: int = 0
    lease_escrow_expiry_ns: int = 0
    lease_archive_gap_ns: int = 0
    max_attestation_skew_ns: int = 0

    @classmethod
    def from_json(cls, d: dict[str, Any]) -> "Block":
        known = {f for f in cls.__dataclass_fields__}
        kwargs = {k: v for k, v in d.items() if k in known}
        return cls(**kwargs)

    def to_json(self) -> dict[str, Any]:
        """Wire form: omit empty optional fields the way Go's omitempty does."""
        d = asdict(self)
        out: dict[str, Any] = {}
        always = {"type", "account", "previous", "balance", "timestamp", "asset", "hash"}
        for k, v in d.items():
            if k in always:
                out[k] = v
            elif v in ("", 0, None, [], {}):
                continue
            else:
                out[k] = v
        return out


def _has_genesis_timing(b: Block) -> bool:
    return any([
        b.lease_min_duration_secs, b.lease_settle_grace_ns, b.lease_force_settle_gap_ns,
        b.lease_escrow_expiry_ns, b.lease_archive_gap_ns, b.max_attestation_skew_ns,
    ])


def marshal_block_canonical(b: Block) -> bytes:
    if b.type not in TYPE_BYTES:
        raise EncodingError(f"unknown block type {b.type!r}")
    if b.memo and b.type not in ("send", "burn"):
        raise EncodingError(f"memo not allowed on {b.type} blocks")
    validate_memo(b.memo)
    asset = b.asset.encode("utf-8")
    if len(asset) > 8:
        raise EncodingError("asset too long")
    buf = bytearray()
    buf.append(VERSION_BYTE)
    buf.append(TYPE_BYTES[b.type])
    buf += asset.ljust(8, b"\x00")
    buf += _hex(b.account, "account")
    buf += bytes(32) if b.previous == "0" else _hex(b.previous, "previous")
    buf += _u64(b.balance)
    buf += _u64(b.timestamp)

    t = b.type
    if t == "send":
        buf += _hex(b.destination, "destination")
        buf += _u64(b.amount)
    elif t == "receive":
        buf += _hex(b.source, "source")
    elif t == "lease":
        buf += _hex(b.destination, "destination")
        buf += _u64(b.amount) + _u64(b.vcpus) + _u64(b.memory_mb) + _u64(b.disk_gb) + _u64(b.duration)
        buf += bytes(32) if not b.access_pub_key else _hex(b.access_pub_key, "access_pub_key")
    elif t == "genesis":
        pass
    elif t in ("multisig_open", "multisig_update"):
        if not b.keyset:
            raise EncodingError(f"{t} requires keyset")
        # The ledger lowercases hex before it sorts (normalizeBlockHex), so a mixed-case keyset must sort the
        # same way here or the hash differs from the node's (XE-0474). Other hex fields decode to the same
        # bytes whatever their case.
        keys = sorted(k.lower() for k in b.keyset["keys"])
        buf += _u32(b.keyset["threshold"]) + _u32(len(keys))
        for k in keys:
            buf += _hex(k, "keyset key")
    elif t in ("lease_cancel", "lease_force_settle"):
        buf += _hex(b.source, "source")
    elif t in ("lease_accept", "lease_settle"):
        buf += _hex(b.source, "source")
        buf += _u64(b.amount)
        if t == "lease_accept":
            buf += _u64(b.locked_r) + _u64(b.locked_payout_cap) + _u64(b.locked_twap_milli)
    elif t == "lease_renew":
        buf += _hex(b.source, "source")
        buf += _u64(b.amount) + _u64(b.duration)
        buf += _u64(b.locked_r) + _u64(b.locked_payout_cap) + _u64(b.locked_twap_milli)
    elif t in ("burn", "mint"):
        buf += _u64(b.amount)

    buf += bytes(32) if not b.representative else _hex(b.representative, "representative")

    if _has_genesis_timing(b):
        if t != "genesis":
            raise EncodingError("lease-timing fields only allowed on genesis")
        for v in (b.lease_min_duration_secs, b.lease_settle_grace_ns, b.lease_force_settle_gap_ns,
                  b.lease_escrow_expiry_ns, b.lease_archive_gap_ns, b.max_attestation_skew_ns):
            buf += _u64(v)

    if t in ("send", "burn"):
        memo = b.memo.encode("utf-8")
        buf.append(len(memo))
        buf += memo
    return bytes(buf)


def marshal_block_aux(b: Block) -> bytes:
    buf = bytearray()
    if b.pub_key:
        buf += _len_prefixed(AUX_TAG_ACCOUNT_PUBKEY)
        buf += _len_prefixed(b.pub_key.encode("ascii"))
    if b.type not in LEASE_FAMILY:
        return bytes(buf)
    buf += _len_prefixed(b.certificate_hash.encode("ascii"))
    atts = sorted(b.attestations, key=lambda a: a["public_key"])
    buf += _u64(len(atts))
    for a in atts:
        buf += _len_prefixed(a["public_key"].encode("ascii"))
        buf += _u64(a["timestamp"])
        buf += _len_prefixed(a["signature"].encode("ascii"))
    return bytes(buf)


def hash_block(b: Block, network_id: str) -> str:
    h = hashlib.sha256()
    h.update(network_id.encode("utf-8"))
    h.update(marshal_block_canonical(b))
    h.update(marshal_block_aux(b))
    return h.hexdigest()


def sign_block(b: Block, kp: KeyPair, network_id: str) -> Block:
    """Single-signer blocks. Declares pub_key on open blocks (previous == "0")."""
    if b.previous == "0" and not b.pub_key and not b.signatures and b.type not in ("multisig_open", "multisig_update"):
        b.pub_key = kp.pub_key_hex
    if b.type not in ("multisig_open", "multisig_update") and derive_address(kp.pub_key_hex) != b.account:
        raise EncodingError("signing key does not derive block account")
    b.hash = hash_block(b, network_id)
    b.signature = kp.sign_hex(bytes.fromhex(b.hash))
    return b


def verify_block_hash(b: Block, network_id: str) -> None:
    expected = hash_block(b, network_id)
    if b.hash != expected:
        raise EncodingError(f"hash mismatch: got {b.hash}, want {expected}")


def verify_open_block_signature(b: Block, network_id: str) -> None:
    """For open blocks the signer key is declared on the block itself."""
    verify_block_hash(b, network_id)
    if not b.pub_key:
        raise EncodingError("open block must declare pub_key")
    if derive_address(b.pub_key) != b.account:
        raise EncodingError("pub_key does not derive account address")
    verify_hex_signature(b.pub_key, b.signature, bytes.fromhex(b.hash))
