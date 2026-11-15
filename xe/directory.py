"""Account directory registrations (directory/verify.go).

Registering says "this account is reachable for chat on node X". Registrations expire after the
node's TTL (30 minutes by default), so the DAO re-registers on a timer.

msg  = "xe/directory-registration/v1\\x00" || for f in [network_id, account, pub_key, node_peer, str(timestamp)]: len u64 || f
sig  = ed25519(sha256(msg))
"""

from __future__ import annotations

import hashlib
import struct
import time
from dataclasses import dataclass, asdict
from typing import Any

from .keys import KeyPair, exact_uint, verify_hex_signature, verify_payload_key

DOMAIN_TAG = b"xe/directory-registration/v1\x00"


class DirectoryError(ValueError):
    pass


def canonical_bytes(network_id: str, account: str, pub_key: str, node_peer: str, timestamp: int) -> bytes:
    # The timestamp is signed as its decimal digits, so it is the integer the registration carries or
    # the encoder refuses: `str()` wrote True as "True" and 1.5 as "1.5", and signed that (XE-3020).
    ts = exact_uint(timestamp, 64, "registration timestamp", DirectoryError)
    buf = bytearray(DOMAIN_TAG)
    for f in (network_id, account, pub_key, node_peer, str(ts)):
        raw = f.encode("utf-8")
        buf += struct.pack(">Q", len(raw)) + raw
    return bytes(buf)


@dataclass
class Registration:
    account: str
    pub_key: str
    node_peer: str
    timestamp: int
    signature: str

    def to_json(self) -> dict[str, Any]:
        return asdict(self)


def new_registration(kp: KeyPair, network_id: str, node_peer: str, timestamp_ns: int | None = None) -> Registration:
    ts = timestamp_ns if timestamp_ns is not None else time.time_ns()
    if not node_peer or not ts:
        # what `verify_registration` below refuses, refused before it is signed (XE-3108)
        raise DirectoryError("missing node_peer" if not node_peer else "missing timestamp")
    msg = canonical_bytes(network_id, kp.address, kp.pub_key_hex, node_peer, ts)
    sig = kp.sign_hex(hashlib.sha256(msg).digest())
    return Registration(account=kp.address, pub_key=kp.pub_key_hex, node_peer=node_peer, timestamp=ts, signature=sig)


def verify_registration(reg: Registration, network_id: str) -> None:
    for name in ("account", "pub_key", "node_peer", "signature"):
        if not getattr(reg, name):
            raise DirectoryError(f"missing {name}")
    if not reg.timestamp:
        raise DirectoryError("missing timestamp")
    try:
        verify_payload_key(reg.pub_key, reg.account)
        msg = canonical_bytes(network_id, reg.account, reg.pub_key, reg.node_peer, reg.timestamp)
        verify_hex_signature(reg.pub_key, reg.signature, hashlib.sha256(msg).digest())
    except ValueError as e:
        raise DirectoryError(str(e)) from e
