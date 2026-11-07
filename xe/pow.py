"""Anti-spam proof of work (core/pow.go).

result = blake2b_8(nonce_LE || hash_bytes), read as big-endian u64; valid if result >= difficulty.
Block PoW costs about a second of one core in Go; in pure Python expect several seconds,
so callers run it off the event loop. Chat PoW is ~2^18 attempts.
"""

from __future__ import annotations

import hashlib
import os
import re
import struct
import time

DEFAULT_DIFFICULTY = 0xFFFFF80000000000
CHAT_POW_DIFFICULTY = 0xFFFFC00000000000
TEST_DIFFICULTY = 0x0000000000000002

# A node-advertised difficulty is taken on trust only within a band around the harness default: no easier
# than the default (so a node saying "0" cannot switch the inbound gates off, XE-1195) and no harder than
# MAX_WORK_FACTOR times the default's expected work (so a node saying "near 2^64" cannot park the worker in
# a grind for years, XE-1188). Outside the band the default is used and the fact is logged. Every grind the
# harness runs unattended also carries a deadline, as a backstop for the band.
MAX_WORK_FACTOR = 64
WORKER_POW_DEADLINE_S = 120.0
_U64 = 1 << 64


def pow_hash(nonce: int, hash_bytes: bytes) -> int:
    h = hashlib.blake2b(digest_size=8)
    h.update(struct.pack("<Q", nonce & 0xFFFFFFFFFFFFFFFF))
    h.update(hash_bytes)
    return struct.unpack(">Q", h.digest())[0]


def validate_pow(hash_bytes: bytes, nonce: int, difficulty: int) -> bool:
    if difficulty == 0:
        return True
    return pow_hash(nonce, hash_bytes) >= difficulty


def compute_pow(hash_bytes: bytes, difficulty: int, deadline_s: float | None = None) -> int:
    """Brute force from a random start. Raises TimeoutError if deadline_s elapses."""
    if difficulty == 0:
        return 0
    nonce = struct.unpack("<Q", os.urandom(8))[0]
    started = time.monotonic()
    blake = hashlib.blake2b
    pack = struct.pack
    unpack = struct.unpack
    while True:
        h = blake(digest_size=8)
        h.update(pack("<Q", nonce & 0xFFFFFFFFFFFFFFFF))
        h.update(hash_bytes)
        if unpack(">Q", h.digest())[0] >= difficulty:
            return nonce & 0xFFFFFFFFFFFFFFFF
        nonce += 1
        if deadline_s is not None and (nonce & 0xFFFF) == 0 and time.monotonic() - started > deadline_s:
            raise TimeoutError("proof of work deadline exceeded")


_DIFFICULTY_RE = re.compile(r"[0-9a-fA-F]{1,16}")


def expected_work(difficulty: int) -> float:
    """Expected attempts for a threshold: 2^64 over the size of the passing range."""
    return _U64 / max(_U64 - difficulty, 1)


def parse_difficulty(hex_str: str | None, default: int) -> int:
    """Nodes advertise thresholds as hex strings in GET /node. Anything that is not 1-16 hex digits (a u64,
    as the node formats it) is malformed (XE-0775); a well-formed value outside the band around `default`
    (see above) is refused the same way. Either raises ValueError; the caller keeps the default."""
    if hex_str is None or hex_str == "":
        return default
    if not isinstance(hex_str, str) or not _DIFFICULTY_RE.fullmatch(hex_str):
        raise ValueError(f"malformed difficulty {hex_str!r}")
    value = int(hex_str, 16)
    if value < default:
        raise ValueError(f"difficulty {hex_str} is below the harness minimum {default:#018x}")
    if expected_work(value) > expected_work(default) * MAX_WORK_FACTOR:
        raise ValueError(f"difficulty {hex_str} asks more than {MAX_WORK_FACTOR}x the expected work of {default:#018x}")
    return value
