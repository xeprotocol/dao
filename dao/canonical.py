"""Canonical JSON and domain-separated digests for everything the DAO signs or hashes itself.

These are DAO conventions, not XE protocol conventions. The protocol's own formats live in `xe/`.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

# Domain tags. Each kind of signed payload gets its own tag so a signature can never be replayed
# as a different kind of thing.
DOMAIN_EVENT = b"xe-dao/event/v1\x00"      # rows written before the v2 envelope; `events.v` says which
DOMAIN_EVENT_V2 = b"xe-dao/event/v2\x00"   # adds public and ref to the hashed body
DOMAIN_PROPOSAL = b"xe-dao/proposal/v1\x00"
DOMAIN_VOTE = b"xe-dao/vote/v1\x00"
DOMAIN_MEMBER_ACTION = b"xe-dao/member-action/v1\x00"
DOMAIN_RESOLUTION = b"xe-dao/resolution/v1\x00"
DOMAIN_OPS_APPROVAL = b"xe-dao/ops-approval/v1\x00"
DOMAIN_INBOX_HTTP = b"xe-dao/inbox/v1\x00"


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def digest(domain: bytes, value: Any) -> bytes:
    """sha256(domain || canonical_json(value)); 32 bytes. This is what gets signed."""
    return hashlib.sha256(domain + canonical_json(value)).digest()


def digest_hex(domain: bytes, value: Any) -> str:
    return digest(domain, value).hex()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
