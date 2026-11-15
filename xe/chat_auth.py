"""Ownership proof for reading an account's chat (api/chat_auth.go).

GET /chat/auth/challenge returns {"challenge": hex, "expires_at": ns}. The client signs
sha256("xe/chat-read-auth/v1\\x00" || challenge_bytes) and passes account, pub_key, challenge
and sig as query parameters. Challenges are bound to the issuing node, live 120 s, single use.
"""

from __future__ import annotations

import hashlib

from .keys import KeyPair, exact_hex

CHAT_AUTH_DOMAIN = b"xe/chat-read-auth/v1\x00"


def chat_sign_target(challenge_hex: str) -> bytes:
    return hashlib.sha256(CHAT_AUTH_DOMAIN + exact_hex(challenge_hex, None, "chat challenge")).digest()


def chat_read_proof(kp: KeyPair, challenge_hex: str) -> dict[str, str]:
    """Query parameters for an authenticated chat read."""
    return {
        "account": kp.address,
        "pub_key": kp.pub_key_hex,
        "challenge": challenge_hex,
        "sig": kp.sign_hex(chat_sign_target(challenge_hex)),
    }
