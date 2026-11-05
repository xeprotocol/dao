"""ed25519 key pairs and XE account addresses.

An account address is sha256("xe/account/v1" || public_key), hex. The public key is
declared on an account's open block (`pub_key`) and bound into that block's hash via
the aux input. Everything that verifies a payload against an account checks that the
declared key derives the account (core.VerifyPayloadKey).
"""

from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass

from nacl.signing import SigningKey, VerifyKey
from nacl.exceptions import BadSignatureError

ACCOUNT_ADDRESS_DOMAIN = b"xe/account/v1"
_HEX_RE = re.compile(r"[0-9a-fA-F]+")


class KeyError_(ValueError):
    pass


def _hex(value: str, n: int, what: str) -> bytes:
    """Exactly 2n hex digits. `bytes.fromhex` alone also accepts whitespace, which the node's
    `hex.DecodeString` does not, and which would make two spellings of one signature (XE-0699)."""
    if not isinstance(value, str) or len(value) != 2 * n or not _HEX_RE.fullmatch(value):
        raise KeyError_(f"invalid {what}: want {2 * n} hex digits")
    return bytes.fromhex(value)


def _hex32(value: str, what: str) -> bytes:
    return _hex(value, 32, what)


def derive_address(pub_key_hex: str) -> str:
    pub = _hex32(pub_key_hex, "public key")
    return hashlib.sha256(ACCOUNT_ADDRESS_DOMAIN + pub).hexdigest()


@dataclass(frozen=True)
class KeyPair:
    seed: bytes

    def __post_init__(self) -> None:
        if len(self.seed) != 32:
            raise KeyError_("seed must be 32 bytes")

    @classmethod
    def generate(cls) -> "KeyPair":
        return cls(os.urandom(32))

    @classmethod
    def from_seed_hex(cls, seed_hex: str) -> "KeyPair":
        return cls(_hex32(seed_hex, "seed"))

    @property
    def signing_key(self) -> SigningKey:
        return SigningKey(self.seed)

    @property
    def public_key(self) -> bytes:
        return bytes(self.signing_key.verify_key)

    @property
    def pub_key_hex(self) -> str:
        return self.public_key.hex()

    @property
    def address(self) -> str:
        return hashlib.sha256(ACCOUNT_ADDRESS_DOMAIN + self.public_key).hexdigest()

    def sign(self, message: bytes) -> bytes:
        """Raw ed25519 signature (64 bytes) over `message`."""
        return self.signing_key.sign(message).signature

    def sign_hex(self, message: bytes) -> str:
        return self.sign(message).hex()


def verify_signature(pub_key: bytes, signature: bytes, message: bytes) -> bool:
    try:
        VerifyKey(pub_key).verify(message, signature)
        return True
    except (BadSignatureError, ValueError):
        return False


def verify_hex_signature(pub_key_hex: str, sig_hex: str, message: bytes) -> None:
    """Raises KeyError_ on any failure (mirrors core.VerifyHexSignature)."""
    pub = _hex32(pub_key_hex, "public key")
    sig = _hex(sig_hex, 64, "signature")
    if not verify_signature(pub, sig, message):
        raise KeyError_("signature verification failed")


def verify_payload_key(pub_key_hex: str, account: str) -> None:
    """Mirror of core.VerifyPayloadKey: the declared key must derive the account."""
    if not pub_key_hex:
        raise KeyError_("missing public key")
    if not account:
        raise KeyError_("missing account")
    if derive_address(pub_key_hex) != account:
        raise KeyError_(f"public key does not derive account {account}")
