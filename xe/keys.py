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


def is_hex(value: object, n: int | None = None) -> bool:
    """Hex digits and nothing else: exactly 2n of them when `n` is given, any whole number of bytes when it
    is not."""
    return (isinstance(value, str) and len(value) % 2 == 0 and bool(_HEX_RE.fullmatch(value))
            and (n is None or len(value) == 2 * n))


def exact_hex(value: object, n: int | None, what: str, err: type[Exception] = KeyError_) -> bytes:
    """The bytes of a hex string, and the one place this package and the harness decode one: nothing else
    calls `bytes.fromhex`. That function also accepts whitespace, which the node's `hex.DecodeString` does
    not, so a spaced spelling would pass here and be refused there, and one signature or hash would have
    two spellings (XE-0699, XE-3845, XE-3534). `err` is the calling module's own error."""
    if not is_hex(value, n):
        want = f"{2 * n} hex digits" if n is not None else "hex digits, a whole number of bytes"
        raise err(f"invalid {what}: want {want}")
    return bytes.fromhex(value)


def exact_uint(value: object, bits: int, what: str, err: type[Exception] = KeyError_) -> int:
    """An integer field as the integer it is, and the one test of it before an encoder packs it: an `int`
    from 0 to the most `bits` bits hold. Not a bool, a float or a string of digits, which Python would
    convert and the node's JSON decoder refuses; and not a number outside the field, which the encoders
    used to mask to its width. Either way the hash, and the signature over it, were of a number the
    object did not carry: 2^64 + 5 was signed as 5 and sent as written (XE-3020). `err` is the calling
    module's own error, as for `exact_hex`."""
    if type(value) is not int or not 0 <= value < (1 << bits):
        raise err(f"invalid {what}: want an integer from 0 to 2^{bits} - 1")
    return value


def _hex(value: str, n: int, what: str) -> bytes:
    return exact_hex(value, n, what)


def _hex32(value: str, what: str) -> bytes:
    return _hex(value, 32, what)


def is_valid_public_key(pub: bytes) -> bool:
    """A usable ed25519 public key: 32 bytes that decode to a canonical point on the main subgroup with no
    small order (libsodium's check). Without that binding only the length is checked."""
    if len(pub) != 32:
        return False
    try:
        from nacl.bindings import crypto_core_ed25519_is_valid_point, has_crypto_core_ed25519
    except ImportError:
        return True
    return crypto_core_ed25519_is_valid_point(pub) if has_crypto_core_ed25519 else True


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
