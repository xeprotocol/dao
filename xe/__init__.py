"""Minimal Python implementation of the XE protocol surfaces the DAO needs.

Ported from github.com/xeprotocol/xe (GPL-3.0): core/crypto.go, core/encoding.go,
core/pow.go, statechain/encoding.go, statechain/crypto.go, chat/envelope.go,
directory/verify.go, api/chat_auth.go. Every function here must stay byte-identical
to the Go node; tests/test_xe.py checks that against blocks fetched from testnet.
"""

from .keys import KeyPair, derive_address, verify_hex_signature, verify_payload_key
from .amounts import MICRO, from_micro
from .encoding import Block, hash_block, marshal_block_canonical, marshal_block_aux, sign_block
from .pow import DEFAULT_DIFFICULTY, CHAT_POW_DIFFICULTY, compute_pow, validate_pow
from .statechain import (
    StateBlock,
    StateOp,
    hash_state_block,
    marshal_state_canonical,
    sign_state_block_hash,
    verify_state_signature,
    compact_json,
)
from .chat import Envelope, compute_envelope_id, new_envelope, verify_envelope
from .directory import Registration, new_registration, verify_registration
from .chat_auth import chat_read_proof
from .client import XeClient, XeError

__all__ = [
    "KeyPair", "derive_address", "verify_hex_signature", "verify_payload_key",
    "MICRO", "from_micro",
    "Block", "hash_block", "marshal_block_canonical", "marshal_block_aux", "sign_block",
    "DEFAULT_DIFFICULTY", "CHAT_POW_DIFFICULTY", "compute_pow", "validate_pow",
    "StateBlock", "StateOp", "hash_state_block", "marshal_state_canonical",
    "sign_state_block_hash", "verify_state_signature", "compact_json",
    "Envelope", "compute_envelope_id", "new_envelope", "verify_envelope",
    "Registration", "new_registration", "verify_registration",
    "chat_read_proof",
    "XeClient", "XeError",
]
