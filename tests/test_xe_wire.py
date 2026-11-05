"""Byte-exact checks of the xe package against blocks captured from the live testnet.
If any of these fail, nothing the harness signs would be accepted by a node."""

import hashlib

import pytest

from xe.chat import compute_envelope_id, new_envelope, verify_envelope
from xe.directory import new_registration, verify_registration
from xe.encoding import Block, hash_block, sign_block, verify_open_block_signature
from xe.keys import KeyPair, derive_address, verify_hex_signature
from xe.pow import TEST_DIFFICULTY, compute_pow, validate_pow
from xe.statechain import StateBlock, StateOp, build_block, compact_json, hash_state_block, verify_state_signature

from .conftest import NETWORK_ID


@pytest.mark.parametrize("name", ["send", "receive", "burn", "lease", "mint"])
def test_block_hash_matches_testnet(blocks, name):
    d = blocks[name]
    b = Block.from_json(d)
    assert hash_block(b, NETWORK_ID) == d["hash"], name


def test_open_block_pubkey_derives_account_and_signature_verifies(blocks):
    d = blocks["open"]
    assert derive_address(d["pub_key"]) == d["account"]
    verify_open_block_signature(Block.from_json(d), NETWORK_ID)


def test_pow_on_real_blocks(blocks):
    from xe.pow import DEFAULT_DIFFICULTY
    for name in ("send", "receive", "burn"):
        d = blocks[name]
        assert validate_pow(bytes.fromhex(d["hash"]), d["pow_nonce"], DEFAULT_DIFFICULTY), name


def test_sign_block_roundtrip():
    kp = KeyPair.generate()
    b = Block(type="send", account=kp.address, previous="0" * 64, balance=5, timestamp=1, asset="XE",
              destination="ab" * 32, amount=5)
    sign_block(b, kp, NETWORK_ID)
    verify_hex_signature(kp.pub_key_hex, b.signature, bytes.fromhex(b.hash))
    b.pow_nonce = compute_pow(bytes.fromhex(b.hash), TEST_DIFFICULTY)
    assert validate_pow(bytes.fromhex(b.hash), b.pow_nonce, TEST_DIFFICULTY)


def test_statechain_oracle_block_hash(statechain):
    """Blocks the node itself marshals (oracle, DAO) carry compact value bytes; re-compacting the API
    output reproduces them exactly."""
    d = statechain["oracle"]
    blk = StateBlock.from_json(d)
    assert hash_state_block(blk) == d["hash"]
    for sig in d["signatures"]:
        verify_state_signature(d["hash"], sig)


def _pretty_nested(value, indent: int, depth: int) -> str:
    """A JSON value as it appears inside a pretty-printed document at nesting `depth`: first line
    unindented (it follows `"value": `), continuation lines carry the enclosing indentation."""
    import json
    lines = json.dumps(value, indent=indent, ensure_ascii=False).split("\n")
    pad = " " * (indent * depth)
    return lines[0] + "".join("\n" + pad + ln for ln in lines[1:])


def test_statechain_genesis_hash_is_over_document_bytes(statechain):
    """Finding: the node hashes op values as the exact bytes in the genesis document (json.RawMessage
    preserves whitespace), and genesis.json is pretty-printed with 4-space indent, values at depth 3.
    The API serves the values compacted, so genesis cannot be re-hashed from API output alone. Our
    canonical encoding is right; the value bytes must be the document's."""
    d = statechain["genesis"]
    compact = StateBlock.from_json(d)
    assert hash_state_block(compact) != d["hash"], "if this starts matching, the node changed how it hashes genesis"
    ops = [StateOp(o["action"], o["key"], _pretty_nested(o["value"], 4, 3)) for o in d["ops"]]
    doc = StateBlock(index=d["index"], prev_hash=d["prev_hash"], ops=ops, timestamp=d["timestamp"])
    assert hash_state_block(doc) == d["hash"]
    for sig in d.get("signatures", []):
        verify_state_signature(d["hash"], sig)


def test_statechain_dao_blocks_if_any(statechain):
    for d in statechain.get("dao", []):
        assert hash_state_block(StateBlock.from_json(d)) == d["hash"]


def test_compact_json_matches_go_rawmessage():
    assert compact_json({"a": "<b>&", "n": 1}) == '{"a":"\\u003cb\\u003e\\u0026","n":1}'
    # XE-0465: Go also escapes the line separators; a raw one would hash one way here and another on peers
    assert compact_json({"a": "x\u2028y\u2029z"}) == '{"a":"x\\u2028y\\u2029z"}'


def test_op_values_given_as_text_are_canonicalised_and_validated():
    """XE-0569: a value handed in as a JSON string is parsed and re-compacted, never kept as typed."""
    from xe.statechain import StateChainError
    pretty = '{\n  "entity": "XE <DAO>",\n  "n": 1\n}'
    op = StateOp.from_json({"action": "set", "key": "dao.x", "value": pretty})
    assert op.value == '{"entity":"XE \\u003cDAO\\u003e","n":1}'
    op.validate()
    assert StateOp.from_json({"action": "set", "key": "dao.x", "value": "x\u2028"}).value == '"x\\u2028"'
    # an op built by hand with non-compact text is refused rather than hashed
    with pytest.raises(StateChainError, match="compact"):
        StateOp("set", "dao.x", pretty).validate()
    # and the canonical form is a fixed point, so re-normalising stored ops changes nothing
    assert StateOp.from_json({"action": "set", "key": "dao.x", "value": op.value}).value == op.value


def test_keyset_keys_sort_case_insensitively_like_the_ledger():
    """XE-0474: the node lowercases hex before sorting; the encoder must agree."""
    from xe.encoding import marshal_block_canonical
    lo = ["a" * 64, "b" * 64]
    mixed = ["B" * 64, "a" * 64]  # raw sort puts "B" first; the ledger's lowercase sort puts "a" first
    mk = lambda keys: Block(type="multisig_open", account="c" * 64, previous="0", balance=0, timestamp=1, asset="XE",
                            keyset={"keys": keys, "threshold": 1})
    assert marshal_block_canonical(mk(mixed)) == marshal_block_canonical(mk(lo))


def test_build_block_on_tip(statechain):
    tip = statechain["oracle"]
    op = StateOp.set("dao.registry", {"entity": "XE Network DAO LLC", "version": 1})
    blk = build_block(tip, [op], tip["timestamp"] - 5)  # earlier than tip: must clamp
    assert blk.index == tip["index"] + 1
    assert blk.prev_hash == tip["hash"]
    assert blk.timestamp >= tip["timestamp"]
    assert blk.hash == hash_state_block(blk)
    wire = blk.to_wire()
    assert '"value":{"entity":"XE Network DAO LLC","version":1}' in wire


def test_chat_envelope_roundtrip():
    kp = KeyPair.generate()
    env = new_envelope(kp, "cd" * 32, "hello", difficulty=TEST_DIFFICULTY)
    assert env.id == compute_envelope_id(env.from_, env.pub_key, env.to, env.message, env.timestamp)
    verify_envelope(env, difficulty=TEST_DIFFICULTY)


def test_directory_registration_roundtrip():
    kp = KeyPair.generate()
    reg = new_registration(kp, NETWORK_ID, "12D3KooWtest")
    verify_registration(reg, NETWORK_ID)
    with pytest.raises(Exception):
        verify_registration(reg, "othernet")


def test_address_domain():
    pub = bytes(32)
    assert derive_address(pub.hex()) == hashlib.sha256(b"xe/account/v1" + pub).hexdigest()
