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


def _recompacted(d: dict) -> StateBlock:
    """A captured block with each value written out again compactly. That is the node's bytes only for
    values whose compact form has one spelling, which the captured ones do; it is not a way to read a
    block back in general, and the package no longer offers one (XE-10435)."""
    ops = [StateOp(o["action"], o["key"], compact_json(o["value"]) if o["action"] == "set" else None) for o in d.get("ops", [])]
    return StateBlock(index=int(d["index"]), prev_hash=d["prev_hash"], ops=ops, timestamp=int(d["timestamp"]),
                      signatures=list(d.get("signatures") or []), hash=d.get("hash", ""))


def test_statechain_oracle_block_hash(statechain):
    """Blocks the node itself marshals (oracle, DAO) carry compact value bytes; re-compacting the API
    output reproduces them exactly."""
    d = statechain["oracle"]
    blk = _recompacted(d)
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
    compact = _recompacted(d)
    assert hash_state_block(compact) != d["hash"], "if this starts matching, the node changed how it hashes genesis"
    ops = [StateOp(o["action"], o["key"], _pretty_nested(o["value"], 4, 3)) for o in d["ops"]]
    doc = StateBlock(index=d["index"], prev_hash=d["prev_hash"], ops=ops, timestamp=d["timestamp"])
    assert hash_state_block(doc) == d["hash"]
    for sig in d.get("signatures", []):
        verify_state_signature(d["hash"], sig)


def test_statechain_dao_blocks_if_any(statechain):
    for d in statechain.get("dao", []):
        assert hash_state_block(_recompacted(d)) == d["hash"]


def test_a_served_block_is_not_rehashed_from_a_parsed_copy_of_its_values():
    """XE-10435: values that parse and do not write out as they were. A block holding one hashes over
    the bytes it holds; a copy re-serialised from the parsed value hashes to something else, which is why
    nothing in the package reads a block back that way."""
    import json

    import xe.statechain as sc
    assert not hasattr(StateBlock, "from_json") and not hasattr(sc, "_op_from_wire")
    for raw in ("1e2", "1.50", '"\\u0041"', '{"a":1,"a":2}', "-0.0e0"):
        held = StateBlock(index=1, prev_hash="0" * 64, ops=[StateOp("set", "dao.x", raw)], timestamp=1)
        again = StateBlock(index=1, prev_hash="0" * 64, ops=[StateOp("set", "dao.x", compact_json(json.loads(raw)))], timestamp=1)
        assert hash_state_block(held) != hash_state_block(again), raw
        assert f'"value":{raw}' in held.to_wire(), "what is sent is the text that was hashed"


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


# ---- XE-9785: hex the ledger lowercases is lowercased before it is hashed or compared ---------------------

def test_an_opening_block_hashes_the_same_however_its_pub_key_and_hash_are_spelled(blocks):
    from xe.encoding import verify_block_hash
    d = blocks["open"]
    assert d["pub_key"].upper() != d["pub_key"], "the vector's key has letters in it"
    shouted = Block.from_json({**d, "pub_key": d["pub_key"].upper()})
    assert hash_block(shouted, NETWORK_ID) == d["hash"]
    verify_open_block_signature(shouted, NETWORK_ID)
    verify_block_hash(Block.from_json({**d, "hash": d["hash"].upper()}), NETWORK_ID)
    # every other hex field of the canonical section is decoded, so its case never reached the hash
    for name in ("send", "receive"):
        b = blocks[name]
        loud = {k: (v.upper() if k in ("account", "previous", "destination", "source", "representative") and isinstance(v, str) and len(v) == 64 else v)
                for k, v in b.items()}
        assert hash_block(Block.from_json(loud), NETWORK_ID) == b["hash"], name
