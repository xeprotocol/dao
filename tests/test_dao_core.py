"""Harness-side primitives that need no database or node: canonical JSON, signed requests, signer
keyfile, tally rules, copy lint, registry value, JSONB-safe op normalisation."""

import json
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from xe.keys import KeyPair

from dao.auth import SignedRequest, verify_signed
from dao.canonical import DOMAIN_VOTE, canonical_json, digest
from dao.config import lint_public_copy, load_config
from dao.log import event_hash
from dao.services.portal import tally
from dao.services.sessions import normalise_ops, ops_digest
from dao.signer import Signer, SignerError

ROOT = Path(__file__).resolve().parents[1]


def test_canonical_json_is_sorted_compact_ascii():
    assert canonical_json({"b": 1, "a": "é"}) == b'{"a":"\\u00e9","b":1}'


def test_signed_request_verifies_and_is_domain_bound():
    kp = KeyPair.generate()
    payload = {"proposal": "ab" * 32, "choice": "for", "reason": ""}
    ts = time.time_ns()
    sig = kp.sign_hex(digest(DOMAIN_VOTE, {"payload": payload, "timestamp": ts}))
    req = SignedRequest(payload=payload, timestamp=ts, pub_key=kp.pub_key_hex, signature=sig)
    v = verify_signed(req, DOMAIN_VOTE)
    assert v.account == kp.address
    assert v.digest == digest(DOMAIN_VOTE, {"payload": payload, "timestamp": ts})
    # verification is pure: the replay claim lives in the database (test_log_db), so a second check passes here
    assert verify_signed(req, DOMAIN_VOTE).signature == sig.lower()
    # wrong domain fails
    from dao.canonical import DOMAIN_PROPOSAL
    with pytest.raises(HTTPException):
        verify_signed(SignedRequest(payload=payload, timestamp=ts, pub_key=kp.pub_key_hex, signature=sig), DOMAIN_PROPOSAL)


def test_http_pow_binds_to_digest_and_difficulty():
    from dao.auth import Verified, compute_http_pow, require_pow, validate_http_pow
    target = digest(DOMAIN_VOTE, {"payload": {"message": "hi"}, "timestamp": 1})
    easy = 0x0100000000000000  # ~1 in 256
    nonce = compute_http_pow(target, easy)
    assert validate_http_pow(target, nonce, easy)
    assert validate_http_pow(target, 0, 0)
    assert require_pow(Verified("a", "p", {}, 1, "s", digest=target, pow_nonce=nonce), easy) is None
    with pytest.raises(HTTPException) as e:
        require_pow(Verified("a", "p", {}, 1, "s", digest=target, pow_nonce=None), easy)
    assert e.value.status_code == 400 and "pow_nonce" in e.value.detail
    # the work is bound to the digest: the same nonce over different bytes almost never passes a hard target
    other = digest(DOMAIN_VOTE, {"payload": {"message": "ho"}, "timestamp": 1})
    hard = 0xFFFFFFFF00000000
    assert not validate_http_pow(other, nonce, hard) or not validate_http_pow(target, nonce + 1, hard)


def test_clean_text_rejects_control_characters_everywhere():
    from dao.text import clean_text, has_bad_control, scrub
    assert clean_text("  hello\nworld\t! ", "message", max_len=100) == "hello\nworld\t!"
    for bad in ("a\x00b", "a\x01b", "a\x1bb", "a\x7fb"):
        with pytest.raises(HTTPException) as e:
            clean_text(bad, "message", max_len=100)
        assert e.value.status_code == 400 and "message" in e.value.detail
        assert has_bad_control(bad)
    with pytest.raises(HTTPException):
        clean_text("", "title", max_len=10)
    assert clean_text("", "title", max_len=10, required=False) == ""
    with pytest.raises(HTTPException):
        clean_text("x" * 11, "title", max_len=10)
    with pytest.raises(HTTPException):
        clean_text(123, "title", max_len=10)
    assert scrub("a\x00b\nc") == "a\ufffdb\nc"


def test_clean_text_rejects_lone_surrogates_before_the_driver_sees_them():
    """XE-0878: a JSON `\\ud800` escape decodes to a lone surrogate, which is not UTF-8 and fails at asyncpg.
    It is refused with the same 400 as a control character, including on the byte-bounded path, whose own
    encode would otherwise raise first."""
    import json
    from dao.text import clean_text, has_bad_control, scrub
    s = json.loads('"a\\ud800b"')
    assert has_bad_control(s)
    for kwargs in ({}, {"max_bytes": 100}):
        with pytest.raises(HTTPException) as e:
            clean_text(s, "reason", max_len=100, **kwargs)
        assert e.value.status_code == 400 and "reason" in e.value.detail
    assert clean_text("emoji \U0001f600 and \u2028 pass", "message", max_len=100, max_bytes=100)
    assert scrub(s) == "a\ufffdb"
    scrub(s).encode("utf-8")


def test_rate_limit_buckets_refill_and_forget():
    from dao.ratelimit import Buckets, Limit
    b = Buckets(sweep_every_s=10)
    lim = Limit(per_minute=60, burst=2)
    assert b.take("k", lim, now=0.0) == 0.0
    assert b.take("k", lim, now=0.0) == 0.0
    wait = b.take("k", lim, now=0.0)
    assert 0 < wait <= 1.0
    assert b.take("k", lim, now=1.0) == 0.0        # one token back after a second
    assert b.take("other", lim, now=100.0) == 0.0  # sweep: the idle key is gone
    assert "k" not in b._b


def test_rate_limit_classes_are_separate_and_the_address_pays_once(monkeypatch):
    """XE-0478: inbox traffic from an address does not spend its votes, and a signed request costs the
    address one token, not two."""
    from dao import ratelimit
    from dao.ratelimit import INBOX, VOTE, Buckets, enforce_account, enforce_ip
    monkeypatch.setattr(ratelimit, "_buckets", Buckets())
    req = SimpleNamespace(client=SimpleNamespace(host="203.0.113.9"))
    for _ in range(INBOX.ip.burst):
        enforce_ip(req, INBOX)
    with pytest.raises(HTTPException):
        enforce_ip(req, INBOX)
    enforce_ip(req, VOTE)                                  # a different class, a different bucket
    enforce_account(VOTE, "a" * 64)
    assert ratelimit._buckets._b["ip:vote:203.0.113.9"][0] == VOTE.ip.burst - 1   # one token for the request


def test_signed_request_rejects_stale_timestamp():
    kp = KeyPair.generate()
    ts = time.time_ns() - 3600 * 1_000_000_000
    sig = kp.sign_hex(digest(DOMAIN_VOTE, {"payload": {}, "timestamp": ts}))
    with pytest.raises(HTTPException) as e:
        verify_signed(SignedRequest(payload={}, timestamp=ts, pub_key=kp.pub_key_hex, signature=sig), DOMAIN_VOTE)
    assert e.value.status_code == 400


def test_signer_keyfile_roundtrip_and_scopes(tmp_path):
    p = tmp_path / "signer.json"
    infos = Signer.init_keyfile(p, "correct horse battery staple")
    assert set(infos) == {"harness", "dao", "fee"}
    s = Signer.load(p, "correct horse battery staple")
    assert s.address("dao") == infos["dao"].address
    s.sign("harness", "event.sign", b"x")
    with pytest.raises(SignerError):
        s.sign("harness", "block.burn", b"x")
    with pytest.raises(SignerError):
        Signer.load(p, "wrong passphrase here")
    Signer.add_key(p, "correct horse battery staple", "agent:research")
    assert Signer.load(p, "correct horse battery staple").has("agent:research")


def test_mainnet_badge_needs_a_positive_match():
    from dao.context import NodeIdentity
    assert NodeIdentity(network_id="mainnet").badge == "mainnet"
    assert NodeIdentity(network_id="mainnet-0001").badge == "mainnet"
    for other in ("testnet-0005", "testnet", "devnet-0001", "mainnet2", "staging", ""):
        assert NodeIdentity(network_id=other).badge == "testnet", other


def test_event_hash_is_deterministic():
    a = event_hash(0, 1, "k", "harness", {"x": 1, "y": [1, 2]}, "0" * 64)
    b = event_hash(0, 1, "k", "harness", {"y": [1, 2], "x": 1}, "0" * 64)
    assert a == b and len(a) == 64


def test_normalise_ops_stores_exact_value_bytes():
    ops = normalise_ops([{"action": "set", "key": "dao.x", "value": {"b": 1, "a": "<"}}])
    assert ops[0]["value"] == '{"b":1,"a":"\\u003c"}'
    assert ops_digest(ops) == ops_digest(normalise_ops(ops))  # idempotent


def _vote(weight, choice, participating=True, is_agent=False):
    return SimpleNamespace(weight=weight, choice=choice, participating=participating, is_agent=is_agent)


def _proposal(quorum=20, cap=0.01):
    return SimpleNamespace(rules={"quorum_wallets": quorum, "pass_mark_fraction": 0.5, "agents": {"max_weight_share": cap}})


def test_tally_quorum_is_wallet_count_not_xe():
    votes = [_vote(10_000_000_000, "for")]  # one whale, 10k XE
    t = tally(_proposal(quorum=20), votes)
    assert not t["quorum_met"] and t["outcome"] == "no_quorum"
    votes = [_vote(1_000_000, "for") for _ in range(20)]
    t = tally(_proposal(quorum=20), votes)
    assert t["quorum_met"] and t["outcome"] == "passed"


def test_tally_agent_weight_is_capped_and_excluded_from_quorum():
    votes = [_vote(1_000_000, "against") for _ in range(19)] + [_vote(100_000_000, "for", participating=False, is_agent=True)]
    t = tally(_proposal(quorum=20), votes)
    assert t["participating_wallets"] == 19 and not t["quorum_met"]
    votes.append(_vote(1_000_000, "against"))
    t = tally(_proposal(quorum=20), votes)
    assert t["quorum_met"]
    # agents may count at most 1% of total cast: 20 XE human + 100 XE agent raw → cap ~1.2 XE
    assert t["weight"]["for"] <= int(0.01 * (20_000_000 + 100_000_000)) + 1
    assert t["outcome"] == "failed"


def test_abstain_not_counted_in_pass_mark():
    votes = [_vote(1_000_000, "abstain") for _ in range(20)] + [_vote(1, "for")]
    t = tally(_proposal(quorum=20), votes)
    assert t["quorum_met"] and t["outcome"] == "passed"


def test_config_loads_and_public_copy_is_clean():
    cfg = load_config(ROOT / "config")
    assert cfg.pinned_rules()["quorum_wallets"] == 20
    assert cfg.pinned_rules()["fee_micro_xe"] == 10_000_000
    assert lint_public_copy(cfg) == []
    assert lint_public_copy(cfg, ["Our members voted"]) != []


def test_every_agent_seat_has_a_prompt_and_hashes_are_published():
    cfg = load_config(ROOT / "config")
    assert "_preamble" in cfg.prompts
    for seat in cfg.agent_seats:
        assert seat.id in cfg.prompts, f"missing config/prompts/{seat.id}.md"
        assert len(cfg.prompt_hash(seat.id)) == 64
        assert f"prompts/{seat.id}.md" in cfg.hashes
    # the preamble carries the non-negotiables every seat must see
    pre = cfg.prompts["_preamble"].lower()
    for phrase in ("not self-executing", "never decide", "untrusted", "would_change_my_mind", "counter_argument"):
        assert phrase in pre, phrase
    # a prompt change changes the published hash
    assert cfg.prompt_hash("risk") != cfg.prompt_hash("legal")


def test_charter_keeps_its_legal_framing():
    """The Charter is served verbatim and hashed; these lines are what the wrapper depends on."""
    cfg = load_config(ROOT / "config")
    text = " ".join(cfg.charter_md.split())
    for must in (
        "## Standing", "## Statement of Intent on Human Dissociation", "## Amendment Rules",
        "natural-person control is permanent", "not self-executing", "confers no membership",
        "is not a member, officer, manager or agent-at-law", "Reserved matters under the Operating Agreement",
    ):
        assert must in text, must
    assert len(cfg.charter_hash) == 64


def test_seat_pages_resolve_and_summaries_pass_copy_lint():
    cfg = load_config(ROOT / "config")
    assert cfg.seat_page("legal-and-compliance")[1].id == "legal"
    assert cfg.seat_page("legal")[1].id == "legal"
    assert cfg.seat_page("orchestrator-backup")[1].id == "orchestrator-backup"
    assert cfg.seat_page("founder-a")[0] == "human"
    assert cfg.seat_page("nope") is None
    slugs = [a.slug for a in cfg.agent_seats]
    assert len(slugs) == len(set(slugs)), "agent role slugs must be unique"
    glossary = cfg.tool_scope_glossary
    for a in cfg.agent_seats:
        assert a.summary, f"{a.id} needs a summary in schedule_c.yaml"
        for sc in a.tool_scopes:
            assert sc in glossary, f"tool scope {sc} has no plain-language entry"
    # summaries and the glossary are public-register text
    assert lint_public_copy(cfg, [a.summary for a in cfg.agent_seats] + list(glossary.values())) == []


def test_registry_value_is_compact_and_small():
    from xe.statechain import compact_json
    from dao.services.records import registry_value
    cfg = load_config(ROOT / "config")
    ctx = SimpleNamespace(config=cfg, signer=Signer.empty())
    val = registry_value(ctx)
    raw = compact_json(val)
    assert len(raw.encode()) < 4096
    assert json.loads(raw)["entity"] == "XE Network DAO LLC"


# ---- vote weight: a receive dated before the snapshot whose send is dated after it does not count -----

H = 3600 * 1_000_000_000


class _Lattice:
    """Two wallets and the blocks between them, as a node would serve them."""

    def __init__(self, chains, blocks):
        self.chains, self.blocks, self.lookups = chains, blocks, 0

    async def full_chain(self, account):
        from xe.client import XeError
        if account not in self.chains:
            raise XeError(404, "no such account")
        return self.chains[account]

    async def block(self, h):
        from xe.client import XeError
        self.lookups += 1
        if h not in self.blocks:
            raise XeError(404, "no such block")
        return self.blocks[h]


async def test_snapshot_does_not_count_a_receive_whose_send_is_after_it():
    from dao.chainops import account_snapshot
    T = 100 * H
    a_recv = {"type": "receive", "asset": "XE", "balance": 1000, "timestamp": T - 10 * H, "hash": "a1", "source": "ext"}
    a_send = {"type": "send", "asset": "XE", "balance": 0, "timestamp": T + 30 * 60 * 10**9, "hash": "a2",
              "destination": "B", "amount": 1000}                                   # dated half an hour late
    b_recv = {"type": "receive", "asset": "XE", "balance": 1000, "timestamp": T - 60 * 10**9, "hash": "b1", "source": "a2"}
    chain = _Lattice({"A": [a_recv, a_send], "B": [b_recv]},
                     {"ext": {"timestamp": T - 11 * H}, "a2": a_send})
    a = await account_snapshot(chain, "A", T)
    b = await account_snapshot(chain, "B", T)
    assert a["balance"] == 1000                     # the send is dated after the snapshot, so A still holds it
    assert b["balance"] == 0 and b["excluded_receives"] == ["b1"] and b["exists"] is False
    # the same XE is not counted twice; and A's old receive was not looked up (outside the two-hour window)
    assert a["balance"] + b["balance"] == 1000 and chain.lookups == 1
    # once the send is dated at or before the snapshot, B's receive counts and A's balance is after the send
    a_send["timestamp"] = T - 2 * 60 * 10**9
    a = await account_snapshot(chain, "A", T)
    b = await account_snapshot(chain, "B", T)
    assert a["balance"] == 0 and b["balance"] == 1000 and b["exists"] is True
    # an account the node does not know
    assert (await account_snapshot(chain, "C", T))["exists"] is False


async def test_nothing_made_after_open_can_reach_the_snapshot():
    """XE-0352: a transfer dated early on both sides passes the causal check, so the snapshot sits an hour
    and a margin before the open, where no block made after the open can be dated."""
    from dao.chainops import SNAPSHOT_LEAD_NS, TIMESTAMP_WINDOW_NS, account_snapshot, snapshot_time
    opened = 100 * H
    snap_at = snapshot_time(opened)
    assert opened - snap_at == SNAPSHOT_LEAD_NS > TIMESTAMP_WINDOW_NS
    # A watches the proposal open, then funds a fresh wallet B, dating both blocks as early as a node allows
    made_at = opened + 60 * 10**9
    earliest = made_at - TIMESTAMP_WINDOW_NS
    a_recv = {"type": "receive", "asset": "XE", "balance": 1000, "timestamp": opened - 10 * H, "hash": "a1", "source": "ext"}
    a_send = {"type": "send", "asset": "XE", "balance": 0, "timestamp": earliest, "hash": "a2", "destination": "B", "amount": 1000}
    b_recv = {"type": "receive", "asset": "XE", "balance": 1000, "timestamp": earliest, "hash": "b1", "source": "a2"}
    chain = _Lattice({"A": [a_recv, a_send], "B": [b_recv]}, {"ext": {"timestamp": opened - 11 * H}, "a2": a_send})
    # at the open itself both blocks would count: B exists and A has moved its weight across
    assert (await account_snapshot(chain, "B", opened))["exists"] is True
    # at the snapshot the harness uses, neither block is visible: B does not exist and A still holds the XE
    a = await account_snapshot(chain, "A", snap_at)
    b = await account_snapshot(chain, "B", snap_at)
    assert b["exists"] is False and b["balance"] == 0
    assert a["exists"] is True and a["balance"] == 1000


def test_request_bodies_over_the_limit_are_refused_before_parsing():
    from fastapi.testclient import TestClient
    from dao.main import MAX_BODY_BYTES, BodyLimit
    from fastapi import FastAPI

    inner = FastAPI()

    @inner.post("/v1/x")
    async def x(body: dict):
        return {"n": len(body)}

    inner.add_middleware(BodyLimit)
    c = TestClient(inner)
    big = '{"a":"' + "x" * MAX_BODY_BYTES + '"}'
    assert c.post("/v1/x", content=big, headers={"content-type": "application/json"}).status_code == 413
    # the same without a content-length (chunked) is counted as it streams
    r = c.post("/v1/x", content=iter([big.encode()]), headers={"content-type": "application/json"})
    assert r.status_code == 413 and r.json()["error"] == "request body too large"
    assert c.post("/v1/x", json={"a": 1}).status_code == 200


def test_signature_and_key_hex_must_be_canonical():
    """XE-0699: `bytes.fromhex` would accept whitespace; the signature is the replay key, so only the exact
    128 (and 64) hex digits are a valid spelling, at the model and in the verifier."""
    from pydantic import ValidationError
    from xe.keys import KeyError_, verify_hex_signature
    kp = KeyPair.generate()
    payload = {"x": 1}
    ts = time.time_ns()
    sig = kp.sign_hex(digest(DOMAIN_VOTE, {"payload": payload, "timestamp": ts}))
    spaced = " ".join(sig[i:i + 2] for i in range(0, len(sig), 2))
    for bad_sig in (spaced, " " + sig, sig + "\n", sig[:-2]):
        with pytest.raises(ValidationError):
            SignedRequest(payload=payload, timestamp=ts, pub_key=kp.pub_key_hex, signature=bad_sig)
    with pytest.raises(ValidationError):
        SignedRequest(payload=payload, timestamp=ts, pub_key=kp.pub_key_hex[:2] + " " + kp.pub_key_hex[2:], signature=sig)
    target = digest(DOMAIN_VOTE, {"payload": payload, "timestamp": ts})
    verify_hex_signature(kp.pub_key_hex.upper(), sig, target)   # case is not canonical form; it is normalised later
    with pytest.raises(KeyError_):
        verify_hex_signature(kp.pub_key_hex, spaced, target)
    with pytest.raises(KeyError_):
        verify_hex_signature(" " + kp.pub_key_hex[1:], sig, target)


def test_node_difficulty_is_a_u64_hex_or_the_default():
    """XE-0775: the node's advertised difficulty is parsed strictly, and a lying node leaves the defaults."""
    import asyncio
    from xe.pow import parse_difficulty
    assert parse_difficulty("fffff80000000000", 7) == 0xFFFFF80000000000
    assert parse_difficulty("0", 7) == 0 and parse_difficulty(None, 7) == 7 and parse_difficulty("", 7) == 7
    for bad in ("zz", "-1", "+ff", "0x10", " ff", "f_f", "1" * 17, 12, True, [], {}):
        with pytest.raises(ValueError):
            parse_difficulty(bad, 7)

    from dao.context import Context
    for body in ({"pow_difficulty": "zz", "chat_pow_difficulty": "-1"}, ["not", "a", "dict"], "nope", {"pow_difficulty": 5}):
        ctx = Context.__new__(Context)
        ctx.chain = SimpleNamespace(node=_const(body))
        from dao.context import NodeIdentity
        ctx.node = NodeIdentity()
        before = (ctx.node.pow_difficulty, ctx.node.chat_pow_difficulty)
        node = asyncio.run(ctx.refresh_node())
        assert (node.pow_difficulty, node.chat_pow_difficulty) == before


def _const(value):
    async def f():
        return value
    return f
