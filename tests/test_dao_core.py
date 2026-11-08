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


def test_text_guard_refuses_format_characters_and_normalises_line_separators():
    """XE-1099: the bidi controls and the rest of Cf are refused everywhere `clean_text`, `field_text` and
    `scrub` are used; the joiners and emoji variation selectors pass; U+2028/2029 become newlines."""
    from dao.text import clean_text, field_text, scrub
    bad = ["\u202e", "\u2066", "\u200b", "\u00ad", "\ufeff", "\U000e0001"]
    for c in bad:
        with pytest.raises(HTTPException):
            clean_text(f"a{c}b", "title", max_len=100)
        with pytest.raises(HTTPException):
            field_text({"proposal": f"a{c}b"}, "proposal")
        assert scrub(f"a{c}b") == "a\ufffdb"
    ok = "e\u0301 \u0646\u200c\u0627 \U0001f468\u200d\U0001f469 \u2764\ufe0f"
    assert clean_text(ok, "title", max_len=100) == ok
    assert clean_text("one\u2028two\u2029three", "body", max_len=100) == "one\ntwo\nthree"
    assert scrub("one\u2028two") == "one\ntwo"


def test_field_text_turns_a_wrong_type_into_a_400_naming_the_field():
    """XE-0966/XE-1010: every payload field the code lower-cases, compares or looks up goes through one
    guard, so a list where a hash was expected is a 400, not an AttributeError."""
    from dao.text import field_text
    for wrong in ([], {}, 1, True, 0):
        with pytest.raises(HTTPException) as e:
            field_text({"proposal": wrong}, "proposal")
        assert e.value.status_code == 400 and "proposal" in e.value.detail
    assert field_text({}, "proposal") == ""
    assert field_text({"proposal": "AB"}, "proposal") == "AB"
    with pytest.raises(HTTPException):
        field_text({"proposal": "x" * 300}, "proposal")


def test_every_payload_string_site_uses_the_guard():
    """The rule, enforced on the tree: no service or route reads a payload field and treats it as text
    without `clean_text` or `field_text`. Equality comparisons (`!=`) are safe for any type and are allowed."""
    import re
    bare = re.compile(r"payload\.get\([^)]*\)\s*(or\s*\"\")?\s*\)?\s*\.(lower|strip|upper|encode)|\(v\.payload\.get\([^)]*\) or \"\"\)\.")
    for path in (ROOT / "dao").rglob("*.py"):
        for n, line in enumerate(path.read_text().splitlines(), 1):
            assert not bare.search(line), f"{path.relative_to(ROOT)}:{n} treats a payload field as text without the guard"


def test_browser_signer_sorts_keys_by_code_point_like_python():
    """XE-1186: signer.js and canonical.py are two implementations of one format. Keys that start with an
    astral-plane character sort after U+E000..U+FFFF by code point (Python) and before them by UTF-16 code
    unit (JavaScript's default sort); the signer must give Python's order. Runs the signer's own `canon`
    under node when it is available."""
    import shutil
    import subprocess
    if not shutil.which("node"):
        pytest.skip("node not available")
    js = (ROOT / "dao/static/signer.js").read_text()
    start, end = js.index("  // Python json.dumps(sort_keys=True"), js.index("  async function sha256(")
    vectors = [
        {"\ufffd": 1, "\U00010000": 2, "a": [3, {"\U0001f600": "x", "\uffff": "y", "z": "\u00e9"}]},
        {"b": 1, "a": "\u2028", "\u00e9": None, "": True},
    ]
    script = js[start:end] + "\nconst vs = JSON.parse(process.argv[1]);\nfor (const v of vs) process.stdout.write(canon(v) + '\\n');\n"
    out = subprocess.run(["node", "-e", script, json.dumps(vectors)], capture_output=True, text=True, check=True).stdout
    assert out.splitlines() == [canonical_json(v).decode("ascii") for v in vectors]


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


def test_dated_jobs_are_due_once_per_calendar_period(monkeypatch):
    """XE-1192: a dated job is due when it has not run since its most recent scheduled time, read off the
    calendar; a 31-day month does not make the monthly job due again on the 4th."""
    from datetime import datetime, timezone
    from dao import worker_schedule as ws
    cfg = SimpleNamespace(config=SimpleNamespace(cadence={"monthly_report_day": 1, "daily_note_hour_utc": 8}))
    NS = 1_000_000_000

    def at(y, m, d, h=12):
        return int(datetime(y, m, d, h, tzinfo=timezone.utc).timestamp() * NS)

    runs = []
    for day in range(1, 32):
        monkeypatch.setattr(ws.time, "time_ns", lambda d=day: at(2026, 3, d))
        monkeypatch.setattr(ws, "datetime", _FrozenDatetime.at(datetime(2026, 3, day, 12, tzinfo=timezone.utc)))
        j = ws.job_table(cfg)["monthly"]
        if ws.due_at(runs[-1] if runs else None, j["prev"]):
            runs.append(at(2026, 3, day))
    assert runs == [at(2026, 3, 1)], "one run in March, on the 1st"
    monkeypatch.setattr(ws.time, "time_ns", lambda: at(2026, 4, 1))
    monkeypatch.setattr(ws, "datetime", _FrozenDatetime.at(datetime(2026, 4, 1, 12, tzinfo=timezone.utc)))
    j = ws.job_table(cfg)["monthly"]
    assert ws.due_at(runs[-1], j["prev"]) and j["prev"] == datetime(2026, 4, 1, 9, tzinfo=timezone.utc)
    assert j["at"] == datetime(2026, 5, 1, 9, tzinfo=timezone.utc)
    # the daily and weekly jobs expose the same shape
    t = ws.job_table(cfg)
    assert t["daily"]["at"] - t["daily"]["prev"] == __import__("datetime").timedelta(days=1)
    assert t["weekly"]["at"] - t["weekly"]["prev"] == __import__("datetime").timedelta(days=7)


class _FrozenDatetime:
    """`datetime` as worker_schedule sees it, with `now()` pinned."""
    @classmethod
    def at(cls, when):
        from datetime import datetime as real

        class Frozen(real):
            @classmethod
            def now(cls_, tz=None):
                return when if tz else when.replace(tzinfo=None)
        return Frozen


def test_node_advertised_difficulty_is_bounded_and_worker_pow_has_a_deadline():
    """XE-1188 / XE-1195: a difficulty below the harness default (including "0") or asking more than
    MAX_WORK_FACTOR times the default's work is refused the way a malformed one is, and the default stands;
    the grind the worker runs carries a deadline."""
    from xe.pow import (CHAT_POW_DIFFICULTY, DEFAULT_DIFFICULTY, MAX_WORK_FACTOR, WORKER_POW_DEADLINE_S,
                        compute_pow, expected_work, parse_difficulty)
    for d in (DEFAULT_DIFFICULTY, CHAT_POW_DIFFICULTY):
        assert parse_difficulty(f"{d:x}", d) == d
        harder_ok = (1 << 64) - ((1 << 64) - d) // MAX_WORK_FACTOR
        assert parse_difficulty(f"{harder_ok:x}", d) == harder_ok
        for bad in ("0", "1", f"{d - 1:x}", f"{harder_ok + 1:x}", "ffffffffffffffff", "fffffffffffff000"):
            with pytest.raises(ValueError):
                parse_difficulty(bad, d)
        assert parse_difficulty(None, d) == d and parse_difficulty("", d) == d
    assert expected_work(DEFAULT_DIFFICULTY) == 2 ** 21 and expected_work(CHAT_POW_DIFFICULTY) == 2 ** 18
    with pytest.raises(TimeoutError):
        compute_pow(b"\x00" * 32, 0xFFFFFFFFFFFFFFFF, deadline_s=0.05)
    assert WORKER_POW_DEADLINE_S > 0
    # the two unattended callers pass it
    import inspect
    from dao import chainops
    from dao.services import inbox
    assert "WORKER_POW_DEADLINE_S" in inspect.getsource(chainops._pow)
    assert "WORKER_POW_DEADLINE_S" in inspect.getsource(inbox.flush_outbox)


async def test_full_chain_stops_at_the_page_bound_whatever_total_the_node_claims():
    """XE-1189: the walk ends on a short page or the node's total when honest, and on the page bound when
    not, with an error rather than a silently truncated chain."""
    from xe.client import MAX_CHAIN_PAGES, PAGE, XeClient, XeError
    c = XeClient("http://node")
    calls = []

    async def lying(address, offset=0, limit=PAGE):
        calls.append(offset)
        return {"blocks": [{"hash": str(offset + i)} for i in range(limit)], "total": 2_000_000_000}

    c.chain = lying
    with pytest.raises(XeError) as e:
        await c.full_chain("a" * 64)
    assert e.value.status == 413 and len(calls) == MAX_CHAIN_PAGES

    async def honest(address, offset=0, limit=PAGE):
        blocks = [{"hash": str(i)} for i in range(offset, min(offset + limit, 2500))]
        return {"blocks": blocks, "total": 2500}

    c.chain = honest
    assert len(await c.full_chain("a" * 64)) == 2500


def test_the_streaming_handler_holds_no_request_scoped_session():
    """XE-1237: a long-lived response takes no pooled session for its lifetime; every read is its own short
    session. Asserted on every streaming handler in the tree, found by the response class it returns."""
    import inspect
    import re

    from dao.api import public
    streaming = {}
    for path in sorted(Path(public.__file__).parent.parent.rglob("*.py")):
        for chunk in re.split(r"\n(?=async def |def )", path.read_text()):   # top-level functions only
            m = re.match(r"async def (\w+)\(([^)]*)\)", chunk)
            if m and re.search(r"(EventSourceResponse|StreamingResponse)\(", chunk):
                streaming[m.group(1)] = m.group(2)
    assert set(streaming) == {"events_stream"}, streaming
    for name, params in streaming.items():
        assert "Db" not in params and "db" not in inspect.signature(getattr(public, name)).parameters, name


async def test_snapshot_node_reads_are_bounded_and_the_bound_only_lowers_the_weight():
    """XE-1460: one read per distinct source send, at most MAX_CAUSAL_LOOKUPS of them, and receives past the
    bound are excluded, never counted."""
    from dao.chainops import CAUSAL_LOOKUP_CONCURRENCY, MAX_CAUSAL_LOOKUPS, account_snapshot
    T = 100 * H
    n = MAX_CAUSAL_LOOKUPS * 4
    early = {"timestamp": T - 3 * H}
    # a dense account: n receives of 1 in the two-hour window, every one from a distinct, genuinely early send,
    # then the same n receives again from the same sends (repeats cost nothing)
    recvs = [{"type": "receive", "asset": "XE", "balance": i + 1, "timestamp": T - H + i, "hash": f"r{i}", "source": f"s{i % n}"}
             for i in range(2 * n)]
    chain = _Lattice({"D": recvs}, {f"s{i}": early for i in range(n)})
    in_flight = {"now": 0, "max": 0}
    real = chain.block

    async def counted(h):
        in_flight["now"] += 1
        in_flight["max"] = max(in_flight["max"], in_flight["now"])
        try:
            return await real(h)
        finally:
            in_flight["now"] -= 1
    chain.block = counted
    d = await account_snapshot(chain, "D", T)
    assert chain.lookups == MAX_CAUSAL_LOOKUPS and in_flight["max"] <= CAUSAL_LOOKUP_CONCURRENCY
    assert d["lookups_capped"] and len(d["excluded_receives"]) == 2 * n - 2 * MAX_CAUSAL_LOOKUPS
    # the true balance is 2n; what is counted is at most that, and exactly the receives whose sends were checked
    assert d["balance"] == 2 * MAX_CAUSAL_LOOKUPS <= 2 * n
    # a sparse account is unaffected: every send looked up once, nothing capped
    chain2 = _Lattice({"S": recvs[:3]}, {f"s{i}": early for i in range(3)})
    s = await account_snapshot(chain2, "S", T)
    assert chain2.lookups == 3 and not s["lookups_capped"] and s["balance"] == 3 and s["excluded_receives"] == []


def test_agents_tip_a_human_decision_and_never_make_one():
    """XE-1459: agent weight is bounded by the weight humans decided with, not by the total cast."""
    agent = _vote(100_000_000_000, "for", participating=False, is_agent=True)
    # humans abstain: quorum is met, nothing is decided, the agents do not decide it
    t = tally(_proposal(), [_vote(1_000_000, "abstain") for _ in range(20)] + [agent])
    assert t["quorum_met"] and t["weight"]["for"] == 0 and t["outcome"] == "failed"
    # humans vote dust against: the agents are bounded against that dust, not against their own bloc
    t = tally(_proposal(), [_vote(1_000_000, "against") for _ in range(20)] + [agent])
    assert t["weight"]["for"] <= int(0.01 * 20_000_000) and t["outcome"] == "failed"
    # no humans at all
    t = tally(_proposal(quorum=0), [agent])
    assert t["weight"]["for"] == 0 and t["outcome"] == "failed"
    # contested control: a close human vote, the agents tip it within the cap
    votes = [_vote(1_000_000, "for") for _ in range(10)] + [_vote(1_000_000, "against") for _ in range(10)] + [agent]
    t = tally(_proposal(), votes)
    assert 0 < t["weight"]["for"] - 10_000_000 <= int(0.01 * 20_000_000) and t["outcome"] == "passed"


def test_held_streams_are_capped_per_address_and_in_total():
    from fastapi import HTTPException

    from dao.ratelimit import Held
    held = Held("streams", per_ip=2, total=3)
    req = lambda ip: SimpleNamespace(client=SimpleNamespace(host=ip))  # noqa: E731
    a1, a2 = held.take(req("a")), held.take(req("a"))
    with pytest.raises(HTTPException) as e:
        held.take(req("a"))
    assert e.value.status_code == 429
    b1 = held.take(req("b"))
    with pytest.raises(HTTPException):
        held.take(req("c"))                      # total reached
    held.release(a1)
    held.take(req("c"))                          # a slot freed anywhere is available to anyone under their own cap
    held.release(a2), held.release(b1)
    assert held._n == 1 and held._by_ip == {"c": 1}
