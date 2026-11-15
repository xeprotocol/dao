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
    from dao.auth import signing_target
    kp = KeyPair.generate()
    payload = {"proposal": "ab" * 32, "choice": "for", "reason": ""}
    ts = time.time_ns()
    to = {"dao": "d" * 64, "network": "xe-test"}
    ctx = SimpleNamespace(config=SimpleNamespace(accounts={"dao": to["dao"]}), node=SimpleNamespace(network_id=to["network"]))
    # one target, and it is the documented one: domain, then who it is for, what it says and when
    target = digest(DOMAIN_VOTE, {"dao": to["dao"], "network": to["network"], "payload": payload, "timestamp": ts})
    assert signing_target(DOMAIN_VOTE, to, payload, ts) == target
    sig = kp.sign_hex(target)
    req = SignedRequest(payload=payload, timestamp=ts, pub_key=kp.pub_key_hex, signature=sig)
    v = verify_signed(ctx, req, DOMAIN_VOTE)
    assert v.account == kp.address
    assert v.digest == target
    # verification is pure: the replay claim lives in the database (test_log_db), so a second check passes here
    assert verify_signed(ctx, req, DOMAIN_VOTE).signature == sig.lower()
    # wrong domain fails
    from dao.canonical import DOMAIN_PROPOSAL
    with pytest.raises(HTTPException):
        verify_signed(ctx, SignedRequest(payload=payload, timestamp=ts, pub_key=kp.pub_key_hex, signature=sig), DOMAIN_PROPOSAL)
    # and so does the same request at a deployment with another account or on another network (XE-2068;
    # every signed route is walked in test_seat_requests)
    for other in (SimpleNamespace(config=ctx.config, node=SimpleNamespace(network_id="mainnet")),
                  SimpleNamespace(config=SimpleNamespace(accounts={"dao": "e" * 64}), node=ctx.node)):
        with pytest.raises(HTTPException) as e:
            verify_signed(other, req, DOMAIN_VOTE)
        assert e.value.status_code == 401


def test_http_pow_binds_to_digest_and_difficulty():
    from dao.auth import Verified, compute_http_pow, pow_target, require_pow, validate_http_pow
    d = digest(DOMAIN_VOTE, {"payload": {"message": "hi"}, "timestamp": 1})
    pub, other_pub = "11" * 32, "22" * 32
    target = pow_target(d, pub)
    easy = 0x0100000000000000  # ~1 in 256
    nonce = compute_http_pow(target, easy)
    assert validate_http_pow(target, nonce, easy)
    assert validate_http_pow(target, 0, 0)
    assert require_pow(Verified("a", pub, {}, 1, "s", digest=d, pow_nonce=nonce), easy) is None
    with pytest.raises(HTTPException) as e:
        require_pow(Verified("a", pub, {}, 1, "s", digest=d, pow_nonce=None), easy)
    assert e.value.status_code == 400 and "pow_nonce" in e.value.detail
    # The work is the sender's: the digest names the message and any key can sign it, so work found for
    # one key pays for that key alone (XE-11360). A nonce is taken that is work over the first key's target
    # and not over the second's (one in 65,536 is both, by luck, and the search starts somewhere random).
    hard_enough = 0xFFFF000000000000
    n2 = compute_http_pow(pow_target(d, pub), hard_enough)
    while validate_http_pow(pow_target(d, other_pub), n2, hard_enough):
        n2 = compute_http_pow(pow_target(d, pub), hard_enough)
    require_pow(Verified("a", pub, {}, 1, "s", digest=d, pow_nonce=n2), hard_enough)
    assert pow_target(d, pub) != pow_target(d, other_pub) and pow_target(d, pub)[:32] == d
    with pytest.raises(HTTPException) as e:
        require_pow(Verified("b", other_pub, {}, 1, "s2", digest=d, pow_nonce=n2), hard_enough)
    assert e.value.status_code == 400
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


def test_the_page_parses_typed_json_only_when_every_number_in_it_is_exact():
    """XE-11041. `canon` refuses a float and an integer past 2^53, and JSON.parse had already turned
    1.0000000000000001 into 1 and 9007199254740993 into its neighbour before canon saw either. What a
    person types into the ops box is read as text first."""
    import shutil
    import subprocess
    js = (ROOT / "dao/static/signer.js").read_text()
    for page in ("proposal_new.html", "members.html"):
        text = (ROOT / "dao/templates" / page).read_text()
        assert "XeSigner.parseExact(" in text and "JSON.parse(" not in text, page
    if not shutil.which("node"):
        pytest.skip("node not available")
    start, end = js.index("  // Python json.dumps(sort_keys=True"), js.index("  async function sha256(")
    kept = ['{"a":[1,-2,0]}', '{"s":"1.5e3 \\" 2.0","n":9007199254740991}']
    refused = ["[1.0]", "[1e2]", "[9007199254740993]", "[1.0000000000000001]", '{"a":-9007199254740992}', "[01]"]
    script = js[start:end] + """
for (const t of JSON.parse(process.argv[1])) {
  let out; try { out = JSON.stringify(parseExact(t)); } catch (e) { out = "refused"; }
  process.stdout.write(out + "\\n");
}
"""
    out = subprocess.run(["node", "-e", script, json.dumps(kept + refused)], capture_output=True, text=True, check=True).stdout
    assert out.splitlines() == kept + ["refused"] * len(refused)


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
        verify_signed(None, SignedRequest(payload={}, timestamp=ts, pub_key=kp.pub_key_hex, signature=sig), DOMAIN_VOTE)
    assert e.value.status_code == 400   # the window is checked before anything else is looked at


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
        # final unless a test says otherwise: a weight rests only on blocks the node holds final (XE-3129)
        return [{"finalized": True, **b} for b in self.chains[account]]

    async def block(self, h):
        from xe.client import XeError
        self.lookups += 1
        if h not in self.blocks:
            raise XeError(404, "no such block")
        return {"finalized": True, **self.blocks[h]}


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
    from xe.pow import DEFAULT_DIFFICULTY, parse_difficulty
    # the format: 1-16 hex digits in either case, read as a u64. Which well-formed values are then taken
    # (none easier than the default, "0" included, and none far harder) is the band's test, further down.
    for well_formed in ("fffff80000000000", "FFFFF80000000000"):
        assert parse_difficulty(well_formed, DEFAULT_DIFFICULTY) == 0xFFFFF80000000000
    assert parse_difficulty("7", 7) == 7 and parse_difficulty(None, 7) == 7 and parse_difficulty("", 7) == 7
    for bad in ("zz", "-1", "+ff", "0x10", " ff", "f_f", "1" * 17, 12, True, [], {}):
        with pytest.raises(ValueError):
            parse_difficulty(bad, 7)

    from dao.context import Context
    for body in ({"pow_difficulty": "zz", "chat_pow_difficulty": "-1"}, ["not", "a", "dict"], "nope", {"pow_difficulty": 5}):
        ctx = Context.__new__(Context)
        ctx.chain = SimpleNamespace(node=_const(body))
        ctx.settings = SimpleNamespace(xe_network_id="xe-test", xe_node_url="http://node")
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
    # every receive left out is counted; the snapshot names the first of them and no more (XE-14105)
    from dao.chainops import MAX_EXCLUDED_SHOWN
    assert d["lookups_capped"] and d["excluded_count"] == 2 * n - 2 * MAX_CAUSAL_LOOKUPS > MAX_EXCLUDED_SHOWN
    assert len(d["excluded_receives"]) == MAX_EXCLUDED_SHOWN
    # the true balance is 2n; what is counted is at most that, and exactly the receives whose sends were checked
    assert d["balance"] == 2 * MAX_CAUSAL_LOOKUPS <= 2 * n
    # a sparse account is unaffected: every send looked up once, nothing capped
    chain2 = _Lattice({"S": recvs[:3]}, {f"s{i}": early for i in range(3)})
    s = await account_snapshot(chain2, "S", T)
    assert chain2.lookups == 3 and not s["lookups_capped"] and s["balance"] == 3 and s["excluded_receives"] == []
    # XE-1548 / XE-1589: the budget goes to the largest receives, whatever their order, and foreign-asset
    # receives spend none of it. A stranger floods the window with 100 dust XE receives and 100 XUSD receives
    # after the voter's one material receive; the material receive is checked and counted, the dust is what
    # the cap drops.
    dust_xe = [{"type": "receive", "asset": "XE", "balance": 1_000_000 + i + 1, "timestamp": T - H + 10 + i, "hash": f"d{i}", "source": f"ds{i}"}
               for i in range(100)]
    dust_xusd = [{"type": "receive", "asset": "XUSD", "balance": i + 1, "timestamp": T - H + 200 + i, "hash": f"u{i}", "source": f"us{i}"}
                 for i in range(100)]
    material = {"type": "receive", "asset": "XE", "balance": 1_000_000, "timestamp": T - H + 1, "hash": "m", "source": "ms"}
    chain3 = _Lattice({"V": [material, *dust_xe, *dust_xusd]}, {"ms": early, **{f"ds{i}": early for i in range(100)}})
    v = await account_snapshot(chain3, "V", T)
    assert chain3.lookups == MAX_CAUSAL_LOOKUPS and v["lookups_capped"]
    assert "m" not in v["excluded_receives"] and not any(h.startswith("u") for h in v["excluded_receives"])
    assert v["balance"] == 1_000_000 + (MAX_CAUSAL_LOOKUPS - 1)   # the material receive and 31 dust; 69 dust dropped


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


# ---- XE-1479: the company's accounts come from the signer; agents are bounded, not zeroed -----------------

def test_company_accounts_come_from_the_signer_and_agent_seats_are_not_zeroed():
    cfg = load_config(ROOT / "config")
    agent = "a" * 64
    cfg.schedule_c["agent_seats"] = [{"id": "x", "role": "r", "account": agent}]
    cfg.schedule_c["accounts"] = {"dao": "", "fee": "", "treasury": "t" * 64}
    cfg.signer_accounts = {"dao": "D" * 64, "fee": "F" * 64}
    assert cfg.accounts["dao"] == "d" * 64 and cfg.accounts["fee"] == "f" * 64 and cfg.accounts["treasury"] == "t" * 64
    ex = cfg.excluded_accounts()
    assert {"d" * 64, "f" * 64, "t" * 64} <= ex, "the company's own accounts weigh nothing"
    assert agent not in ex, "an agent seat's weight is bounded by the tally cap, not zeroed"
    assert agent in cfg.agent_accounts
    # the pinned rules a proposal carries agree with the property
    assert set(cfg.pinned_rules()["excluded_accounts"]) == ex
    # schedule C naming a different address for an account the signer holds does not win: the key is the fact
    cfg.schedule_c["accounts"]["fee"] = "9" * 64
    assert cfg.accounts["fee"] == "f" * 64


# ---- XE-1493: the agent cap is shared by largest remainder; no micro-XE is lost or invented --------------

def test_agent_cap_is_shared_without_losing_or_inventing_weight():
    from dao.services.portal import _share
    for parts, total in (({"for": 1, "against": 1, "abstain": 1}, 2), ({"for": 7, "against": 3, "abstain": 0}, 1),
                         ({"for": 333, "against": 333, "abstain": 334}, 100), ({"for": 5, "against": 0, "abstain": 0}, 5),
                         ({"for": 0, "against": 0, "abstain": 0}, 0)):
        out = _share(parts, total)
        assert sum(out.values()) == total and set(out) == set(parts), (parts, total, out)
        assert all(0 <= out[k] <= parts[k] for k in parts), (parts, total, out)
        assert all(out[k] == 0 for k in parts if parts[k] == 0)
    # the tally: 20 humans decide with 20 XE; agents cast 100 XE across for and against. 1% of 20 XE = 0.2 XE,
    # all of it counted, split between the agent choices in proportion
    votes = [_vote(1_000_000, "against") for _ in range(20)]
    votes += [_vote(75_000_000, "for", participating=False, is_agent=True), _vote(25_000_000, "against", participating=False, is_agent=True)]
    t = tally(_proposal(quorum=20), votes)
    assert t["weight"]["for"] + t["weight"]["against"] == 20_000_000 + 200_000
    assert t["weight"]["for"] == 150_000 and t["weight"]["against"] == 20_050_000
    # an agent alone, with no human decision, counts nothing
    t = tally(_proposal(quorum=1), [_vote(1_000_000, "abstain"), _vote(10, "for", participating=False, is_agent=True)])
    assert t["weight"]["for"] == 0 and t["weight_agent_raw"]["for"] == 10


# ---- XE-1504: a statechain key is matched end to end, as the node's RE2 matches it ------------------------

def test_statechain_key_pattern_has_no_trailing_newline_exception():
    from xe.statechain import StateChainError, StateOp
    StateOp.set("dao.ok-1_2", 1).validate()
    for bad in ("dao.x\n", "dao.x\n\n", "\ndao.x", "dao.X", "dao x", "", "a" * 300):
        with pytest.raises(StateChainError):
            StateOp.set(bad, 1).validate()
    with pytest.raises(StateChainError):
        StateOp.delete("k\n").validate()


# ---- XE-1489: caller-supplied values are data in a node URL, never path or query -------------------------

def test_every_client_path_segment_is_percent_encoded():
    import re
    from xe.client import _seg
    src = Path("xe/client.py").read_text()
    raw = [m for m in re.findall(r'f"/[^"]*"', src) if re.search(r"\{(?!_seg\()", m)]
    assert raw == [], f"path interpolation without _seg: {raw}"
    assert _seg("dao.anchor.1") == "dao.anchor.1" and _seg(7) == "7"
    assert _seg("x/../y") == "x%2F..%2Fy" and _seg("k?limit=1") == "k%3Flimit%3D1" and _seg("a#b") == "a%23b"
    assert _seg("a b\n") == "a%20b%0A"


# ---- XE-1789: XE that arrives by a lease settle is causal like a receive -----------------------------------

async def test_snapshot_does_not_count_a_settle_for_a_lease_opened_after_it():
    from dao.chainops import account_snapshot
    T = 100 * H
    # the provider's chain: a settle dated just before the snapshot, minting 59 XE for lease L
    settle = {"type": "lease_settle", "asset": "XE", "balance": 59_000_000, "timestamp": T - 60 * 10**9, "hash": "s1", "source": "L"}
    lease_after = {"type": "lease", "asset": "XUSD", "timestamp": T + 50 * 60 * 10**9, "hash": "L"}   # escrow dated after the snapshot
    chain = _Lattice({"P": [settle]}, {"L": lease_after})
    p = await account_snapshot(chain, "P", T)
    assert p["balance"] == 0 and p["excluded_receives"] == ["s1"] and chain.lookups == 1
    # a lease opened before the snapshot: the emission counts
    lease_after["timestamp"] = T - 2 * H
    p = await account_snapshot(chain, "P", T)
    assert p["balance"] == 59_000_000 and p["excluded_receives"] == []
    # a settle outside the two-hour window is not looked up at all
    settle["timestamp"] = T - 3 * H
    chain.lookups = 0
    assert (await account_snapshot(chain, "P", T))["balance"] == 59_000_000 and chain.lookups == 0


# ---- XE-1917 / XE-1919: ops are validated as the node validates them: whole block, strict JSON -----------

def test_ops_that_cannot_make_a_block_are_refused_at_intake():
    from xe.statechain import MAX_BLOCK_SIZE, MAX_VALUE_SIZE, StateChainError, StateOp, check_ops_fit
    from dao.services.sessions import normalise_ops
    big = "x" * (MAX_VALUE_SIZE - 10)
    ops = [StateOp.set(f"dao.k{i}", big) for i in range(5)]   # each under the per-op bound, together past the block
    for op in ops:
        op.validate()
    with pytest.raises(StateChainError, match="MaxBlockSize"):
        check_ops_fit(ops)
    with pytest.raises(HTTPException) as e:
        normalise_ops([{"action": "set", "key": f"dao.k{i}", "value": big} for i in range(5)])
    assert e.value.status_code == 400 and "MaxBlockSize" in e.value.detail
    check_ops_fit(ops[:3])
    assert 3 * MAX_VALUE_SIZE < MAX_BLOCK_SIZE < 5 * MAX_VALUE_SIZE


def test_non_finite_numbers_are_not_json_anywhere_a_value_is_read():
    from xe.statechain import StateChainError, StateOp, canonical_value, compact_json, strict_loads
    from dao.services.sessions import normalise_ops
    for raw in ("1e400", "Infinity", "-Infinity", "NaN", '{"a":1e999}', "[NaN]"):
        with pytest.raises(StateChainError):
            canonical_value(raw)
        with pytest.raises(StateChainError):
            strict_loads(raw)
    for val in (float("inf"), float("nan"), {"a": float("-inf")}):
        with pytest.raises(StateChainError):
            compact_json(val)
    # a value that arrived already as the text Python would have written is refused when validated
    with pytest.raises(StateChainError):
        StateOp("set", "dao.x", "Infinity").validate()
    with pytest.raises(HTTPException) as e:
        normalise_ops([{"action": "set", "key": "dao.x", "value": "1e400"}])
    assert e.value.status_code == 400
    with pytest.raises(HTTPException):
        normalise_ops([{"action": "set", "key": "dao.x", "value": float("inf")}])
    assert normalise_ops([{"action": "set", "key": "dao.x", "value": 1e300}])[0]["value"] == "1e+300"


# ---- XE-1688: every Unicode control is refused, the C1 range included ---------------------------------------

def test_text_guard_refuses_c1_controls():
    from dao.text import clean_text, has_bad_control, scrub
    for c in ("\x80", "\x85", "\x9f", "\x7f", "\x00"):
        assert has_bad_control("a" + c + "b"), hex(ord(c))
        with pytest.raises(HTTPException):
            clean_text("a" + c + "b", "f", max_len=10)
        assert scrub("a" + c + "b") == "a\ufffdb"
    assert clean_text("a\tb\nc", "f", max_len=10) == "a\tb\nc"


# ---- XE-1779: a keyfile that cannot be opened is one SignerError -------------------------------------------

def test_every_corrupt_keyfile_is_a_signer_error(tmp_path):
    good = tmp_path / "ok.json"
    Signer.init_keyfile(good, "pass phrase here")
    blob = json.loads(good.read_text())
    cases = {
        "not-json": "{not json",
        "not-object": "[1,2,3]",
        "no-salt": json.dumps({k: v for k, v in blob.items() if k != "salt"}),
        "bad-hex-salt": json.dumps({**blob, "salt": "zz"}),
        "no-ciphertext": json.dumps({k: v for k, v in blob.items() if k != "ciphertext"}),
        "truncated": json.dumps({**blob, "ciphertext": blob["ciphertext"][:20]}),
    }
    for name, text in cases.items():
        p = tmp_path / f"{name}.json"
        p.write_text(text)
        # every way in: the keyfile is opened by `load` and by `add_key` (XE-4282)
        for opened in (lambda: Signer.load(p, "pass phrase here"), lambda: Signer.add_key(p, "pass phrase here", "agent:x")):
            with pytest.raises(SignerError):
                opened()
        assert p.read_text() == text, "a keyfile that could not be opened is left as it was"
    from dao import signer as signer_mod
    for name, contents in (("not-a-dict", [1]), ("no-keys", {"scopes": {}}), ("keys-a-list", {"keys": ["x"]}),
                           ("scopes-a-list", {"keys": {}, "scopes": []})):
        p = tmp_path / f"{name}.json"
        p.write_text(json.dumps(signer_mod.encrypt_keyfile(contents, "pass phrase here")))
        for opened in (lambda: Signer.load(p, "pass phrase here"), lambda: Signer.add_key(p, "pass phrase here", "agent:x")):
            with pytest.raises(SignerError):
                opened()
    for opened in (Signer.load, lambda path, pw: Signer.add_key(path, pw, "agent:x")):
        with pytest.raises(SignerError, match="not found"):
            opened(tmp_path / "absent.json", "pass phrase here")
        with pytest.raises(SignerError, match="wrong or the file is corrupt"):
            opened(good, "not the pass phrase")
        with pytest.raises(SignerError, match="empty"):
            opened(good, "")


# ---- XE-1639: the expected number of checks is counted under the cadence in force at the time --------------

def test_expected_checks_use_the_cadence_each_stretch_ran_under():
    from dao.services.records import expected_checks
    S = 10**9
    start, now = 0, 30 * 86400 * S
    # ten-minute checks for 29 days, then hourly for the last day
    rows = [(t, 600) for t in range(0, 29 * 86400 * S, 600 * S)] + [(t, 3600) for t in range(29 * 86400 * S, now, 3600 * S)]
    assert expected_checks(rows, start, now, 3600) == 29 * 144 + 24
    assert expected_checks(rows, start, now, 600) == 29 * 144 + 24, "the current cadence rewrites nothing behind it"
    # a gap: 144 checks are expected for a missing day at ten minutes, whatever the config says today
    rows = [(0, 600), (2 * 86400 * S, 600)]
    assert expected_checks(rows, 0, 3 * 86400 * S, 3600) == 3 * 144
    # rows without a recorded cadence (older) use the current one; no rows at all: the window at the current cadence
    assert expected_checks([(0, None)], 0, 86400 * S, 600) == 144
    assert expected_checks([], 0, 86400 * S, 3600) == 24
    assert expected_checks([], 10, 10, 600) == 0


# ---- XE-1673: the stream parses before it takes a slot -----------------------------------------------------

def test_stream_resume_is_parsed_before_a_slot_is_taken():
    import re
    from dao.api.public import RESUME_RE
    assert RESUME_RE.fullmatch("12") and RESUME_RE.fullmatch("-5") and RESUME_RE.fullmatch("0")
    for bad in ("--5", "+5", "5x", "", " 5", "1" * 19, "١٢"):
        assert not RESUME_RE.fullmatch(bad), bad
    src = (ROOT / "dao" / "api" / "public.py").read_text()
    body = src.split("async def events_stream(", 1)[1].split("\n    async def gen(", 1)[0]
    parse_at, take_at = body.index("RESUME_RE.fullmatch"), body.index("STREAMS.take(")
    assert parse_at < take_at, "anything that can refuse the request happens before the slot is taken"
    after_take = body[take_at:]
    assert re.search(r"\bint\(resume\)", after_take), "the parse the regex guarantees happens after the take"
    assert "raise HTTPException" not in after_take, "nothing between the take and the response refuses the request"


# ---- XE-1649 / XE-1725: ops are compared by what they write ---------------------------------------------------

def test_same_ops_compares_values_by_meaning_not_bytes():
    from dao.services.portal import same_ops
    a = [{"action": "set", "key": "dao.x", "value": '{"b":1,"a":2}'}, {"action": "delete", "key": "dao.y"}]
    b = [{"action": "set", "key": "dao.x", "value": '{"a":2,"b":1}'}, {"action": "delete", "key": "dao.y"}]
    assert same_ops(a, b) and same_ops(a, a)
    assert not same_ops(a, b[:1]) and not same_ops(a, [b[1], b[0]])
    assert not same_ops(a, [{"action": "set", "key": "dao.x", "value": '{"a":2,"b":2}'}, b[1]])
    assert not same_ops(a, [{"action": "set", "key": "dao.z", "value": '{"a":2,"b":1}'}, b[1]])
    assert not same_ops(None, a) and not same_ops(a, None)


def test_same_ops_allows_key_order_and_nothing_else():
    """XE-2077: the comparison is of the text that goes on the chain, with object keys sorted. Values Python
    calls equal and the chain does not are different ops, at every depth and in every position."""
    from dao.services.portal import same_ops
    op = lambda v: [{"action": "set", "key": "dao.x", "value": v}]  # noqa: E731
    different = ["1", "1.0", "true", '"1"', "[1]", "0", "0.0", "false", "null", '""', "{}", "[]", '"true"', "2"]
    for i, x in enumerate(different):
        for y in different[i + 1:]:
            assert not same_ops(op(x), op(y)) and not same_ops(op(y), op(x)), (x, y)
            assert not same_ops(op('{"a":{"b":[%s]}}' % x), op('{"a":{"b":[%s]}}' % y)), (x, y)
        assert same_ops(op(x), op(x))
    assert same_ops(op('{"a":{"y":1,"x":[{"q":1,"p":2}]},"b":2}'), op('{"b":2,"a":{"x":[{"p":2,"q":1}],"y":1}}'))
    assert same_ops(op('{ "a" : 1.0 }'), op('{"a":1e0}')) and same_ops(op('"\\u0061"'), op('"a"')), \
        "one value spelled two ways is one value"
    assert not same_ops(op("[1,2]"), op("[2,1]")), "array order is content"
    assert not same_ops(op("not json"), op("not json")), "a value that is not JSON authorises nothing"
    assert not same_ops(op("NaN"), op("NaN"))
    assert not same_ops([{"action": "set", "key": "dao.x"}], [{"action": "set", "key": "dao.x"}])


# ---- XE-2374: the window is rounded once ------------------------------------------------------------------

def test_expected_checks_are_summed_exactly_and_rounded_once():
    """A worker that checks every cadence-and-a-half ran two-thirds of its checks, at any cadence and whether
    or not the rows recorded one. Rounding each gap to a whole check scored it full."""
    from dao.services.records import expected_checks
    S = 10**9
    day = 86400 * S
    for cadence in (60, 600, 3600):
        want = 86400 // cadence
        for factor in (1.0, 1.25, 1.4, 1.5, 2.0, 3.3):
            step = int(cadence * factor) * S
            for recorded in (cadence, None):
                rows = [(t, recorded) for t in range(0, day, step)]
                assert expected_checks(rows, 0, day, cadence) == want, (cadence, factor, recorded)
    # mixed cadences with slow stretches: 12 hours owed at ten minutes, then 12 hours owed hourly
    rows = [(t, 600) for t in range(0, day // 2, 900 * S)] + [(t, 3600) for t in range(day // 2, day, 5400 * S)]
    assert expected_checks(rows, 0, day, 600) == 72 + 12
    # a window shorter than half a check owes none; one past half owes one
    assert expected_checks([], 0, 299 * S, 600) == 0 and expected_checks([], 0, 301 * S, 600) == 1


# ---- XE-2209 / XE-1935 / XE-2305 / XE-2353: what the node sends is input, bounded and typed in one place ----

def _node(handler):
    import httpx

    from xe.client import XeClient
    return XeClient("http://node", transport=httpx.MockTransport(handler))


_HOSTILE = [
    b"", b"null", b"[]", b"{}", b'"x"', b"1", b"1.5", b"true", b"<html>busy</html>", b"[" * 100_000,
    b'{"blocks":1}', b'{"blocks":[1]}', b'{"blocks":[{"amount":"x"}],"total":"y"}', b'{"blocks":[{"hash":5}],"total":1}',
    b'{"blocks":[{"hash":"a","balance":1.5}],"total":1}', b'{"blocks":[],"total":-1}', b'{"blocks":[],"total":7}',
    b'{"blocks":null,"total":null}', b'{"blocks":[{"hash":"a"},{"hash":"b"},{"hash":"c"}],"total":3}',
    b'{"balances":[]}', b'{"balances":{"XE":1.5}}', b'{"balances":{"XE":-1}}', b'{"balances":{"XE":true}}',
    b'{"balances":{"XE":null}}', b'{"balances":{"XE":"12x"}}', b'{"balances":{"XE":18446744073709551616}}',
    b'{"pending":5}', b'{"pending":[1]}', b'{"pending":[{"Amount":[]}]}', b'{"pending":[{"amount":"1","SendHash":7}]}',
    b'{"keys":[1],"threshold":1}', b'{"keys":5,"threshold":"x"}', b'{"keys":["AB"]}', b'{"threshold":2}',
    b'{"index":{},"timestamp":[],"hash":5}', b'{"index":1,"timestamp":2}', b'{"hash":"h","index":"-1"}',
    b'{"challenge":"zz"}', b'{"challenge":5}', b'{"key":"k","value":{"a":[1]}}', b'[{"id":1},2,"x",null]',
    b'{"type":"send","amount":"9","timestamp":1e3}', b'{"error":"no"}', b"\xff\xfe",
]


async def test_every_node_read_returns_its_types_or_fails_as_xeerror():
    """The rule, across every read the client has and every status the node can answer with: whatever
    the body, the call returns or raises XeError. Nothing from httpx, json or a conversion escapes, so no
    caller needs a second except clause, and none is taken down by a body it did not expect."""
    import inspect

    import httpx

    from xe.client import XeClient, XeError
    a, proof = "a" * 64, {"account": "a" * 64, "challenge": "00", "signature": "00", "pub_key": "00"}
    reads = {
        "node": (), "ready": (), "chain": (a,), "full_chain": (a,), "chain_end": (a,), "tip": (a,), "keyset_of": (a,),
        "pending_for": (a,), "balances": (a,), "block": ("h",), "statechain_tip": (), "statechain_block": (3,),
        "statechain_key": ("dao.x",), "dao_keyset": (), "directory": (a,), "chat_challenge": (), "chat_messages": (proof,),
    }
    writes = {"submit_block", "submit_statechain_block", "directory_register", "chat_send", "chat_events", "aclose"}
    public = {n for n, f in inspect.getmembers(XeClient, inspect.isfunction) if not n.startswith("_")}
    assert public == set(reads) | writes, "a new client method is added to this test, typed, or not added at all"
    for status in (200, 404, 500):
        for body in _HOSTILE:
            c = _node(lambda request: httpx.Response(status, content=body))
            for name, args in reads.items():
                try:
                    await getattr(c, name)(*args)
                except XeError:
                    pass
                except BaseException as e:   # noqa: BLE001 - the assertion is that there is no such thing
                    raise AssertionError(f"{name} let {type(e).__name__} out for {status} {body[:40]!r}") from e
            await c.aclose()

    def refuse(request):
        raise httpx.ConnectError("refused")
    c = _node(refuse)
    for name, args in reads.items():
        with pytest.raises(XeError) as e:
            await getattr(c, name)(*args)
        assert e.value.status == 0 and e.value.transient, name


async def test_node_fields_the_harness_computes_with_are_integers_or_the_response_is_refused():
    import httpx

    from xe.client import XeError
    body = {}
    c = _node(lambda request: httpx.Response(200, json=body["v"]))

    async def refused(call, *args):
        with pytest.raises(XeError) as e:
            await call(*args)
        assert e.value.status == 0 and "malformed" in e.value.message, body["v"]

    # a decimal string is the number it spells; nothing else is a number
    body["v"] = {"balances": {"XE": "12", "XUSD": 7}}
    assert await c.balances("a") == {"XE": 12, "XUSD": 7}
    for bad in (1.5, -1, True, None, "12x", "", "١٢", "1" * 21, 2**64, [], {}):
        body["v"] = {"balances": {"XE": bad}}
        await refused(c.balances, "a")
    for field in ("balance", "timestamp", "amount"):
        for bad in (1.5, -1, True, "x", [], {}):
            body["v"] = {"blocks": [{"hash": "h", field: bad}], "total": 1}
            await refused(c.chain, "a")
            body["v"] = {"hash": "h", field: bad}
            await refused(c.block, "h")
    for field in ("type", "account", "previous", "asset", "source", "destination", "hash"):
        body["v"] = {"blocks": [{field: 5}], "total": 1}
        await refused(c.chain, "a")
    body["v"] = {"blocks": [{"hash": "h", "amount": "9", "timestamp": 3, "memo": None, "finalized": True}], "total": "1"}
    page = await c.chain("a")
    assert page == {"blocks": [{"hash": "h", "amount": 9, "timestamp": 3, "finalized": True}], "total": 1}
    # a page is never longer than was asked for
    body["v"] = {"blocks": [{"hash": "1"}, {"hash": "2"}], "total": 2}
    await refused(lambda: c.chain("a", limit=1))
    # pending entries, either spelling of the keys
    body["v"] = {"pending": [{"SendHash": "s", "Amount": "5", "Source": "x"}, {"send_hash": "t", "amount": 6}]}
    assert [(p["send_hash"], p["amount"], p["asset"], p["timestamp"]) for p in await c.pending_for("a")] == \
        [("s", 5, "XE", 0), ("t", 6, "XE", 0)]
    for bad in ({"pending": [{"Amount": 1.5}]}, {"pending": [{"SendHash": 5}]}, {"pending": [[]]}, {"pending": {}}):
        body["v"] = bad
        await refused(c.pending_for, "a")
    # the state chain and the keyset
    body["v"] = {"index": "4", "timestamp": 9, "hash": "h"}
    assert await c.statechain_tip() == {"index": 4, "timestamp": 9, "hash": "h"}
    for bad in ({"index": 4, "timestamp": 9}, {"index": 4.0, "timestamp": 9, "hash": "h"}, {"index": 4, "timestamp": 9, "hash": 7}, []):
        body["v"] = bad
        await refused(c.statechain_tip)
    k1, k2 = "ab" * 32, "cd" * 32
    body["v"] = {"keys": [k1.upper(), k2], "threshold": 2}
    assert await c.dao_keyset() == {"keys": [k1, k2], "threshold": 2}
    for bad in ({"keys": [k1, 5], "threshold": 1}, {"keys": k1, "threshold": 1}, {"keys": [k1]}, {"keys": [k1], "threshold": "x"},
                {"keys": ["ab", "cd"], "threshold": 2}, {"keys": [k1, "zz" * 32], "threshold": 1},
                # one key spelt twice is one key: a threshold of two over it could never be met (XE-3845)
                {"keys": [k1, k1.upper()], "threshold": 2}, {"keys": [k1, k2, k1], "threshold": 2}):
        body["v"] = bad
        await refused(c.dao_keyset)
    await c.aclose()


async def test_a_response_is_read_under_a_size_cap_and_a_total_deadline(monkeypatch):
    """XE-2305, XE-1935: on every call, since every call goes through `_send`. A body past the cap is
    refused before it is all buffered; a node that drips is cut off at the deadline, however short each
    silence is; a chat stream that goes silent ends, and so does one whose line never does."""
    import asyncio

    import httpx

    from xe import client as xc

    class Drip(httpx.AsyncByteStream):
        def __init__(self, chunk=b" ", every=0.01, count=10**9):
            self.chunk, self.every, self.count, self.sent = chunk, every, count, 0

        async def __aiter__(self):
            while self.sent < self.count:
                await asyncio.sleep(self.every)
                self.sent += 1
                yield self.chunk

    monkeypatch.setattr(xc, "MAX_BODY_BYTES", 4096)
    big = Drip(chunk=b"x" * 1024, every=0, count=10**6)
    c = _node(lambda request: httpx.Response(200, stream=big))
    for call in (lambda: c.balances("a"), lambda: c.chain("a"), lambda: c.statechain_tip(), lambda: c.chat_send({}),
                 lambda: c.ready()):
        big.sent = 0
        with pytest.raises(xc.XeError) as e:
            await call()
        assert e.value.status == 0 and "exceeds" in e.value.message and big.sent <= 6, "stopped reading at the cap"
    await c.aclose()

    monkeypatch.setattr(xc, "REQUEST_DEADLINE_S", 0.2)
    slow = Drip()
    c = _node(lambda request: httpx.Response(200, stream=slow))
    t0 = time.monotonic()
    with pytest.raises(xc.XeError) as e:
        await c.balances("a")
    assert e.value.status == 0 and e.value.transient and time.monotonic() - t0 < 2

    async def never(request):
        await asyncio.sleep(3600)
    c2 = _node(never)
    with pytest.raises(xc.XeError):
        await c2.statechain_tip()
    await c.aclose(), await c2.aclose()

    # the chat stream: no total deadline, an idle limit and a line cap
    monkeypatch.setattr(xc, "STREAM_IDLE_S", 0.2)

    class Stream(httpx.AsyncByteStream):
        def __init__(self, parts, then=None):
            self.parts, self.then = parts, then

        async def __aiter__(self):
            for p in self.parts:
                yield p
            if self.then == "hang":
                await asyncio.sleep(3600)
            while self.then == "flood":
                yield b"x" * 4096

    async def read(stream):
        c = _node(lambda request: httpx.Response(200, stream=stream))
        got = []
        try:
            async for item in c.chat_events({"account": "a"}):
                got.append(item)
        finally:
            await c.aclose()
        return got

    lines = [b'data: {"id":"1"}\n\n: ping\n\ndata: [1]\n\nda', b'ta: {"id":"2"}\n', b"data: not json\n", b'data: {"id":"3"}\n']
    assert await read(Stream(lines)) == [{"id": "1"}, {"id": "2"}, {"id": "3"}]
    for then, says in (("hang", "silent"), ("flood", "exceeds")):
        got = []
        c = _node(lambda request: httpx.Response(200, stream=Stream(lines, then)))
        t0 = time.monotonic()
        with pytest.raises(xc.XeError) as e:
            async for item in c.chat_events({"account": "a"}):
                got.append(item)
        assert says in e.value.message and e.value.status == 0 and time.monotonic() - t0 < 2
        assert [g["id"] for g in got] == ["1", "2", "3"], "what arrived before the stream died was delivered"
        await c.aclose()
    c = _node(lambda request: httpx.Response(401))
    with pytest.raises(xc.XeError) as e:
        async for _ in c.chat_events({"account": "a"}):
            pass
    assert e.value.status == 401
    await c.aclose()


async def test_what_the_client_returns_can_be_kept_and_only_a_2xx_is_an_answer():
    """The other half of the boundary. Node data ends up in JSONB and text columns, where one value
    Postgres will not take fails the whole write it rides in on; and "nothing there" is acted on (an empty
    account, an unregistered entry), so only the node saying so, with a 404, is taken for it."""
    import gzip

    import httpx

    from xe import client as xc
    from xe.client import PAGE, XeError
    a, proof = "a" * 64, {"account": "a" * 64, "challenge": "00", "signature": "00", "pub_key": "00"}
    reply = {}
    c = _node(lambda request: reply["v"](request) if callable(reply["v"]) else httpx.Response(200, content=reply["v"]))

    async def refused(call, says=""):
        with pytest.raises(XeError) as e:
            await call()
        assert e.value.status == 0 and says in e.value.message, (reply["v"], e.value.message)

    # not JSON, not storable as JSON, not text: refused whichever read it arrives in
    nul = '{"key":"k","value":"a\\u0000b"}'
    unkeepable = (b'{"key":"k","value":NaN}', b'{"key":"k","value":[1,Infinity]}', b'{"key":"k","value":-Infinity}',
                  nul.encode(), b'{"key":"k","value":{"a\\u0000":1}}', b'{"key":"k","value":"\\ud800"}',
                  # the same NUL in the encodings a lenient parser guesses: the body is UTF-8 or it is refused
                  nul.encode("utf-16-le"), nul.encode("utf-16"), nul.encode("utf-32-be"), '{"key":"k","value":"plain"}'.encode("utf-16"))
    for body in unkeepable:
        reply["v"] = body
        await refused(lambda: c.statechain_key("dao.x"))
    reply["v"] = b'{"key":"k","value":"\\ud83d\\ude00 a pair is a character"}'
    assert (await c.statechain_key("dao.x")).startswith("\U0001f600")
    reply["v"] = b'{"key":"k","value":"a backslash, then u0000: \\\\u0000"}'
    assert (await c.statechain_key("dao.x")).endswith("\\u0000"), "six characters of text, not a NUL"
    for body in (b'{"blocks":[{"hash":"h","memo":"a\\u0000"}],"total":1}', b'{"blocks":[{"hash":"h","extra":NaN}],"total":1}'):
        reply["v"] = body
        await refused(lambda: c.chain(a))
    reply["v"] = b'[{"id":"1","message":"x\\u0000"}]'
    await refused(lambda: c.chat_messages(proof))
    # an error's text is stored too
    reply["v"] = lambda request: httpx.Response(400, content=b"bad \x00 block")
    with pytest.raises(XeError) as e:
        await c.balances(a)
    assert e.value.status == 400 and "\x00" not in str(e.value)

    # only a 2xx is an answer: a redirect is not followed, is not a success, and is not the node's refusal
    for status in (301, 302, 307, 308):
        reply["v"] = lambda request, s=status: httpx.Response(s, headers={"location": "http://elsewhere/"}, json={"balances": {"XE": 5}})
        for call in (lambda: c.balances(a), lambda: c.directory(a), lambda: c.chat_send({}), lambda: c.directory_register({})):
            with pytest.raises(XeError) as e:
                await call()
            assert e.value.status == status and e.value.transient
    # a read that comes back empty is not "nothing there"; a 404 is; a null that was found is not
    for body in (b"", b"null"):
        reply["v"] = body
        for call in (lambda: c.balances(a), lambda: c.keyset_of(a), lambda: c.directory(a), lambda: c.chain(a), lambda: c.pending_for(a)):
            await refused(call, "malformed")
    await refused(lambda: c.statechain_key("dao.x"), "malformed")   # reply is still `null`: found, and not a value
    reply["v"] = lambda request: httpx.Response(404, json={"error": "not found"})
    assert await c.balances(a) == {} and await c.keyset_of(a) is None and await c.directory(a) is None
    assert await c.statechain_key("dao.x") is None

    # a chain that was there a moment ago and is a 404 now is not an account with no chain
    def vanishing(request):
        offset = int(request.url.params["offset"])
        if offset == 0:
            return httpx.Response(200, json={"blocks": [{"hash": f"b{i}"} for i in range(int(request.url.params["limit"]))], "total": 5 * PAGE})
        return httpx.Response(404, json={"error": "account not found"})
    reply["v"] = vanishing
    for call in (lambda: c.chain_end(a), lambda: c.tip(a), lambda: c.full_chain(a)):
        await refused(call, "malformed")

    # compressed: asked not to be, and refused unread if it is, since the size cap counts what is sent
    seen = []

    def squeezed(request):
        seen.append(request.headers.get("accept-encoding"))
        return httpx.Response(200, headers={"content-encoding": "gzip"}, content=gzip.compress(b'{"balances":{"XE":5}}'))
    reply["v"] = squeezed
    await refused(lambda: c.balances(a), "compressed")
    assert seen == ["identity"]
    got = []
    with pytest.raises(XeError) as e:
        async for item in c.chat_events({"account": a}):
            got.append(item)
    # the name of the encoding is the answerer's text, and is not in the message (XE-14195)
    assert "compressed" in e.value.message and "gzip" not in e.value.message and got == []

    # a value too long to put in a URL fails as the node failing, like everything else
    reply["v"] = b"{}"
    await refused(lambda: c.statechain_key("k" * 100_000))
    await refused(lambda: c.chat_messages({**proof, "challenge": "0" * 100_000}))
    await refused(lambda: c.statechain_key("dao.\ud800"), "not text")   # and so does one that is not text

    # bounds on what is stored or sent back: a keyset's threshold, the tip's hash, /ready, the chat challenge
    k1, k2 = "ab" * 32, "cd" * 32
    for ks in ({"keys": [k1, k2], "threshold": 0}, {"keys": [k1, k2], "threshold": 3}, {"keys": [], "threshold": 0}):
        reply["v"] = json.dumps(ks).encode()
        await refused(c.dao_keyset, "threshold")
        if ks["keys"]:
            await refused(lambda: c.keyset_of(a), "threshold")
    reply["v"] = json.dumps({"keys": [k1.upper(), k2], "threshold": 2, "address": "x"}).encode()
    assert await c.keyset_of(a) == {"keys": [k1, k2], "threshold": 2, "address": "x"}
    # an account that is not multisig has no keyset, and reads as None: what is returned as a keyset has
    # its keys and its threshold, and half of one is refused (XE-14157)
    # however the node spells "none": the fields left out, null, or the zero values of an empty one
    for none in (b'{"address":"x"}', b'{}', b'{"address":"x","threshold":null}', b'{"keys":[],"threshold":0}',
                 b'{"keys":null,"threshold":0}', b'{"address":"x","threshold":0}', b'{"keys":[]}'):
        reply["v"] = none
        assert await c.keyset_of(a) is None
        await refused(c.dao_keyset)   # the DAO's own keyset is never "none"
    for half, why in ((b'{"keys":["%s"]}' % k1.encode(), "threshold is missing"), (b'{"threshold":1}', "keys is missing"),
                      (b'{"keys":null,"threshold":1}', "keys")):
        reply["v"] = half
        await refused(lambda: c.keyset_of(a), why)
    reply["v"] = json.dumps({"index": 4, "timestamp": 9, "hash": "h" * 10_000}).encode()
    await refused(c.statechain_tip, "hash")
    reply["v"] = json.dumps({"balances": {"XE": 2**63}}).encode()
    await refused(lambda: c.balances(a), "range")
    reply["v"] = json.dumps({"balances": {"XE": 2**63 - 1}}).encode()
    assert await c.balances(a) == {"XE": 2**63 - 1}, "the most a BIGINT column holds"
    # /ready: the status, and the flags and counts of a short status object; no text from the answer (XE-14223)
    reply["v"] = json.dumps({"status": "ready", "padding": "x" * xc.MAX_READY_BYTES}).encode()
    assert await c.ready() == (True, {"http_status": 200})
    reply["v"] = b'{"status":"ready","synced":true,"peers":4,"lag":2.5,"detail":{"a":1},"big":%d}' % 2**70
    assert await c.ready() == (True, {"synced": True, "peers": 4, "http_status": 200})
    reply["v"] = b'{"http_status":204}'
    assert await c.ready() == (True, {"http_status": 200}), "and the status is the one the answer came with"
    reply["v"] = json.dumps({"challenge": "ab" * xc.MAX_CHALLENGE_CHARS}).encode()
    await refused(c.chat_challenge, "challenge")
    for network in (5, ["x"], {"a": 1}):
        reply["v"] = json.dumps({"network_id": network}).encode()
        await refused(c.node, "network_id")
    await c.aclose()

    # the chat stream: the same parser, so an item that cannot be kept is skipped and costs only itself;
    # and a whole line past the cap is refused when it arrives in one piece, as when it never ends
    class Stream(httpx.AsyncByteStream):
        def __init__(self, parts):
            self.parts = parts

        async def __aiter__(self):
            for p in self.parts:
                yield p

    async def read(parts):
        s = _node(lambda request: httpx.Response(200, stream=Stream(parts)))
        got = []
        try:
            async for item in s.chat_events({"account": a}):
                got.append(item)
        finally:
            await s.aclose()
        return got
    lines = [b'data: {"id":"1"}\n', b'data: {"id":"2","message":"x\\u0000"}\n', b'data: {"id":"3","message":"\\udc00"}\n',
             b'data: {"id":"4","n":NaN}\n', b'data: {"id":"5"}\n']
    assert [i["id"] for i in await read(lines)] == ["1", "5"]
    with pytest.raises(XeError) as e:
        await read([b'data: {"id":"1"}\n', b'data: {"id":"2","message":"' + b"x" * xc.MAX_STREAM_LINE + b'"}\n', b'data: {"id":"3"}\n'])
    assert "exceeds" in e.value.message


async def test_the_chain_walk_and_the_tip_do_not_take_the_nodes_total_on_trust():
    """XE-2353: `total` is a claim. The walk ends on a short page only; the tip is the block at the end
    of the chain or the read is refused."""
    import httpx

    from xe.client import PAGE, XeError
    chain = [{"hash": f"b{i}", "previous": f"b{i - 1}" if i else "0"} for i in range(2 * PAGE + 7)]
    claim = {}

    def serve(request):
        offset, limit = int(request.url.params["offset"]), int(request.url.params["limit"])
        return httpx.Response(200, json={"blocks": chain[offset:offset + limit], "total": claim["total"]})
    c = _node(serve)
    for total in (len(chain), 0, 1, PAGE, 10**12):
        claim["total"] = total
        assert [b["hash"] for b in await c.full_chain("a")] == [b["hash"] for b in chain], total
    claim["total"] = len(chain)
    count, last = await c.chain_end("a")
    assert count == len(chain) and last["hash"] == chain[-1]["hash"] and await c.tip("a") == chain[-1]["hash"]
    for total in (0, 1, PAGE, len(chain) - 1, len(chain) + 1, 10**12):
        claim["total"] = total
        for call in (c.chain_end, c.tip):
            with pytest.raises(XeError) as e:
                await call("a")
            assert e.value.status == 0 and "malformed" in e.value.message, total
    await c.aclose()
    # an account with no chain: an empty page, or 404
    c = _node(lambda request: httpx.Response(200, json={"blocks": [], "total": 0}))
    assert await c.chain_end("a") == (0, None) and await c.tip("a") == "0" and await c.full_chain("a") == []
    await c.aclose()
    c = _node(lambda request: httpx.Response(404, json={"error": "account not found"}))
    assert await c.chain_end("a") == (0, None) and await c.tip("a") == "0"
    await c.aclose()
    c = _node(lambda request: httpx.Response(503, json={"error": "syncing"}))
    with pytest.raises(XeError) as e:
        await c.tip("a")
    assert e.value.status == 503, "a node that cannot answer is not an empty account"
    await c.aclose()


async def test_a_built_block_is_given_up_only_when_another_final_block_stands_on_its_parent():
    """XE-2043: `placed` reads the block's parent and what follows it, in one page. It says `lost` only for
    a final block standing where this one was built to stand, and concludes nothing from a chain that does
    not hold the parent there: a node one block behind shows a final tip that is not the parent too."""
    from dao import chainops
    from xe.client import XeError

    class Node:
        def __init__(self, blocks):
            self.blocks = blocks

        async def chain(self, account, offset=0, limit=1000):
            if self.blocks is None:
                raise XeError(404, "account not found")
            return {"blocks": self.blocks[offset:offset + limit], "total": len(self.blocks)}

    def b(h, final=True):
        return {"hash": h, "finalized": final}
    p0, p1 = b("p0"), b("p1")
    ours = {"account": "a" * 64, "hash": "ours", "previous": "p1", "at": 2}
    first = {"account": "a" * 64, "hash": "ours", "previous": "0", "at": 0}   # built to open the account
    for block, below in ((ours, [p0, p1]), (first, [])):
        for after, want in (([], "open"), ([b("ours")], "landed"), ([b("ours", False)], "pending"),
                            ([b("x", False)], "pending"), ([b("x")], "lost"), ([b("x"), b("y")], "lost"),
                            ([b("ours"), b("y", False)], "landed")):
            assert await chainops.placed(Node(below + after), block) == want, (block["at"], after)
    assert await chainops.placed(Node(None), first) == "open", "an account the node has no chain for"
    # the parent is not where the block was built on it: behind, unknown, or another chain altogether
    for served in ([p0], [], None, [p0, b("q")], [p0, b("q"), b("x")], [b("p1"), b("p0"), b("x")]):
        with pytest.raises(XeError) as e:
            await chainops.placed(Node(served), ours)
        assert e.value.status == 0 and "nothing is concluded" in e.value.message, served


async def test_nothing_is_signed_for_a_network_the_node_has_not_named():
    """A process that came up while the node was down has no network id. A block signed for "" is one no
    node takes, and a stored settlement signed that way would be offered for ever: the node is asked
    again, and nothing is signed until it answers."""
    from dao import chainops
    from xe.client import XeError
    from xe.encoding import Block
    kp = KeyPair.generate()
    answers = iter(["", "xe-test"])

    async def refresh_node():
        ctx.node.network_id = next(answers)
    ctx = SimpleNamespace(node=SimpleNamespace(network_id="", pow_difficulty=0), refresh_node=refresh_node)

    def receive():
        return Block(type="receive", account=kp.address, previous="0", balance=1, timestamp=1, asset="XE", source="1" * 64)
    with pytest.raises(XeError) as e:
        await chainops.signed(ctx, receive(), kp)
    assert e.value.transient
    done = await chainops.signed(ctx, receive(), kp)
    assert done.hash and done.signature and ctx.node.network_id == "xe-test"


def test_an_envelope_from_a_node_is_an_envelope_or_a_chaterror():
    from xe.chat import MAX_MESSAGE_BYTES, ChatError, Envelope, new_envelope, verify_envelope
    kp = KeyPair.generate()
    env = new_envelope(kp, "b" * 64, "hello", 0)
    back = Envelope.from_json(json.loads(json.dumps(env.to_json())))
    assert back == env
    verify_envelope(back, 0)
    assert Envelope.from_json({}).to_json() == Envelope.from_json({k: None for k in env.to_json()}).to_json()
    good = env.to_json()
    hostile = [None, [], "x", 5, True, [good]]
    for key in ("id", "from", "pub_key", "to", "signature", "message"):
        hostile += [{**good, key: v} for v in (5, 1.5, [], {}, True, "a" * (MAX_MESSAGE_BYTES + 1))]
    for key in ("timestamp", "pow_nonce"):
        hostile += [{**good, key: v} for v in ("1", 1.5, True, -1, 2**64, [], {})]
    hostile.append({**good, "timestamp": 2**63})
    # text that is not text, or that no text column takes: an envelope's fields are stored as they come
    for key in ("id", "from", "pub_key", "to", "signature", "message"):
        hostile += [{**good, key: "a\x00b"}, {**good, key: "a\ud800b"}]
    for item in hostile:
        with pytest.raises(ChatError):
            Envelope.from_json(item)


# ---- XE-2073: a seat is one identity ---------------------------------------------------------------------

def test_a_schedule_c_whose_seats_share_an_identity_is_refused_at_load(tmp_path):
    import shutil

    import yaml

    from dao.config import seat_conflicts
    cfg = load_config(ROOT / "config")
    assert seat_conflicts(cfg) == [], "the committed Schedule C loads"
    k1, k2 = KeyPair.generate(), KeyPair.generate()

    def conflicts(humans=(), agents=(), company=None):
        c = load_config(ROOT / "config")
        c.schedule_c["human_seats"] = [{"id": i, "kind": "member", "public_key": k} for i, k in humans]
        c.schedule_c["agent_seats"] = [{"id": i, "role": r, "account": a} for i, r, a in agents]
        c.signer_accounts = company or {}
        return seat_conflicts(c)

    assert conflicts([("a", k1.pub_key_hex), ("b", k2.pub_key_hex), ("c", ""), ("d", "")],
                     [("x", "Research", "c" * 64), ("y", "Legal & Compliance", ""), ("z", "Ops", "")]) == [], \
        "blank keys and accounts are seats not yet filled"
    cases = {
        "seat id": conflicts([("a", k1.pub_key_hex), ("a", k2.pub_key_hex)]),
        "seat id, by case": conflicts([("a", ""), ("A", "")]),
        "public key": conflicts([("a", k1.pub_key_hex), ("b", k1.pub_key_hex.upper())]),
        "agent id": conflicts(agents=[("x", "Research", ""), ("x", "Legal", "")]),
        "agent page": conflicts(agents=[("x", "Legal & Compliance", ""), ("y", "legal and compliance", "")]),
        "agent page against agent id": conflicts(agents=[("research", "Ops", ""), ("y", "Research", "")]),
        "human id against agent id": conflicts([("x", "")], [("x", "Research", "")]),
        "human id against agent page": conflicts([("research", "")], [("x", "Research", "")]),
        "agent account": conflicts(agents=[("x", "A", "c" * 64), ("y", "B", "C" * 64)]),
        "agent account against a human's": conflicts([("a", k1.pub_key_hex)], [("x", "Ops", k1.address.upper())]),
        "key that is not a key": conflicts([("a", "zz")]),
        "blank id": conflicts([("", k1.pub_key_hex)]),
        "id the seat page cannot spell": conflicts([("Founder A", "")]),
        "agent id that is not a handle": conflicts(agents=[("x/y", "Research", "")]),
        "agent with no role, so no page": conflicts(agents=[("x", "", "")]),
        "agent account that is not an account": conflicts(agents=[("x", "Research", "zz")]),
        "human seat on a company account": conflicts([("a", k1.pub_key_hex)], company={"dao": k1.address.upper()}),
        "agent seat on a company account": conflicts(agents=[("x", "Research", "c" * 64)], company={"fee": "c" * 64}),
    }
    for what, found in cases.items():
        assert len(found) == 1, (what, found)
    assert conflicts([("a", k1.pub_key_hex)], company={"dao": "d" * 64, "fee": "d" * 64}) == [], \
        "one company account under two names is not a seat conflict"
    # a seat entry that is not a seat at all is the same refusal, not a traceback of its own kind
    from dao.config import require_distinct_seats
    for bad in ([{"kind": "member"}], ["founder-a"], [{"id": 7}], [{"id": "a", "may": 5}]):
        c = load_config(ROOT / "config")
        c.schedule_c["human_seats"] = bad
        with pytest.raises(ValueError) as e:
            require_distinct_seats(c)
        assert "schedule_c.yaml" in str(e.value), bad
    # and the load itself refuses it, which is the path the API, the worker and the CLI all take
    d = tmp_path / "config"
    shutil.copytree(ROOT / "config", d)
    doc = yaml.safe_load((d / "schedule_c.yaml").read_text())
    doc["human_seats"][1]["id"] = doc["human_seats"][0]["id"]
    (d / "schedule_c.yaml").write_text(yaml.safe_dump(doc))
    with pytest.raises(ValueError) as e:
        load_config(d)
    assert "schedule_c.yaml" in str(e.value) and doc["human_seats"][0]["id"] in str(e.value)


# ---- XE-2210: the snapshot preview is the vote's derivation ------------------------------------------------

class _Released:
    """The session a read route is given, as far as the route uses it after its rows are read (XE-4318)."""

    def __init__(self):
        self.released = 0

    async def commit(self):
        self.released += 1


async def test_the_snapshot_preview_answers_what_the_vote_would(monkeypatch):
    """For every kind of account and any snapshot time, including time zero, the public preview of a
    proposal returns what `portal.eligibility` derives for a vote on it: one function, two callers, given
    the same proposal, so the same pinned rules and the same snapshot."""
    from dao.api import public
    from dao.chainops import SNAPSHOT_LEAD_NS
    from dao.services import portal
    T = 100 * H
    holder, agent, excluded, poor, stranger = "a" * 64, "b" * 64, "c" * 64, "d" * 64, "e" * 64

    def held(xe, xusd):
        return [{"type": "receive", "asset": "XE", "balance": xe, "timestamp": T - 10 * H, "hash": f"x{xe}", "source": "early"},
                {"type": "receive", "asset": "XUSD", "balance": xusd, "timestamp": T - 9 * H, "hash": f"u{xusd}", "source": "early"}]
    chain = _Lattice({holder: held(1, 7_000_000), agent: held(2, 8_000_000), excluded: held(3, 9_000_000), poor: held(9_000_000, 4)},
                     {"early": {"timestamp": T - 20 * H}})
    rules = {"participating_wallet": {"min_balance_micro_xe": 1_000_000}, "weight_asset": "XUSD", "excluded_accounts": [excluded],
             "agents": {}}
    # the rules have changed since the proposals below opened: today's weigh XE and exclude nobody. A preview
    # of a proposal is under the rules that proposal pinned, as its votes are, not under these
    today = {"participating_wallet": {"min_balance_micro_xe": 1}, "weight_asset": "XE", "excluded_accounts": [], "agents": {}}
    ctx = SimpleNamespace(chain=chain, config=SimpleNamespace(pinned_rules=lambda: today, agent_accounts={agent}))
    proposals = {f"{i:064x}": SimpleNamespace(rules=rules, opened_at=at + SNAPSHOT_LEAD_NS, status="open") for i, at in enumerate((T, T - 15 * H, 0))}

    async def get(db, h):
        if h not in proposals:
            raise HTTPException(404, "proposal not found")
        return proposals[h]
    monkeypatch.setattr(portal, "get", get)
    n = 0
    for account in (holder, agent, excluded, poor, stranger):
        for h, pr in proposals.items():
            n += 1
            request = SimpleNamespace(client=SimpleNamespace(host=f"10.0.0.{n}"))
            preview = await public.snapshot(request, account.upper(), ctx, _Released(), proposal=h)
            snap, reasons, participating, weight = await portal.eligibility(ctx, pr, account, account in ctx.config.agent_accounts)
            assert preview == {"account": account, **snap, "weight": weight, "participating": participating,
                               "not_participating_because": reasons}, (account[0], h[-1])
            assert preview["at"] == pr.opened_at - SNAPSHOT_LEAD_NS
    request = SimpleNamespace(client=SimpleNamespace(host="10.0.1.1"))
    at_T, _, at_zero = proposals
    p = await public.snapshot(request, holder, ctx, _Released(), proposal=at_T)
    assert p["balance"] == p["weight"] == 7_000_000 and p["participating"], "the asset that proposal weighs, not today's"
    assert (await public.snapshot(request, poor, ctx, _Released(), proposal=at_T))["not_participating_because"] == ["balance below the participation minimum at snapshot"]
    assert (await public.snapshot(request, excluded, ctx, _Released(), proposal=at_T))["weight"] == 0
    zero = await public.snapshot(request, holder, ctx, _Released(), proposal=at_zero)
    assert zero["at"] == 0 and not zero["exists"] and not zero["participating"], "a snapshot at time zero is time zero, not now"
    # with no proposal named: a proposal opened now, under the rules it would pin, at the snapshot it would take
    now = await public.snapshot(request, holder, ctx, _Released(), proposal=None)
    assert abs(now["at"] - (time.time_ns() - SNAPSHOT_LEAD_NS)) < 60 * 10**9 and now["balance"] == now["weight"] == 1
    assert (await public.snapshot(request, excluded, ctx, _Released(), proposal=None))["weight"] == 3, "today's rules exclude nobody"
    with pytest.raises(HTTPException) as e:
        await public.snapshot(request, holder, ctx, _Released(), proposal="f" * 64)
    assert e.value.status_code == 404
    for bad in ("xyz", "a" * 63, "a" * 65):
        with pytest.raises(HTTPException) as e:
            await public.snapshot(request, bad, ctx, _Released(), proposal=at_T)
        assert e.value.status_code == 400


# ---- XE-2213: no command takes a secret on its command line -------------------------------------------------

def test_no_command_takes_a_secret_as_an_argument():
    import re

    import typer
    from typer.testing import CliRunner

    from dao import cli
    secretish = re.compile(r"seed|pass|secret|priv|mnemonic", re.I)
    seen = []

    def walk(cmd, path):
        for name, sub in getattr(cmd, "commands", {}).items():
            walk(sub, path + [name])
        for p in cmd.params:
            seen.append((" ".join(path), p.name))
            assert not secretish.search(p.name) and not any(secretish.search(o) for o in p.opts), (path, p.name, p.opts)
    walk(typer.main.get_command(cli.app), [])
    assert ("sign", "digest") in seen and ("keys init", "path") in seen, "the walk reached the commands"
    src = (ROOT / "dao" / "cli.py").read_text()
    assert src.count("getpass.getpass(") == 1 and src.count("os.environ") == 1, "one function reads a secret"
    # and the commands still work, from the environment
    kp = KeyPair.generate()
    runner = CliRunner()
    digest_hex = "ab" * 32
    r = runner.invoke(cli.app, ["sign", "--digest", digest_hex], env={"XE_SEED": kp.seed.hex()})
    assert r.exit_code == 0, r.output
    out = json.loads(r.output)
    assert out["pub_key"] == kp.pub_key_hex and out["signature"] == kp.sign_hex(bytes.fromhex(digest_hex))
    assert kp.seed.hex() not in r.output
    for argv in (["sign", "--digest", digest_hex, "--seed", kp.seed.hex()], ["keys", "show", "--passphrase", "x"],
                 ["sign-request", "xe-dao/vote/v1", "{}", "--seed", kp.seed.hex()]):
        r = runner.invoke(cli.app, argv)
        assert r.exit_code == 2, (argv, r.output)


async def test_a_block_signature_from_a_key_no_longer_in_the_keyset_is_counted_nowhere(monkeypatch):
    """XE-2713: whether a block has its signatures is one count, of signatures from keys in the keyset
    now, asked by every site that sends a block to the chain or decides why the chain refused it."""
    from dao.services import sessions
    k1, k2, gone = (KeyPair.generate() for _ in range(3))
    block_hash = "ab" * 32

    def sig(kp):
        return kp.sign_hex(bytes.fromhex(block_hash))
    ks = {"keys": [k1.pub_key_hex, k2.pub_key_hex], "threshold": 2}
    s = SimpleNamespace(id="s1", status="signing", not_before=0, block={"index": 3, "prev_hash": "tip"}, block_hash=block_hash,
                        block_signatures=[{"public_key": gone.pub_key_hex, "signature": sig(gone)}])
    submitted = []

    async def nothing(*a, **k):
        return None

    async def keyset():
        return ks

    async def tip():
        return {"hash": "tip", "index": 2, "timestamp": 1}

    # a submit is two halves (`attempt` asks the node, `settle` records what came of it); the first is the send
    async def attempt(ctx_, db_, s_):
        submitted.append(len(s_.block_signatures))
        return sessions.Outcome("deferred", "not sent: this is a test")

    async def settle(ctx_, db_, s_, out):
        return s_
    order = []

    async def asked(db_):
        order.append("pause?")

    async def appended(db_, kind, *a, **k):
        order.append(kind)
    ctx = SimpleNamespace(chain=SimpleNamespace(dao_keyset=keyset, statechain_tip=tip), events=SimpleNamespace(append=appended))
    monkeypatch.setattr(sessions, "require_unpaused", asked)
    monkeypatch.setattr(sessions, "require_executable", lambda ctx_, s_: None)   # what the session writes is XE-4131's rule
    monkeypatch.setattr(sessions, "attempt", attempt)
    monkeypatch.setattr(sessions, "settle", settle)
    # two signatures on the block, one of them from a key rotated out: two of two is not met, at any site
    await sessions.sign(ctx, None, s, k1.pub_key_hex, sig(k1), "member:a")
    assert len(s.block_signatures) == 2 and not submitted
    # a signature kept and not sent is checked against the pause a last time once the log head is held (XE-4126)
    assert order == ["pause?", "pause?", "session.block_signed", "pause?"]
    assert not sessions.signatures_met(s, ks) and not sessions.ready_to_submit(s, ks)
    assert await sessions._moved_under(ctx, s) == "session.keyset_moved"
    # the second live signature is the one that sends it
    await sessions.sign(ctx, None, s, k2.pub_key_hex, sig(k2), "member:b")
    assert submitted == [3] and sessions.ready_to_submit(s, ks) and await sessions._moved_under(ctx, s) is None


# ---- XE-3709: the log is replayed once at a time, whoever asks ----------------------------------

async def test_callers_that_arrive_during_a_replay_wait_for_it_and_share_its_answer(monkeypatch):
    import asyncio

    from dao.log import EventLog
    replays, release = [], asyncio.Event()

    async def slow(db, expected_signer=""):
        replays.append(expected_signer)
        await release.wait()
        return {"ok": True, "count": len(replays), "head": "h", "first_error": None}

    monkeypatch.setattr(EventLog, "verify", staticmethod(slow))
    monkeypatch.setattr(EventLog, "_verify_cache", None)
    monkeypatch.setattr(EventLog, "_verify_lock", None)
    waiting = [asyncio.ensure_future(EventLog.verify_cached(None, "k")) for _ in range(25)]
    for _ in range(5):
        await asyncio.sleep(0)   # every caller has found the cache empty and is at the lock or past it
    assert len(replays) == 1
    release.set()
    out = await asyncio.gather(*waiting)
    assert len(replays) == 1 and [o["count"] for o in out] == [1] * 25
    assert [o["cached"] for o in out].count(False) == 1   # the one that ran it; the rest took its answer
    # the answer is kept from when the replay ended, so one that took most of the minute is not stale at once
    assert (await EventLog.verify_cached(None, "k"))["cached"] is True and len(replays) == 1
    monkeypatch.setattr(EventLog, "_verify_cache", (EventLog._verify_cache[0] - EventLog.VERIFY_CACHE_S - 1, out[0]))
    assert (await EventLog.verify_cached(None, "k"))["cached"] is False and len(replays) == 2



# ---- XE-3160 and the value-by-value reports after it: a schedule value is in its domain at load -----------

def test_a_schedule_value_outside_its_domain_is_refused_at_load(tmp_path):
    import copy
    import shutil

    import yaml

    from dao.config import (FEE_ACTIONS, SCHEDULE_B_DOMAINS, SEAT_RIGHTS, require_valid_schedules, schedule_b_faults,
                            schedule_c_faults)
    from dao.services import fees, resolutions, sessions
    from dao.worker_schedule import job_table
    from xe.keys import is_valid_public_key
    cfg = load_config(ROOT / "config")
    assert schedule_b_faults(cfg) == [] and schedule_c_faults(cfg) == [], "the committed schedules load"

    def section_of(doc, path):
        for name in (path.split(".") if path else ()):
            doc = doc[name]
        return doc
    # every value the committed Schedule B carries has a domain, the prose the code only publishes included
    for path, domain in SCHEDULE_B_DOMAINS.items():
        loose = {k for k, v in section_of(cfg.schedule_b, path).items() if not isinstance(v, dict)} - set(domain)
        assert loose == set(), (path, loose)
    walked = {k for d in SCHEDULE_B_DOMAINS.values() for k in d} | {p.rpartition(".")[2] for p in SCHEDULE_B_DOMAINS if p}

    def names(doc):
        return set(doc) | {k for v in doc.values() if isinstance(v, dict) for k in names(v)}
    assert names(cfg.schedule_b) <= walked, "every name the committed Schedule B uses is one the tables have"
    # the vocabularies are the ones the code acts on
    assert tuple(f"due_{a}" for a in FEE_ACTIONS) == fees.DUE
    assert {resolutions.SIGN_RIGHT, sessions.SIGN_RIGHT, "pause", "operational_review"} <= set(SEAT_RIGHTS)

    def b_faults(path, key, value):
        c = load_config(ROOT / "config")
        c.schedule_b = copy.deepcopy(c.schedule_b)
        section_of(c.schedule_b, path)[key] = value
        return schedule_b_faults(c)
    outside = {
        "health_check_minutes": (0, 61, 1.5, True), "directory_reregister_minutes": (0, 30, True),
        "daily_note_hour_utc": (-1, 24, 8.0), "weekly_review_weekday": (0, 8), "weekly_review_hour_utc": (-1, 24),
        "anchor_weekday": (0, 8), "anchor_hour_utc": (-1, 24), "monthly_report_day": (0, 29, 31),
        "open_vote_days": (0, -21, 366), "protocol_parameter_days": (0, 366), "upgrade_timelock_hours": (-1, 8761),
        "upgrade_timelock_status": ("Active", "on", "active "),
        "initial_hours": (0, -72), "extension_days": (0, -7), "public_post_within_hours": (0, -4),
        "grounds": ([], [""], ["a", "a"], "exploit_or_irreversible_loss"),
        "fee_micro_xe": (-1, 2**64, 1.0, True), "fee_on_quorum": ("Refund", "refnud", "", "due_refund"),
        "fee_below_quorum": ("Burn", "keep"), "quorum_wallets": (0, -1, True),
        "pass_mark_fraction": (1, 1.5, -0.1, float("nan"), True), "weight_asset": ("XUSD", "xe", ""),
        "excluded_accounts": (["zz"], "f" * 64, ["f" * 64, "f" * 64]),
        "min_balance_micro_xe": (-1, 2**64), "must_exist_before_open": ("yes", 1, 0), "exclude_agent_accounts": ("no", 1),
        "stipend_micro_xe": (-1, 2**64), "max_weight_share": (1.01, -0.01, 5, float("nan"), True),
        "count_toward_quorum": ("false", 0),
        "version": (0, -1, True), "agent_budget_micro_xe": (-1, 2**64, True),
        "agents_decide": ([""], ["a", "a"], "membership", [["a"]], [" "]),
        "agents_do_not_decide": ([""], ["a", "a"], "membership", [None]),
        "members_fraction": (0, 1.5, -0.1, float("nan"), True),
    }
    prose = ("member", "specialist_agents", "reserved_matters", "other_oa_rules", "specialists", "reserved_matter")
    outside.update({key: ("", "  ", 8, True) for key in prose})
    assert {k for d in SCHEDULE_B_DOMAINS.values() for k in d} == set(outside), "every checked value is walked"
    for path, domain in SCHEDULE_B_DOMAINS.items():
        for key in domain:
            for value in (None, [1], {"a": 1}, 8.5) + (() if key in prose else ("8",)) + outside[key]:
                found = b_faults(path, key, value)
                assert len(found) == 1 and found[0].startswith((f"{path}." if path else "") + f"{key} "), (path, key, value, found)
            # absent is the code's default, which is in the domain
            c = load_config(ROOT / "config")
            c.schedule_b = copy.deepcopy(c.schedule_b)
            del section_of(c.schedule_b, path)[key]
            assert schedule_b_faults(c) == [], (path, key)
    # a section that is not a mapping, and an armed timelock that runs for no time
    for path in filter(None, SCHEDULE_B_DOMAINS):
        c = load_config(ROOT / "config")
        c.schedule_b = copy.deepcopy(c.schedule_b)
        head, _, leaf = path.rpartition(".")
        (section_of(c.schedule_b, head) if head else c.schedule_b)[leaf] = None
        assert any(f.startswith(f"{path} must be a mapping") for f in schedule_b_faults(c)), path
    assert len(b_faults("windows", "upgrade_timelock_status", "active")) == 0
    c = load_config(ROOT / "config")
    c.schedule_b = copy.deepcopy(c.schedule_b)
    c.schedule_b["windows"].update(upgrade_timelock_status="active", upgrade_timelock_hours=0)
    assert len(schedule_b_faults(c)) == 1
    # the edges of each cadence domain are values the scheduler can turn into a time
    for hour, weekday, day, minutes in ((0, 1, 1, 1), (23, 7, 28, 60)):
        cadence = {"daily_note_hour_utc": hour, "weekly_review_weekday": weekday, "weekly_review_hour_utc": hour,
                   "anchor_weekday": weekday, "anchor_hour_utc": hour, "monthly_report_day": day,
                   "health_check_minutes": minutes, "directory_reregister_minutes": min(minutes, 29)}
        c = load_config(ROOT / "config")
        c.schedule_b = {**c.schedule_b, "cadence": cadence}
        assert schedule_b_faults(c) == []
        assert job_table(SimpleNamespace(config=c))["health"]["every_s"] == minutes * 60

    # Schedule C, read as written
    def c_faults(edit):
        c = load_config(ROOT / "config")
        c.schedule_c = copy.deepcopy(c.schedule_c)
        edit(c.schedule_c)
        return schedule_c_faults(c)

    def human(**over):
        return lambda d: d["human_seats"][0].update(over)

    def agent(**over):
        return lambda d: d["agent_seats"][0].update(over)
    cases = {
        "kind by case": human(kind="Member"), "kind with a space": human(kind="member "), "kind unknown": human(kind="director"),
        "kind that is not a word": human(kind=True),
        "may as one word": human(may="pause"), "may with an unknown right": human(may=["pause", "sign_everything"]),
        "may by case": human(may=["Pause"]), "may repeated": human(may=["pause", "pause"]),
        "agent class by case": agent(**{"class": "Specialist"}), "agent status unknown": agent(status="live"),
        "agent optional as a word": agent(optional="yes"), "agent scopes as one word": agent(tool_scopes="chain.read"),
        "agent scope outside the glossary": agent(tool_scopes=["chain.read", "tx.sign"]),
        "mode unknown": lambda d: d.update(mode="Ensemble"),
    }
    identity = "01" + "00" * 31    # a point, and one no signature verifies under
    if not is_valid_public_key(bytes.fromhex(identity)):
        cases["key no signature can verify under"] = human(public_key=identity)
    for what, edit in cases.items():
        assert len(c_faults(edit)) == 1, (what, c_faults(edit))
    assert c_faults(human(public_key=KeyPair.generate().pub_key_hex.upper(), may=[], kind="officer")) == []
    # and the load itself refuses, naming every fault in both files: the path the API, the worker and the CLI take
    d = tmp_path / "config"
    shutil.copytree(ROOT / "config", d)
    b, sc = (yaml.safe_load((d / f).read_text()) for f in ("schedule_b.yaml", "schedule_c.yaml"))
    b["open_vote"]["fee_on_quorum"], b["cadence"]["daily_note_hour_utc"] = "refnud", 24
    sc["human_seats"][0]["kind"] = "Member"
    (d / "schedule_b.yaml").write_text(yaml.safe_dump(b))
    (d / "schedule_c.yaml").write_text(yaml.safe_dump(sc))
    with pytest.raises(ValueError) as e:
        load_config(d)
    for words in ("schedule_b.yaml: cadence.daily_note_hour_utc", "schedule_b.yaml: open_vote.fee_on_quorum", "schedule_c.yaml: human seat 1"):
        assert words in str(e.value), words
    require_valid_schedules(cfg)


def test_a_schedule_name_the_file_does_not_have_is_refused_at_load(tmp_path):
    """XE-14108 / XE-14107. A schedule key that is present is one the file has, or the config does not
    load. A misspelt key was read by nothing and its default stood in for what the members wrote: `knd:
    member` made a founder an officer, `treasuy:` left the treasury out of the vote exclusion, `open_vot:`
    ran every vote on the code's defaults. Asserted for every mapping in both schedules, by adding a name
    and by misspelling each one the committed file carries."""
    import copy
    import shutil

    import yaml

    from dao.config import SCHEDULE_B_DOMAINS, SCHEDULE_C_KEYS, schedule_b_faults, schedule_c_faults

    def section_of(doc, path):
        for name in (path.split(".") if path else ()):
            doc = doc[name]
        return doc

    def b_faults(edit):
        c = load_config(ROOT / "config")
        c.schedule_b = copy.deepcopy(c.schedule_b)
        edit(c.schedule_b)
        return schedule_b_faults(c)

    def c_faults(edit):
        c = load_config(ROOT / "config")
        c.schedule_c = copy.deepcopy(c.schedule_c)
        edit(c.schedule_c)
        return schedule_c_faults(c)

    def misspell(section, key):
        section[key + "x"] = section.pop(key)
    cfg = load_config(ROOT / "config")
    # Schedule B: every mapping, the top of the file included
    for path in SCHEDULE_B_DOMAINS:
        where = f"{path}." if path else ""
        for name in ("knd", "", 7, None, True):
            found = b_faults(lambda d, p=path, n=name: section_of(d, p).update({n: 1}))
            assert len(found) == 1 and found[0].startswith(f"{where}{str(name)!r} is not a name"), (path, name, found)
        for key in list(section_of(cfg.schedule_b, path)):
            found = b_faults(lambda d, p=path, k=key: misspell(section_of(d, p), k))
            assert len(found) == 1 and found[0].startswith(f"{where}{key + 'x'!r} is not a name"), (path, key, found)
    # Schedule C: the top, the repository, the accounts, and every seat of both kinds
    mappings = {
        "": lambda d: [d], "repository.": lambda d: [d["repository"]], "accounts.": lambda d: [d["accounts"]],
        "human seat": lambda d: d["human_seats"], "agent seat": lambda d: d["agent_seats"],
    }
    assert {w.rstrip(".") for w in mappings} == set(SCHEDULE_C_KEYS)
    for where, find in mappings.items():
        for i, section in enumerate(find(cfg.schedule_c)):
            assert set(section) <= set(SCHEDULE_C_KEYS[where.rstrip(".")]), (where, i)
            said = where if where.endswith(".") or not where else f"{where} {i + 1} ({section['id']}): "
            found = c_faults(lambda d, f=find, i=i: f(d)[i].update(knd="member"))
            assert found == [f for f in found if f.startswith(f"{said}'knd' is not a name")] and len(found) == 1, (where, i, found)
            for key in section:
                if key == "id":
                    continue      # a seat with no id is refused before this, as a seat that is not one
                found = c_faults(lambda d, f=find, i=i, k=key: misspell(f(d)[i], k))
                assert any(f.startswith(f"{said}{key + 'x'!r} is not a name") for f in found), (where, i, key, found)
    # a fourth account name is read by nothing, and the published prose has a shape
    assert len(c_faults(lambda d: d["accounts"].update(claim_pool="c" * 64))) == 1
    assert c_faults(lambda d: d.update(repository="https://github.com/xeprotocol/dao")) == ["repository must be a mapping"]
    for bad in ("Grok", [""], ["a", "a"], [7]):
        assert len(c_faults(lambda d, v=bad: d.update(model_candidates=v))) == 1, bad
    # and the load itself refuses, naming each: the path the API, the worker and the CLI take
    d = tmp_path / "config"
    shutil.copytree(ROOT / "config", d)
    b, sc = (yaml.safe_load((d / f).read_text()) for f in ("schedule_b.yaml", "schedule_c.yaml"))
    b["open_vot"] = b.pop("open_vote")
    b["agents_do_not_decide"] = "membership"
    sc["human_seats"][0]["knd"] = sc["human_seats"][0].pop("kind")
    sc["accounts"]["treasuy"] = sc["accounts"].pop("treasury")
    (d / "schedule_b.yaml").write_text(yaml.safe_dump(b))
    (d / "schedule_c.yaml").write_text(yaml.safe_dump(sc))
    with pytest.raises(ValueError) as e:
        load_config(d)
    for words in ("schedule_b.yaml: 'open_vot' is not a name", "schedule_b.yaml: agents_do_not_decide is 'membership'",
                  "'knd' is not a name", "schedule_c.yaml: accounts.'treasuy' is not a name"):
        assert words in str(e.value), words


# ---- XE-10452: a per-client allowance is counted against the client's network ------------------------------

def test_a_client_allowance_is_keyed_by_network_not_by_one_address(monkeypatch):
    from dao import ratelimit
    from dao.ratelimit import INBOX, Buckets, Held, client_ip, client_key, enforce_ip
    assert client_key("203.0.113.9") == "203.0.113.9"
    assert client_key("::ffff:203.0.113.9") == "203.0.113.9", "an IPv4 client over a dual-stack socket is that IPv4 client"
    assert client_key("2001:db8:1:2::1") == client_key("2001:DB8:1:2:ffff:ffff:ffff:ffff") == "2001:db8:1:2::/64"
    assert client_key("2001:db8:1:3::1") != client_key("2001:db8:1:2::1")
    assert client_key("fe80::1%eth0") == "fe80::/64"
    assert client_key("unknown") == "unknown" and client_key("testclient") == "testclient"

    def req(host):
        return SimpleNamespace(client=SimpleNamespace(host=host))
    assert client_ip(req("2001:db8:1:2::9")) == "2001:db8:1:2::/64" and client_ip(SimpleNamespace(client=None)) == "unknown"
    # both things that are counted per client take that key: the buckets and the held streams
    monkeypatch.setattr(ratelimit, "_buckets", Buckets())
    for i in range(INBOX.ip.burst):
        enforce_ip(req(f"2001:db8:1:2::{i + 1:x}"), INBOX)
    with pytest.raises(HTTPException) as e:
        enforce_ip(req("2001:db8:1:2:aaaa::1"), INBOX)
    assert e.value.status_code == 429
    enforce_ip(req("2001:db8:1:3::1"), INBOX)       # the next /64 is someone else
    held = Held("streams", per_ip=2, total=10)
    first = held.take(req("2001:db8:9::1"))
    held.take(req("2001:db8:9::2"))
    with pytest.raises(HTTPException) as e:
        held.take(req("2001:db8:9::3"))
    assert e.value.status_code == 429
    held.release(first)
    held.take(req("2001:db8:9::4"))


# ---- XE-4267: a stream that is behind reads on until it has caught up --------------------------------------

async def test_the_event_stream_reads_a_backlog_without_waiting_between_full_batches(monkeypatch):
    import asyncio

    from dao import ratelimit
    from dao.api import public
    monkeypatch.setattr(ratelimit, "_buckets", ratelimit.Buckets())
    behind = 2 * public.STREAM_BATCH + 50
    reads = []

    class Session:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

    async def head(s):
        return SimpleNamespace(index=behind, hash="0" * 64)

    async def since(s, after, limit=200, public_only=True):
        reads.append((after, limit))
        return [SimpleNamespace(index=i) for i in range(after + 1, min(after + limit, behind) + 1)]

    async def connected():
        return False
    monkeypatch.setattr(public, "session", lambda: Session())
    monkeypatch.setattr(public.EventLog, "head", staticmethod(head))
    monkeypatch.setattr(public.EventLog, "since", staticmethod(since))
    monkeypatch.setattr(public, "event_to_dict", lambda ev: {"index": ev.index})
    subscribed = []
    ctx = SimpleNamespace(events=SimpleNamespace(subscribe=subscribed.append, unsubscribe=subscribed.remove))
    request = SimpleNamespace(headers={"accept": "text/event-stream"}, client=SimpleNamespace(host="203.0.113.7"),
                              is_disconnected=connected)
    resp = await public.events_stream(request, ctx, after=0)
    stream = resp.body_iterator

    async def entries(n):
        got = []
        async for item in stream:
            if item["event"] == "entry":
                got.append(int(item["id"]))
            if len(got) == n:
                return got
    # the wait for news is three seconds; a reader this far behind is not made to take it between batches
    got = await asyncio.wait_for(entries(behind), timeout=2)
    assert got == list(range(1, behind + 1))
    assert reads == [(0, public.STREAM_BATCH), (public.STREAM_BATCH, public.STREAM_BATCH), (2 * public.STREAM_BATCH, public.STREAM_BATCH)]
    await stream.aclose()
    assert subscribed == [] and public.STREAMS._n == 0, "the slot and the subscription go with the stream"


# ---- XE-3405: a set op carries a value --------------------------------------------------------------------

def test_a_set_op_with_no_value_is_refused_at_every_intake():
    from xe.statechain import StateChainError, StateOp
    missing = {"action": "set", "key": "dao.x"}
    with pytest.raises(StateChainError):
        StateOp.from_json(missing)
    with pytest.raises(StateChainError):
        StateOp("set", "dao.x", None).validate()
    with pytest.raises(HTTPException) as e:
        normalise_ops([{"action": "set", "key": "dao.ok", "value": 1}, missing])
    assert e.value.status_code == 400 and "requires a value" in e.value.detail
    # a value given as null is a value, as on the node; a delete carries none
    assert StateOp.from_json({**missing, "value": None}).value == "null"
    assert normalise_ops([{**missing, "value": None}]) == [{**missing, "value": "null"}]
    assert normalise_ops([{"action": "delete", "key": "dao.x"}]) == [{"action": "delete", "key": "dao.x"}]


async def test_the_chat_store_read_takes_the_most_a_node_can_hold_and_no_more(monkeypatch):
    """XE-11882: /chat/messages is a whole store in one answer. A full store of large envelopes is past the
    general bound and inside this read's own, which is still a bound."""
    import httpx

    from xe import client as xc
    assert xc.MAX_CHAT_STORE_BYTES >= xc.CHAT_STORE_ENVELOPES * 6 * 8192 > xc.MAX_BODY_BYTES
    env = {"id": "e", "message": "<" * 8192}
    full = ("[" + ",".join(json.dumps(env).replace("<", "\\u003c") for _ in range(xc.CHAT_STORE_ENVELOPES)) + "]").encode()
    assert xc.MAX_BODY_BYTES < len(full) <= xc.MAX_CHAT_STORE_BYTES, "the largest store an honest node serves"
    c = _node(lambda request: httpx.Response(200, content=full))
    got = await c.chat_messages({"account": "a"}, 0)
    assert len(got) == xc.CHAT_STORE_ENVELOPES and got[0]["message"] == "<" * 8192
    with pytest.raises(xc.XeError) as e:    # the same bytes on any other read are still refused
        await c.balances("a")
    assert e.value.status == 0 and "exceeds" in e.value.message
    await c.aclose()
    monkeypatch.setattr(xc, "MAX_CHAT_STORE_BYTES", 4096)
    c = _node(lambda request: httpx.Response(200, content=full))
    with pytest.raises(xc.XeError) as e:
        await c.chat_messages({"account": "a"}, 0)
    assert e.value.status == 0 and "exceeds 4096" in e.value.message
    await c.aclose()


# ---- XE-4285: the keyfile is put in place whole and private, by every writer ---------------------------------

def test_the_keyfile_is_created_private_and_replaced_whole_by_both_writers(tmp_path, monkeypatch):
    import os
    import stat

    from dao import signer as signer_mod
    modes = []
    real_open, real_replace = os.open, os.replace

    def spy_open(path, flags, mode=0o777, **kw):
        fd = real_open(path, flags, mode, **kw)
        if str(path).endswith(".tmp"):
            modes.append((stat.S_IMODE(os.fstat(fd).st_mode), bool(flags & os.O_EXCL)))
        return fd
    monkeypatch.setattr(signer_mod.os, "open", spy_open)
    monkeypatch.setattr(signer_mod.os, "chmod", lambda *a, **k: pytest.fail("the mode is set at creation, not after"))
    old_umask = os.umask(0o022)   # the umask the report's window needs: a plain create would be 0644
    try:
        p = tmp_path / "keys" / "signer.json"
        Signer.init_keyfile(p, "correct horse battery staple")
        first = p.read_bytes()
        Signer.add_key(p, "correct horse battery staple", "agent:research")
    finally:
        os.umask(old_umask)
    assert modes == [(0o600, True), (0o600, True)], "both writers create the file 0600 and new, before a byte is written"
    assert stat.S_IMODE(p.stat().st_mode) == 0o600 and p.read_bytes() != first
    assert [f.name for f in p.parent.iterdir()] == ["signer.json"], "nothing is left beside it"
    # a write that fails part-way leaves the keyfile that was there, for both writers
    before = p.read_bytes()

    def no_space(src, dst):
        raise OSError(28, "No space left on device")
    monkeypatch.setattr(signer_mod.os, "replace", no_space)
    with pytest.raises(SignerError, match="could not be written"):
        Signer.add_key(p, "correct horse battery staple", "agent:second")
    q = tmp_path / "keys" / "other.json"
    with pytest.raises(SignerError, match="could not be written"):
        Signer.init_keyfile(q, "correct horse battery staple")
    assert p.read_bytes() == before and not q.exists()
    assert [f.name for f in p.parent.iterdir()] == ["signer.json"]
    monkeypatch.setattr(signer_mod.os, "replace", real_replace)
    assert sorted(k.name for k in Signer.load(p, "correct horse battery staple").infos()) == ["agent:research", "dao", "fee", "harness"]
    # and there is one writer: no other write of the keyfile's path in the module
    src = Path(signer_mod.__file__).read_text()
    assert "write_text" not in src and src.count("os.replace(") == 1 and src.count("_write_keyfile(path, contents, passphrase)") == 2


# ---- XE-3974: a use of a company key that was refused is counted where it was refused ----------------------

def test_a_refused_use_of_a_key_is_counted_by_the_signer_and_logged_once_per_spell():
    import asyncio

    from dao import worker as worker_mod
    s = Signer({"fee": KeyPair.generate()}, {"fee": {"block.receive"}})
    s.keypair("fee", "block.receive")
    assert s.denials() == [], "an allowed use is not a refusal"
    for name, scope in (("fee", "block.burn"), ("fee", "block.burn"), ("dao", "chat.send")):
        with pytest.raises(SignerError):
            s.keypair(name, scope)
    with pytest.raises(SignerError):
        s.sign("fee", "event.sign", b"x")     # `sign` goes through `keypair`
    want = [{"key": "dao", "scope": "chat.send", "count": 1}, {"key": "fee", "scope": "block.burn", "count": 2},
            {"key": "fee", "scope": "event.sign", "count": 1}]
    logged = []

    class Events:
        async def append(self, db, kind, actor, payload, **kw):
            logged.append((kind, actor, payload, kw))
    w = worker_mod.Worker.__new__(worker_mod.Worker)
    w.ctx = SimpleNamespace(signer=s, events=Events())

    def check():
        w._signer_denials_logged(asyncio.run(w._log_signer_denials(None)))
    check()
    assert logged == [("signer.denied", "harness", {"denied": want}, {"public": True})]
    assert s.denials() == [], "the count starts again"
    # the same refusals going on are not an entry per check; a change in what is refused is
    for _ in range(3):
        for name, scope in (("fee", "block.burn"), ("dao", "chat.send"), ("fee", "event.sign")):
            with pytest.raises(SignerError):
                s.keypair(name, scope)
        check()
    assert len(logged) == 1
    with pytest.raises(SignerError):
        s.keypair("fee", "block.send.refund")
    check()
    # the entry for the change counts every refusal since the last entry, the three checks in between included
    assert len(logged) == 2 and logged[1][2] == {"denied": [
        {"key": "dao", "scope": "chat.send", "count": 3}, {"key": "fee", "scope": "block.burn", "count": 3},
        {"key": "fee", "scope": "block.send.refund", "count": 1}, {"key": "fee", "scope": "event.sign", "count": 3}]}
    check()   # nothing refused and nothing uncounted: nothing logged, and the spell is over
    assert len(logged) == 2
    for _ in range(2):
        with pytest.raises(SignerError):
            s.keypair("fee", "block.send.refund")
        check()
    assert len(logged) == 3 and logged[2][2] == {"denied": [{"key": "fee", "scope": "block.send.refund", "count": 1}]}
    check()   # the spell stops with a refusal no entry has counted: a closing entry counts it
    assert len(logged) == 4 and logged[3][2] == {"denied": [{"key": "fee", "scope": "block.send.refund", "count": 1}], "ended": True}
    check()
    assert len(logged) == 4
    # XE-14106: a check that did not commit has recorded nothing, so it has counted nothing off. The
    # refusals it read are still the signer's, the spell is where it was, and the next check that does
    # commit writes the entry the failed one would have: none lost, none twice.
    for name, scope in (("fee", "block.burn"), ("fee", "block.burn")):
        with pytest.raises(SignerError):
            s.keypair(name, scope)
    before = (s.denials(), w._denied_before, dict(w._denied_carried))
    read = asyncio.run(w._log_signer_denials(None))          # appended inside a transaction that then rolls back
    assert len(logged) == 5 and (s.denials(), w._denied_before, w._denied_carried) == before
    assert read[2] is not w._denied_carried
    logged.pop()                                             # the rollback takes the entry with it
    with pytest.raises(SignerError):
        s.keypair("fee", "block.burn")                       # refused between the failed check and the next
    check()
    assert len(logged) == 5 and logged[4][2] == {"denied": [{"key": "fee", "scope": "block.burn", "count": 3}]}
    assert s.denials() == []
    # a refusal after the reading and before the commit is not counted off with it
    with pytest.raises(SignerError):
        s.keypair("fee", "block.burn")
    read = asyncio.run(w._log_signer_denials(None))
    with pytest.raises(SignerError):
        s.keypair("fee", "block.burn")
    w._signer_denials_logged(read)
    assert s.denials() == [{"key": "fee", "scope": "block.burn", "count": 1}]
    # and the health job is the one caller: it counts off only after its commit
    src = Path(worker_mod.__file__).read_text()
    job = src[src.index("async def job_health"):src.index("async def _seal_legacy_log")]
    assert job.index("await db.commit()") < job.index("self._signer_denials_logged(") and src.count("signer.forget(") == 1


# ---- XE-6656 / XE-4124 / XE-5982: what a signed request may carry is settled before anything hashes it -----

def test_a_signed_request_carries_no_float_no_deep_nesting_and_a_u64_nonce():
    from pydantic import ValidationError

    from dao.auth import MAX_PAYLOAD_DEPTH, payload_fault
    ok = {"a": [1, "x", None, True, {"b": [2**70, -1]}]}
    assert payload_fault(ok) is None
    for bad in ({"a": 1.5}, {"a": [float("nan")]}, {"a": {"b": float("inf")}}, {"a": 1.0}, {"a": [1e21]}):
        assert payload_fault(bad) == "numbers in a signed payload are integers", bad
    deep = cur = {}
    for _ in range(MAX_PAYLOAD_DEPTH - 1):
        cur["a"] = {}
        cur = cur["a"]
    assert payload_fault(deep) is None, "exactly the depth allowed"
    cur["a"] = [[]]
    assert "nested deeper" in payload_fault(deep)
    very = cur = []
    for _ in range(200_000):      # far past the interpreter's recursion limit: walked, not recursed
        cur.append([])
        cur = cur[0]
    assert "nested deeper" in payload_fault({"a": very})
    base = {"timestamp": 1, "pub_key": "ab" * 32, "signature": "cd" * 64}
    for bad in ({"a": 1.5}, {"a": very}, {"a": float("nan")}):
        with pytest.raises(ValidationError):
            SignedRequest(payload=bad, **base)
    assert SignedRequest(payload=ok, **base).payload == ok
    # the nonce is a u64 or the request is refused: no value is taken modulo 2**64 (XE-5982)
    for nonce in (0, 1, 2**64 - 1):
        assert SignedRequest(pow_nonce=nonce, **base).pow_nonce == nonce
    for nonce in (-1, 2**64, 2**64 + 5, -(2**64) + 5):
        with pytest.raises(ValidationError):
            SignedRequest(pow_nonce=nonce, **base)
    # and the digest itself has no spelling for a non-finite number, whoever calls it
    for bad in (float("nan"), float("inf"), {"a": [float("-inf")]}):
        with pytest.raises(ValueError):
            canonical_json(bad)
    assert canonical_json({"b": 1, "a": 1.5}) == b'{"a":1.5,"b":1}'


def test_a_body_nested_past_the_parser_is_the_callers_error_on_any_route():
    import asyncio

    from dao import main
    from xe.statechain import StateChainError, strict_loads
    req = SimpleNamespace(url=SimpleNamespace(path="/v1/anything"), method="POST")
    resp = asyncio.run(main.recursion_error(req, RecursionError("maximum recursion depth exceeded")))
    assert resp.status_code == 400 and json.loads(resp.body) == {"error": "the request is nested too deeply", "status": 400}
    assert RecursionError in main.app.exception_handlers
    # an op value whose text is nested past the parser is refused as a value (XE-5877)
    deep = "[" * 200_000 + "]" * 200_000
    with pytest.raises(StateChainError):
        strict_loads(deep)
    with pytest.raises(HTTPException) as e:
        normalise_ops([{"action": "set", "key": "dao.x", "value": deep}])
    assert e.value.status_code == 400


# ---- XE-2775: a statement that failed on the value it was given is recognised by what the driver reports ---

def test_a_data_error_is_recognised_however_the_driver_wraps_it():
    from sqlalchemy.exc import DBAPIError, DataError, InterfaceError

    from dao.main import callers_data

    class Pg(Exception):
        def __init__(self, sqlstate):
            self.sqlstate = self.pgcode = sqlstate

    def wrapped(orig, cls=DBAPIError):
        return cls("SELECT 1", {}, orig)
    assert callers_data(wrapped(Pg("22021"))), "a NUL in text, as Postgres reports it through asyncpg"
    assert callers_data(wrapped(Pg("22003"))) and callers_data(wrapped(Pg("22001")))
    assert callers_data(wrapped(Exception("x"), DataError))
    assert callers_data(wrapped(OverflowError("int too big"))) and callers_data(wrapped(ValueError("bad")))
    outer = Exception("adapted")
    outer.__cause__ = ValueError("invalid input for query argument $1")
    assert callers_data(wrapped(outer, InterfaceError)), "the driver's encode error sits one link down"
    for ours in (Pg("42P01"), Pg("40001"), Pg("08006"), Pg(None), Exception("x"), RuntimeError("pool closed")):
        assert not callers_data(wrapped(ours)), ours
    loop = Exception("a")
    loop.__cause__ = loop
    assert not callers_data(wrapped(loop)), "a chain that does not end is not followed for ever"


# ---- XE-2870 / XE-3350: what the node client keeps and whom it talks to -------------------------------------

async def test_no_read_keeps_a_number_that_is_not_finite_and_the_client_ignores_ambient_proxies(monkeypatch):
    import httpx

    from xe import client as xc
    reads = (lambda c: c.balances("a"), lambda c: c.chain("a"), lambda c: c.statechain_tip(),
             lambda c: c.node(), lambda c: c.block("h"), lambda c: c.chat_messages({"account": "a"}, 0),
             lambda c: c.chat_send({}), lambda c: c.pending_for("a"), lambda c: c.chat_challenge())
    for body in (b'{"XE":1e400}', b'[{"amount":-1e400}]', b'{"a":{"b":[1e999]}}', b"1e400", b'{"XE":NaN}', b"[Infinity]"):
        c = _node(lambda request: httpx.Response(200, content=body))
        for read in reads:
            with pytest.raises(xc.XeError) as e:
                await read(c)
            assert e.value.status == 0, body
        await c.aclose()
    assert xc._parse(b'{"a":1.5,"b":1e2}') == {"a": 1.5, "b": 100.0}, "a finite float is a number like any other"
    # the proxy variables of the environment are not read: not for routing, and not to fail on
    for var in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"):
        monkeypatch.setenv(var, "http://proxy.invalid:3128")
    monkeypatch.setenv("NO_PROXY", "[::1],localhost")
    c = xc.XeClient("https://node.invalid")
    assert c._client.trust_env is False
    await c.aclose()


# ---- XE-12620: the network is the deployment's, and what the node says is compared with it ------------------

def test_the_node_identity_has_a_network_only_when_the_node_reports_the_configured_one():
    import asyncio

    from dao import chainops
    from dao.context import Context, NodeIdentity
    from xe.client import XeError

    def ctx_for(reported, expected):
        ctx = Context.__new__(Context)
        ctx.chain = SimpleNamespace(node=_const({"network_id": reported, "id": "n1", "version": "xe/1"}))
        ctx.settings = SimpleNamespace(xe_network_id=expected, xe_node_url="http://node")
        ctx.node = NodeIdentity()
        return ctx
    for reported, expected, got in (("testnet-0005", "testnet-0005", "testnet-0005"), ("mainnet", "testnet-0005", ""),
                                    ("testnet-0006", "testnet-0005", ""), ("testnet-0005", "", ""), ("", "", ""),
                                    ("TESTNET-0005", "testnet-0005", "")):
        ctx = ctx_for(reported, expected)
        node = asyncio.run(ctx.refresh_node())
        assert node.network_id == got and node.node_id == "n1", (reported, expected)
        if not got:   # and with no network, no company key signs a block: the site every block passes through
            with pytest.raises(XeError):
                asyncio.run(chainops.signed(ctx, SimpleNamespace(hash=""), KeyPair.generate()))
    # a node that was right and now says otherwise loses the identity it had
    ctx = ctx_for("testnet-0005", "testnet-0005")
    asyncio.run(ctx.refresh_node())
    ctx.chain = SimpleNamespace(node=_const({"network_id": "mainnet", "id": "n1"}))
    assert asyncio.run(ctx.refresh_node()).network_id == ""
    from dao.settings import Settings
    assert Settings.model_fields["xe_network_id"].default == "", "there is no network a deployment is for by default"


# ---- XE-6119: a public figure that costs a pass over stored history is worked out once an interval ---------

async def test_the_public_uptime_figure_is_computed_once_an_interval_however_many_ask(monkeypatch):
    import asyncio
    import inspect

    from dao.api import public
    from dao.services import records
    calls = []

    async def counted(ctx, db):
        calls.append(1)
        await asyncio.sleep(0.01)
        return {"n": len(calls)}
    monkeypatch.setattr(records, "uptime_30d", counted)
    monkeypatch.setattr(records, "_uptime_shown", None)
    monkeypatch.setattr(records, "_uptime_lock", asyncio.Lock())
    got = await asyncio.gather(*(records.uptime_30d_shown(None, None) for _ in range(25)))
    assert calls == [1] and got == [{"n": 1}] * 25, "twenty-five requests at once, one pass over the checks"
    assert await records.uptime_30d_shown(None, None) == {"n": 1}
    monkeypatch.setattr(records, "_uptime_shown", (time.monotonic() - records.UPTIME_SHOWN_S - 1, {"n": 1}))
    assert await records.uptime_30d_shown(None, None) == {"n": 2} and await records.uptime_30d_shown(None, None) == {"n": 2}
    assert len(calls) == 2
    assert "uptime_30d_shown(" in inspect.getsource(public.health) and "uptime_30d(" not in inspect.getsource(public.health)
    assert records.UPTIME_SHOWN_S <= 600, "no staler than the cadence the figure moves on"


# ---- XE-11401: a path that exists answers for the method it takes -------------------------------------------

def test_the_two_session_opening_paths_read_with_get_say_which_method_they_take():
    import asyncio

    from dao.api import members
    for path in ("registry", "anchor"):
        with pytest.raises(HTTPException) as e:
            asyncio.run(members.get_session(request=None, sid=path, ctx=None, db=None))
        assert e.value.status_code == 405 and e.value.headers == {"Allow": "POST"}, path
    posts = {r.path for r in members.router.routes if "POST" in r.methods}
    assert {"/v1/members/sessions/registry", "/v1/members/sessions/anchor"} <= posts, "and those are the two there are"


# ---- XE-4592 / XE-10109 / XE-10320: what the client keeps from the node is typed and bounded ---------------

async def test_a_state_chain_value_a_long_identity_and_a_keyset_of_non_keys_are_refused():
    import httpx

    from xe import client as xc
    answers = {}
    c = _node(lambda request: httpx.Response(answers["now"][0], **answers["now"][1]))

    async def refused(call):
        with pytest.raises(xc.XeError) as e:
            await call()
        assert e.value.status == 0
    # the node's {key, value} envelope is opened before the value is judged: a null inside it is a null
    answers["now"] = (200, {"content": b'{"key":"dao.x","value":null}'})
    await refused(lambda: c.statechain_key("dao.x"))
    answers["now"] = (200, {"content": b'{"key":"dao.x","value":{"a":1}}'})
    assert await c.statechain_key("dao.x") == {"a": 1}
    answers["now"] = (200, {"content": b"null"})
    await refused(lambda: c.statechain_key("dao.x"))
    answers["now"] = (404, {"content": b'{"error":"not found"}'})
    assert await c.statechain_key("dao.x") is None, "only a 404 is 'not set'"
    # a body that cannot be encoded is never sent, and what leaves the client is an XeError
    sent = []
    c2 = _node(lambda request: sent.append(request) or httpx.Response(200, content=b"{}"))
    await refused(lambda: c2.submit_statechain_block(SimpleNamespace(to_wire=lambda: '{"a":"\ud800"}')))
    assert sent == []
    await c2.aclose()
    # the node's names are bounded; a keyset holds keys, and a bounded number of them
    for name in ("network_id", "id", "version"):
        answers["now"] = (200, {"content": json.dumps({name: "x" * (xc.MAX_IDENT_CHARS + 1)}).encode()})
        await refused(c.node)
    answers["now"] = (200, {"content": json.dumps({"network_id": "x" * xc.MAX_IDENT_CHARS}).encode()})
    assert len((await c.node())["network_id"]) == xc.MAX_IDENT_CHARS
    key = "ab" * 32
    for keys in (["zz" * 32], [key, "ab"], [key + "00"], [key, 5], [f"{i:064x}" for i in range(xc.MAX_KEYSET_KEYS + 1)], ["<script>" + "a" * 56]):
        answers["now"] = (200, {"content": json.dumps({"keys": keys, "threshold": 1}).encode()})
        await refused(c.dao_keyset)
    answers["now"] = (200, {"content": json.dumps({"keys": [key.upper()], "threshold": 1}).encode()})
    assert await c.dao_keyset() == {"keys": [key], "threshold": 1}
    await c.aclose()


# ---- XE-8855: a read that failed is not "not written" ------------------------------------------------------

async def test_a_registry_read_that_failed_says_so_and_is_not_reported_as_absent(monkeypatch):
    from dao.services import records
    from xe.client import XeError
    answers = {}

    async def statechain_key(key):
        if isinstance(answers["now"], Exception):
            raise answers["now"]
        return answers["now"]
    ctx = SimpleNamespace(chain=SimpleNamespace(statechain_key=statechain_key))
    for answer, present in ((XeError(0, "ReadTimeout"), None), (XeError(503, "busy"), None), (None, False), ({"entity": "x"}, True)):
        monkeypatch.setattr(records, "_public_reads", {})
        answers["now"] = answer
        read = await records.onchain_registry(ctx)
        assert records.registry_present(read) is present, answer
        assert ("error" in read) == isinstance(answer, Exception) and ("value" in read) != ("error" in read)
    import inspect

    from dao.api import legal
    assert "registry_present" in inspect.getsource(legal), "the legal identifier asks the three-way question"


# ---- XE-2475 / XE-12010 / XE-3711 / XE-11041: rules held where a run cannot reach them ---------------------

def test_identity_is_asked_again_rows_are_locked_before_the_log_and_the_browser_signer_refuses_what_it_cannot_sign():
    import inspect

    from dao import main, worker
    from dao.services import resolutions
    # the node's identity is not read once at start: the worker asks with each health check, the API on a timer
    assert "await self.ctx.refresh_node()" in inspect.getsource(worker.Worker.job_health)
    lifespan = inspect.getsource(main)
    assert "await asyncio.sleep(NODE_REFRESH_S if ctx.node.network_id else NODE_RETRY_S)" in lifespan
    assert "await ctx.refresh_node()" in lifespan
    assert 0 < main.NODE_RETRY_S < main.NODE_REFRESH_S <= 600, "and sooner while the network is not confirmed"
    # withdraw takes the session row before its first append, the order every other writer takes them in
    src = inspect.getsource(resolutions.withdraw)
    assert src.index("sessions.get(db, r.session_id, lock=True)") < src.index("ctx.events.append(")
    # signer.js: hex is hex or it is refused; an integer the page cannot hold exactly is not signed
    js = (Path(main.__file__).parent / "static" / "signer.js").read_text(encoding="utf-8")
    assert "/^(?:[0-9a-f]{2})*$/.test(h)" in js and "Number.isSafeInteger(v)" in js and "Number.isInteger(v)" in js
    assert "buf.set(pub, 8 + digest.length)" in js, "and the proof of work is over the digest and the signer's key (XE-11360)"


# ---- the sibling sweep of 15 November: each rule at the sites the first fixes had not reached ---------------

def test_a_deployment_that_has_not_confirmed_who_it_is_accepts_no_signed_request():
    """XE-12620 / XE-2068. Until the node has answered with the configured network the addressee's network
    is empty, and a signature over an empty network (or an empty account) names no deployment: it verified
    at every deployment in that state. Refused before the signature is looked at, on every signed route,
    since every one of them comes through `verify_signed`."""
    from dao.auth import signing_target
    kp, ts, payload = KeyPair.generate(), time.time_ns(), {"choice": "for"}
    for to in ({"dao": "d" * 64, "network": ""}, {"dao": "", "network": "xe-test"}, {"dao": "", "network": ""}):
        sig = kp.sign_hex(signing_target(DOMAIN_VOTE, to, payload, ts))
        req = SignedRequest(payload=payload, timestamp=ts, pub_key=kp.pub_key_hex, signature=sig)
        ctx = SimpleNamespace(config=SimpleNamespace(accounts={"dao": to["dao"]}), node=SimpleNamespace(network_id=to["network"]))
        with pytest.raises(HTTPException) as e:
            verify_signed(ctx, req, DOMAIN_VOTE)
        assert e.value.status_code == 503, to


async def test_the_dao_key_signs_nothing_for_a_node_whose_network_is_not_confirmed():
    """XE-12620. The rule was held at the block and the directory entry; a chat read proof and a chat
    envelope are the DAO key's signature too, and the node they are made for is the one not yet known."""
    import inspect

    from xe.client import XeError

    from dao.services import inbox

    class Never:
        def __getattr__(self, name):
            raise AssertionError(f"{name} was reached")
    ctx = SimpleNamespace(node=SimpleNamespace(network_id=""), chain=Never(), signer=Never())
    with pytest.raises(XeError) as e:
        await inbox.read_proof(ctx)
    assert e.value.status == 0 and "not confirmed" in e.value.message
    src = inspect.getsource(inbox.flush_outbox)
    assert src.index("confirmed_network(ctx)") < src.index('ctx.signer.keypair("dao", "chat.send")')
    src = inspect.getsource(inbox.read_proof)
    assert src.index("confirmed_network(ctx)") < src.index("ctx.chain.chat_challenge()") < src.index("ctx.signer.keypair(")


def test_what_the_door_refuses_in_a_payload_the_cli_refuses_to_sign_and_the_startup_lint_reads_the_pages():
    import inspect

    from dao import cli, main
    src = inspect.getsource(cli.sign_request)
    assert src.index("payload_fault(p)") < src.index("signing_target("), "XE-6656: refused before it is signed"
    assert "lint_public_copy(ctx.config, public_template_prose())" in inspect.getsource(main.lifespan), "XE-5986"


async def test_what_the_client_keeps_of_a_keyset_and_a_balance_is_bounded_field_by_field():
    """XE-10109 / XE-10320. The keys were bounded and the fields beside them were not: a megabyte under any
    other name in the keyset answer, or a balance of ten thousand assets, was stored with every snapshot."""
    import httpx

    from xe import client as xc
    from xe.client import XeError
    reply = {}
    c = _node(lambda request: httpx.Response(200, content=reply["v"]))
    k1, k2, a = "ab" * 32, "cd" * 32, "a" * 64
    big = "x" * (xc.MAX_IDENT_CHARS + 1)
    reply["v"] = json.dumps({"keys": [k1, k2], "threshold": 1, "address": "x", "note": big, "nested": {"a": [1] * 100},
                             "list": [big], big: 1, "flag": True, "n": 3, "none": None}).encode()
    assert await c.keyset_of(a) == {"keys": [k1, k2], "threshold": 1, "address": "x", "flag": True, "n": 3, "none": None}
    reply["v"] = json.dumps({"address": "x", "note": big, "nested": {"deep": big}}).encode()
    assert await c.keyset_of(a) is None, "an account that is not multisig has no keyset to carry anything"
    reply["v"] = json.dumps({"balances": {f"A{i}": 1 for i in range(xc.MAX_BALANCE_ASSETS)}}).encode()
    assert len(await c.balances(a)) == xc.MAX_BALANCE_ASSETS
    for bad in ({f"A{i}": 1 for i in range(xc.MAX_BALANCE_ASSETS + 1)}, {big: 1}):
        reply["v"] = json.dumps({"balances": bad}).encode()
        with pytest.raises(XeError) as e:
            await c.balances(a)
        assert e.value.status == 0
    # the one read sized to a whole store has the time its size needs, and no other read does (XE-11882)
    import inspect
    assert "deadline_s=CHAT_STORE_DEADLINE_S" in inspect.getsource(xc.XeClient.chat_messages)
    assert xc.CHAT_STORE_DEADLINE_S > xc.REQUEST_DEADLINE_S and inspect.getsource(xc.XeClient).count("deadline_s=CHAT_STORE_DEADLINE_S") == 1


def test_schedule_c_names_accounts_or_leaves_them_empty_and_a_fee_fits_the_ledger():
    """XE-2073's rule at the fields it had not reached: an `accounts` entry that is no account is one every
    signed request is addressed to and nothing can match, and a fee past 2^63 - 1 is one the ledger's
    column refuses on the first proposal. Refused at load, by name."""
    import copy

    from dao.config import require_valid_schedules, schedule_b_faults, schedule_c_faults

    def c_faults(edit):
        c = load_config(ROOT / "config")
        c.schedule_c = copy.deepcopy(c.schedule_c)
        edit(c.schedule_c)
        return c, schedule_c_faults(c)
    assert c_faults(lambda d: None)[1] == []
    for value in ("d" * 64, "D" * 64, "", None):
        assert c_faults(lambda d, v=value: d["accounts"].update(dao=v))[1] == [], value
    for value in ("d" * 63, "xyz", 7, ["d" * 64], {"a": 1}, True):
        c, faults = c_faults(lambda d, v=value: d["accounts"].update(dao=v))
        assert len(faults) == 1 and faults[0].startswith("accounts.dao is "), value
        with pytest.raises(ValueError, match="accounts.dao"):
            require_valid_schedules(c)
    assert c_faults(lambda d: d.update(accounts=["d" * 64]))[1] == ["accounts must be a mapping of names to accounts"]
    assert any(f.startswith("tool_scopes must be a mapping") for f in c_faults(lambda d: d.update(tool_scopes=["chain.read"]))[1])
    for fee, ok in ((0, True), (2**63 - 1, True), (2**63, False), (2**64 - 1, False)):
        c = load_config(ROOT / "config")
        c.schedule_b = copy.deepcopy(c.schedule_b)
        c.schedule_b["open_vote"]["fee_micro_xe"] = fee
        assert (schedule_b_faults(c) == []) is ok, fee


def test_the_agent_vote_rule_says_the_share_and_the_quorum_rule_the_config_holds():
    """XE-5988 / XE-3160. The one statement of the rule truncated the share (0.29 read "28%"), failed the
    page when the share was left to its default, and said "never count toward quorum" whatever the two
    flags said. It says what the tally does."""
    import copy

    from dao.ui import templates

    def said(**agents):
        c = load_config(ROOT / "config")
        c.schedule_b = copy.deepcopy(c.schedule_b)
        for k, v in agents.pop("wallet", {}).items():
            c.schedule_b["open_vote"]["participating_wallet"][k] = v
        for k, v in agents.items():
            if v is None:
                c.schedule_b["open_vote"]["agents"].pop(k, None)
            else:
                c.schedule_b["open_vote"]["agents"][k] = v
        return str(templates.env.get_template("_rules.html").module.agent_vote(c))
    for share, shown in ((0.29, "29%"), (0.07, "7%"), (0.125, "12.5%"), (1, "100%"), (0, "0%"), (None, "1%")):
        assert f"at most {shown} of the weight" in said(max_weight_share=share), share
    assert "never count toward quorum" in said()
    assert "never count toward quorum" in said(count_toward_quorum=True), "excluded as agent accounts all the same"
    assert "never count toward quorum" in said(wallet={"exclude_agent_accounts": False})
    assert "count toward quorum as any wallet does" in said(count_toward_quorum=True, wallet={"exclude_agent_accounts": False})
    page = (ROOT / "dao/templates/proposal.html").read_text(encoding="utf-8")
    assert '"%g"|format(p.rules.pass_mark_fraction * 100)' in page and "* 100)|int" not in page


def test_rows_are_written_before_the_log_head_is_taken():
    """XE-12010. A writer that appends between two row writes holds the head and then waits for a row, and
    a writer that holds that row waits for the head. Re-deriving votes did this once per vote, with a node
    read in between; closing a proposal did it with the fee row."""
    import inspect

    from dao.services import portal
    src = inspect.getsource(portal.rederive_stale)
    assert src.count("ctx.events.append(") == 1 and src.index("await db.flush()") < src.index("ctx.events.append(")
    assert src.index("await eligibility(") < src.index("await db.flush()"), "and the node is asked before either is held"
    src = inspect.getsource(portal._close)
    assert src.index("fee.state = ") < src.index("await db.flush()") < src.index("ctx.events.append(")


async def test_an_anchor_number_belongs_to_the_block_the_chain_holds():
    """XE-6256 / XE-4148. An ended session's block lands after a later session has taken its number: the
    register row goes to the block that is on the chain. Where the row already names a block there, the
    chain holds under the number what the later of the two wrote, so the higher index has the row,
    whichever is recorded first (XE-14127)."""
    from dao.models import Anchor
    from dao.services import sessions

    class Db:
        def __init__(self, *answers):
            self.answers, self.added = list(answers), []

        async def execute(self, _stmt):
            row = self.answers.pop(0)
            return SimpleNamespace(scalar_one_or_none=lambda: row)

        def add(self, row):
            self.added.append(row)
    s = SimpleNamespace(id="s2", ops=[{"value": json.dumps({"n": 7, "event_index": 70, "head_hash": "h2"})}],
                        submitted_index=12, submitted_hash="bh")

    def row(index):
        return SimpleNamespace(n=7, event_index=60, head_hash="h1", session_id="s1", statechain_index=index, statechain_hash="")
    waiting = row(None)
    db = Db(None, waiting)
    await sessions._anchor_written(db, s)
    assert (waiting.session_id, waiting.event_index, waiting.head_hash, waiting.statechain_index, waiting.statechain_hash) \
        == ("s2", 70, "h2", 12, "bh") and db.added == []
    earlier = row(5)
    db = Db(None, earlier)
    await sessions._anchor_written(db, s)
    assert (earlier.session_id, earlier.event_index, earlier.head_hash, earlier.statechain_index, earlier.statechain_hash) \
        == ("s2", 70, "h2", 12, "bh") and db.added == [], "a block below this one was written over on the chain"
    for index in (12, 20):
        later = row(index)
        db = Db(None, later)
        await sessions._anchor_written(db, s)
        assert (later.session_id, later.event_index, later.head_hash, later.statechain_index) == ("s1", 60, "h1", index) \
            and db.added == [], "a block at or above this one is what the chain holds"
    db = Db(None, None)
    await sessions._anchor_written(db, s)
    assert len(db.added) == 1 and isinstance(db.added[0], Anchor)
    assert (db.added[0].n, db.added[0].session_id, db.added[0].statechain_index, db.added[0].statechain_hash) == (7, "s2", 12, "bh")
    own = row(None)
    db = Db(own)
    await sessions._anchor_written(db, s)
    assert (own.statechain_index, own.statechain_hash, own.event_index) == (12, "bh", 60), "its own row is filled as it is"


async def test_a_closed_proposal_tells_a_voter_what_the_vote_was_recorded_with(monkeypatch):
    """XE-4460. The preview derived a weight from the chain as it reads now for any proposal; on one that
    has closed, the wallet's vote is on record with the weight the result counted, and that is the answer."""
    from dao.api import public
    from dao.services import portal
    h, voter, other = "ab" * 32, "a" * 64, "b" * 64
    pr = SimpleNamespace(hash=h, status="closed", rules={}, opened_at=1)
    kept = SimpleNamespace(weight=5, participating=False,
                           eligibility={"snapshot": {"snapshot_at": 9, "balance": 5}, "not_participating_because": ["too new"]})
    derived = []

    async def get(db, proposal):
        return pr

    async def vote_of(db, proposal, account):
        return kept if account == voter else None

    async def eligibility(ctx, proposal, account, is_agent):
        derived.append(account)
        return {"snapshot_at": 9, "balance": 1}, [], True, 1
    monkeypatch.setattr(portal, "get", get)
    monkeypatch.setattr(portal, "vote_of", vote_of)
    monkeypatch.setattr(portal, "eligibility", eligibility)
    ctx = SimpleNamespace(config=SimpleNamespace(agent_accounts=set()))

    def request(n):
        return SimpleNamespace(client=SimpleNamespace(host=f"10.77.0.{n}"))
    assert await public.snapshot(request(1), voter, ctx, _Released(), proposal=h) == {
        "account": voter, "snapshot_at": 9, "balance": 5, "weight": 5, "participating": False, "not_participating_because": ["too new"]}
    assert derived == []
    assert (await public.snapshot(request(2), other, ctx, _Released(), proposal=h))["weight"] == 1 and derived == [other]
    pr.status = "open"
    assert (await public.snapshot(request(3), voter, ctx, _Released(), proposal=h))["weight"] == 1, "an open proposal is derived, as a vote would be"


def test_small_rules_of_the_sweep_hold_where_they_are_stated():
    import inspect

    from dao import chainops, signer as signer_mod, ui
    from dao.api import legal
    from dao.services import fees, inbox, portal, sessions
    from xe import encoding
    # a proposal on which no fee was due names no fee block
    base = dict(title="t", author_account="a", status="open", opened_at=10**18, closes_at=2 * 10**18, rules={}, ops=None,
                result=None, decision=None, analysis=[], body="b")
    assert portal.to_dict(SimpleNamespace(hash="h" * 64, fee_block_hash="h" * 64, **base))["fee_block_hash"] == ""
    assert portal.to_dict(SimpleNamespace(hash="h" * 64, fee_block_hash="f" * 64, **base))["fee_block_hash"] == "f" * 64
    # a block is waited on for as long as a node could take it, not for less (XE-4591)
    assert fees.STANDING_NS > chainops.TIMESTAMP_WINDOW_NS
    src = inspect.getsource(fees.settle_due)
    assert src.count("_stands(f)") == 2, "and a row whose pass failed is asked too"
    # every register can be read to its end (XE-4601), and every page has a total order (XE-3250)
    for route in (legal.anchors, legal.pause_state):
        assert {"offset", "limit"} <= set(inspect.signature(route).parameters), route.__name__
    assert "Vote.timestamp.asc(), Vote.account.asc()" in inspect.getsource(portal.votes_for)
    assert "SigningSession.updated_at.desc(), SigningSession.id.desc()" in inspect.getsource(sessions.ended_holding_a_block)
    # the members' page lists every session a member can still act on, however many have come since (XE-1561)
    assert "await sessions.open_sessions(db)" in inspect.getsource(ui.members_page)
    members = (ROOT / "dao/templates/members.html").read_text(encoding="utf-8")
    assert "closed_total > closed|length" in members and "keyset.error" in members
    assert "t.error" in (ROOT / "dao/templates/records.html").read_text(encoding="utf-8")
    # a classification fits its column (XE-2775), an open block's account is compared as the address is derived
    assert 'max_len=32' in inspect.getsource(inbox.set_status)
    assert "b.account.lower()" in inspect.getsource(encoding.verify_open_block_signature)
    # the keyfile: whatever goes wrong looking for it or making room for it is a SignerError (XE-4282)
    assert "path.exists()" not in inspect.getsource(signer_mod._read_keyfile) + inspect.getsource(signer_mod.Signer.init_keyfile)
    src = inspect.getsource(signer_mod._write_keyfile)
    assert src.index("try:") < src.index("path.parent.mkdir(")


# ---- XE-3129: a weight rests only on blocks the node holds final -------------------------------------------

async def test_a_snapshot_walks_only_the_blocks_the_node_holds_final():
    from dao.chainops import SNAPSHOT_RULE, account_snapshot
    T = 100 * H

    class Served:
        """A node that serves exactly these blocks, flags and all."""

        def __init__(self, *blocks, source=None):
            self.served, self.source = list(blocks), {"finalized": True} if source is None else source

        async def full_chain(self, account):
            return self.served

        async def block(self, h):
            return {"timestamp": T - 20 * H, **self.source}

    def b(h, balance, ts, type_="receive", **flag):
        return {"type": type_, "asset": "XE", "balance": balance, "timestamp": ts, "hash": h, "source": "early", **flag}
    opened = b("o", 1000, T - 10 * H, finalized=True)
    # every block final: the chain as it stands
    s = await account_snapshot(Served(opened, b("r", 1500, T - 9 * H, finalized=True)), "a", T)
    assert (s["balance"], s["snapshot_block"], s["unsettled"], s["exists"], s["rule"]) == (1500, "r", False, True, SNAPSHOT_RULE)
    # a block that is not final is not counted, whatever stands in the flag's place; a node that serves no
    # flag has said nothing is final
    for flag in ({"finalized": False}, {}, {"finalized": None}, {"finalized": "true"}, {"finalized": 1}):
        s = await account_snapshot(Served(opened, b("r", 1500, T - 9 * H, **flag)), "a", T)
        assert (s["balance"], s["snapshot_block"], s["unsettled"]) == (1000, "o", True), flag
    # nothing after it is counted either, final or not: each block stands on the one before
    s = await account_snapshot(Served(opened, b("s", 0, T - 9 * H, "send", finalized=False), b("r", 700, T - 8 * H, finalized=True)), "a", T)
    assert (s["balance"], s["snapshot_block"], s["unsettled"]) == (1000, "o", True)
    # one dated after the snapshot would not have been counted, and the chain is unsettled all the same:
    # the place it holds may yet go to a block dated before the snapshot
    s = await account_snapshot(Served(opened, b("s", 0, T + 1, "send", finalized=False)), "a", T)
    assert (s["balance"], s["unsettled"]) == (1000, True)
    # a receive counts only if the source it names is final too, whatever stands in the flag's place
    near = b("r", 1500, T - 1, finalized=True)
    assert (await account_snapshot(Served(opened, near), "a", T))["balance"] == 1500
    for flag in ({"finalized": False}, {}, {"finalized": "true"}, {"finalized": True, "timestamp": None}):
        s = await account_snapshot(Served(opened, near, source=flag), "a", T)
        assert (s["balance"], s["excluded_receives"], s["unsettled"]) == (1000, ["r"], False), flag
    # an account with nothing final does not exist yet, and says why it may
    s = await account_snapshot(Served(b("o", 1000, T - 10 * H, finalized=False)), "a", T)
    assert (s["exists"], s["balance"], s["first_block_ts"], s["unsettled"], s["rule"]) == (False, 0, None, True, SNAPSHOT_RULE)
    assert (await account_snapshot(Served(), "a", T))["unsettled"] is False


def test_a_row_from_an_unsettled_snapshot_is_not_current_and_every_deciding_read_asks_for_finality():
    import inspect

    from dao import chainops
    from dao.chainops import SNAPSHOT_RULE, snapshot_time
    from dao.services import fees, portal
    pr = SimpleNamespace(opened_at=10 * H)
    ctx = SimpleNamespace(config=SimpleNamespace(agent_accounts=set()))

    def row(**snap):
        return SimpleNamespace(account="a", is_agent=False,
                               eligibility={"snapshot": {"at": snapshot_time(pr.opened_at), "rule": SNAPSHOT_RULE, **snap}})
    assert portal.is_current(ctx, pr, row(unsettled=False)) and portal.is_current(ctx, pr, row())
    assert not portal.is_current(ctx, pr, row(unsettled=True))
    assert not portal.is_current(ctx, pr, row(rule=SNAPSHOT_RULE - 1)), "rows derived before the rule are derived again"
    # the chain reads that decide something: a voter's weight, a fee's arrival, a fee's receive, the tip a block is built on
    # and the source a receive names
    for reads in (chainops.account_snapshot, chainops._sends_at_or_before, chainops._build_out, fees._FeeChain.receive_of,
                  portal._verify_fee):
        assert '"finalized") is' in inspect.getsource(reads), reads.__qualname__


# ---- XE-3130: one pass over the pending sends is bounded, and spends its budget where it matters -----------

async def test_a_receive_pass_is_bounded_in_number_and_time_and_dust_waits_behind_a_fee(monkeypatch):
    from dao import chainops
    monkeypatch.setattr(chainops, "_offered", {})
    kp = KeyPair.generate()
    acct = kp.address

    def p(h, amount, asset="XE"):
        return {"send_hash": h, "source": "s", "destination": acct, "amount": amount, "asset": asset, "timestamp": 0}
    dust = [p(f"d{i}", 1) for i in range(100)]
    pending = dust[:50] + [p("junk", 10 ** 12, "JUNK"), p("fee", 5_000_000)] + dust[50:]
    todo = chainops.receive_order(acct, pending, 0.0)
    assert len(todo) == chainops.RECEIVE_PASS_MAX < len(pending) and todo[0]["send_hash"] == "fee"
    assert all(x["asset"] == "XE" for x in todo), "XE before any other asset, whatever number the other carries"

    # offered a receive and pending all the same: it keeps its place ahead of anything smaller, however
    # much of that has never been tried; among sends of one size the untried go first
    two = [p("fee", 5_000_000), p("d0", 1)]
    chainops._offered[(acct, "fee")] = (1, 1000.0)
    assert [x["send_hash"] for x in chainops.receive_order(acct, two, 1001.0)] == ["fee", "d0"]
    assert chainops.receive_order(acct, pending, 1001.0)[0]["send_hash"] == "fee"
    chainops._offered[(acct, "d0")] = (1, 1000.0)
    assert [x["send_hash"] for x in chainops.receive_order(acct, [p("d0", 1), p("d1", 1)], 1001.0)] == ["d1", "d0"]
    # from the second time, a doubling wait
    for n, wait in ((2, 120.0), (3, 240.0), (6, 1920.0), (7, 3600.0), (5000, 3600.0)):
        chainops._offered[(acct, "fee")] = (n, 1000.0)
        assert [x["send_hash"] for x in chainops.receive_order(acct, two, 1000.0 + wait - 1)] == ["d0"], n
        assert [x["send_hash"] for x in chainops.receive_order(acct, two, 1000.0 + wait)] == ["fee", "d0"], n
    # the record leaves with the send, and another account's is not this pass's to clear
    chainops._offered[("other", "x")] = (9, 0.0)
    assert chainops.receive_order(acct, [], 0.0) == [] and chainops._offered == {("other", "x"): (9, 0.0)}
    chainops._offered.clear()

    class Node:
        def __init__(self):
            self.received = []

        async def pending_for(self, address):
            return list(pending)   # nothing ever lands: every send stays pending

        async def submit_block(self, block):
            self.received.append(block.source)

    async def tip(chain, address):
        return "0", {}

    async def signed(ctx_, block, kp_):
        return block

    async def not_paused():
        return False
    monkeypatch.setattr(chainops, "_tip", tip)
    monkeypatch.setattr(chainops, "signed", signed)
    ctx = SimpleNamespace(chain=Node(), signer=SimpleNamespace(keypair=lambda name, scope: kp))
    limit = chainops.RECEIVE_PASS_MAX
    assert await chainops.receive_pending(ctx, "fee", not_paused) == limit
    assert ctx.chain.received[0] == "fee" and len(ctx.chain.received) == limit
    # the next pass offers the fee again, and then dust it has not tried rather than the same dust
    assert await chainops.receive_pending(ctx, "fee", not_paused) == limit
    assert ctx.chain.received[limit] == "fee" and len(set(ctx.chain.received)) == 2 * limit - 1
    # and a pass that has used its time offers nothing more, however long the list
    monkeypatch.setattr(chainops, "RECEIVE_PASS_S", 0.0)
    assert await chainops.receive_pending(ctx, "fee", not_paused) == 0 and len(ctx.chain.received) == 2 * limit
    assert chainops._offered[(acct, "fee")][0] == 2 and all(n == 1 for k, (n, _) in chainops._offered.items() if k[1] != "fee")
    assert len(chainops._offered) == 2 * limit - 1, "a send the pass did not reach has not been tried"

    # what stops a pass before the submit is not about the send, and is held against none of them: the
    # node failing our own tip ends the pass, and a pause check that fails is the caller's to hear of
    from xe.client import XeError
    monkeypatch.setattr(chainops, "RECEIVE_PASS_S", 30.0)
    chainops._offered.clear()

    async def no_tip(chain, address):
        raise XeError(0, "connection refused")
    monkeypatch.setattr(chainops, "_tip", no_tip)
    assert await chainops.receive_pending(ctx, "fee", not_paused) == 0
    monkeypatch.setattr(chainops, "_tip", tip)

    async def no_database():
        raise RuntimeError("the pause check could not be made")
    with pytest.raises(RuntimeError):
        await chainops.receive_pending(ctx, "fee", no_database)
    assert chainops._offered == {} and len(ctx.chain.received) == 2 * limit

    # a failure that is this send's (its block could not be built) costs it a place and the pass goes on
    async def one_bad(ctx_, block, kp_):
        if block.source == "fee":
            raise ValueError("not a block")
        return block
    monkeypatch.setattr(chainops, "signed", one_bad)
    assert await chainops.receive_pending(ctx, "fee", not_paused) == limit - 1
    assert chainops._offered[(acct, "fee")][0] == 1 and len(chainops._offered) == limit

    # a search for proof of work that ran out of time offered the send nothing, so the send is held to
    # nothing: it is first in the next pass and the next, and the sends behind it are offered theirs (XE-14286)
    chainops._offered.clear()

    async def slow_for_the_fee(ctx_, block, kp_):
        if block.source == "fee":
            raise TimeoutError("no proof of work found in 120s")
        return block
    monkeypatch.setattr(chainops, "signed", slow_for_the_fee)
    for _ in range(3):
        assert await chainops.receive_pending(ctx, "fee", not_paused) == limit - 1
        assert (acct, "fee") not in chainops._offered
        assert chainops.receive_order(acct, pending, time.monotonic())[0]["send_hash"] == "fee"

    # nor did a submit that found no node to connect to: the node was shown nothing, the sends behind
    # would be shown nothing, and the pass ends held against none of them
    import httpx
    chainops._offered.clear()
    monkeypatch.setattr(chainops, "signed", signed)
    asked = []

    async def no_node(block):
        asked.append(block.source)
        try:
            raise httpx.ConnectError("connection refused")
        except httpx.ConnectError as e:
            raise XeError(0, "ConnectError") from e
    ctx.chain.submit_block = no_node
    assert await chainops.receive_pending(ctx, "fee", not_paused) == 0
    assert asked == ["fee"] and chainops._offered == {}
    # a connection that gave no answer may have carried a receive the node took: that send's, and the pass goes on
    assert not XeError(0, "ReadTimeout").unsent and not XeError(503, "x").unsent

    async def no_answer(block):
        raise XeError(0, "ReadTimeout")
    ctx.chain.submit_block = no_answer
    assert await chainops.receive_pending(ctx, "fee", not_paused) == 0
    assert len(chainops._offered) == limit and chainops._offered[(acct, "fee")][0] == 1
    chainops._offered.clear()


# ---- XE-4169: a downgrade does not discard what the upgrade cannot restore ---------------------------------

def test_a_downgrade_refuses_while_it_would_discard_what_the_upgrade_cannot_restore():
    import importlib.util
    versions = Path(__file__).resolve().parent.parent / "alembic" / "versions"

    def migration(name):
        spec = importlib.util.spec_from_file_location(f"migration_{name[:4]}", versions / name)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    class Op:
        """Alembic's `op` over a database that answers every question with `row`."""

        def __init__(self, row):
            self.row, self.asked, self.did = row, [], []

        def get_bind(self):
            return self

        def execute(self, statement, params=None):
            self.asked.append((str(statement), params))
            return SimpleNamespace(first=lambda: self.row)

        def __getattr__(self, name):
            return lambda *a, **k: self.did.append(name)

    # 0004: `events.v` says which envelope a row was hashed under, and the upgrade restores every row as v1
    m = migration("0004_event_envelope_v2.py")
    m.op = held = Op(row=(1,))
    with pytest.raises(RuntimeError, match="v2 events"):
        m.downgrade()
    assert held.did == [] and "v >= 2" in held.asked[0][0]
    m.op = empty = Op(row=None)
    m.downgrade()
    assert empty.did == ["drop_column"]
    # 0002: the table of claimed signatures comes back empty, so it is not dropped while a claim still guards a request
    m = migration("0002_seen_signatures.py")
    from dao.auth import MAX_SKEW_NS
    assert m.REPLAY_WINDOW_NS == MAX_SKEW_NS
    m.op = held = Op(row=(1,))
    before = time.time_ns()
    with pytest.raises(RuntimeError, match="could\\s+still be replayed"):
        m.downgrade()
    cutoff = held.asked[0][1]["cutoff"]
    assert held.did == [] and before - MAX_SKEW_NS <= cutoff <= time.time_ns() - MAX_SKEW_NS
    m.op = empty = Op(row=None)
    m.downgrade()
    assert empty.did == ["drop_index", "drop_table"]
    # 0003: the wider column holds nonces the narrower one cannot
    m = migration("0003_pow_nonce_u64.py")
    m.op = held = Op(row=(1,))
    with pytest.raises(RuntimeError, match="2\\^63"):
        m.downgrade()
    assert held.did == [] and "pow_nonce > 9223372036854775807" in held.asked[0][0]
    m.op = empty = Op(row=None)
    m.downgrade()
    assert empty.did == ["alter_column"]
    # 0001: every table, the log first among them; an empty schema may go and one that holds a record may not
    m = migration("0001_initial.py")
    m.op = held = Op(row=(1,))
    with pytest.raises(RuntimeError, match="event log"):
        m.downgrade()
    assert held.did == [] and "FROM events" in held.asked[0][0]
    m.op = empty = Op(row=None)
    m.downgrade()
    assert empty.did == ["drop_table"] * 14
    # the sites: a downgrade that drops a table or a column or narrows a type refuses first, and every
    # other one takes away only what its upgrade rebuilds from what is still there
    guarded = {"0001_initial.py", "0002_seen_signatures.py", "0003_pow_nonce_u64.py", "0004_event_envelope_v2.py"}
    seen = set()
    for path in sorted(versions.glob("0*.py")):
        src = path.read_text()
        down = src[src.index("def downgrade"):]
        seen.add(path.name)
        if path.name in guarded:
            assert down.index("raise RuntimeError(") < min(down.index(w) for w in ("op.drop_", "op.alter_column") if w in down), path.name
            continue
        loses = "drop_table" in down or "drop_column" in down or "type_=" in down
        # 0006: the flag is read back from the log. 0008: the mark says the chain has been asked for the
        # last time, and every ended session starts unmarked and is asked once more.
        restored = {"0006_inbox_published.py", "0008_block_displaced_no_redact_flag.py"}
        assert not loses or path.name in restored, f"{path.name} drops data: say why its upgrade restores it"
    assert guarded < seen and len(seen) == 8


# ---- XE-11273: nothing a client puts in a header raises out of a middleware --------------------------------

async def test_a_declared_length_is_a_bounded_number_or_the_request_is_refused():
    from dao.main import MAX_BODY_BYTES, BodyLimit

    async def answer(value):
        sent, reached = [], []

        async def send(message):
            sent.append(message)

        async def receive():
            return {"type": "http.request", "body": b"{}", "more_body": False}

        async def app(scope, receive, send):
            reached.append(scope)
        await BodyLimit(app)({"type": "http", "method": "POST", "headers": [(b"content-length", value)]}, receive, send)
        return (sent[0]["status"] if sent else None), bool(reached)
    for not_a_length in (b"9" * 5000, b"1" * 19, b"", b"-1", b"+1", b"1 ", b" 1", b"0x10", b"1e3", b"1.0", "١٢".encode()):
        assert await answer(not_a_length) == (400, False), not_a_length[:24]
    for over in (str(MAX_BODY_BYTES + 1).encode(), b"9" * 18):
        assert await answer(over) == (413, False), over
    for fits in (b"0", b"2", str(MAX_BODY_BYTES).encode(), b"000002"):
        assert await answer(fits) == (None, True), fits


# ---- XE-10113 / XE-9506: the copy states the snapshot lead and the vote window the code applies --------------

def test_every_statement_of_the_snapshot_lead_and_the_vote_window_is_the_one_the_code_applies():
    import inspect

    from dao import chainops
    from dao.services import portal
    root = Path(__file__).resolve().parent.parent
    assert chainops.SNAPSHOT_LEAD_NS == 65 * 60 * 10 ** 9 and chainops.SNAPSHOT_LEAD_TEXT == "an hour and five minutes"
    assert "{SNAPSHOT_LEAD_TEXT} before the proposal opened" in inspect.getsource(portal.eligibility_at)
    said = [root / "README.md", root / "config" / "schedule_b.yaml", root / "config" / "copy" / "public.yaml"]
    said += sorted((root / "dao").rglob("*.py")) + sorted((root / "dao" / "templates").glob("*.html"))
    for path in said:
        assert "an hour before" not in path.read_text(), f"{path.relative_to(root)} gives the snapshot a rounder lead than the code does"
    for path in (root / "README.md", root / "config" / "schedule_b.yaml", root / "dao" / "templates" / "proposal.html",
                 root / "dao" / "models.py", root / "dao" / "services" / "portal.py"):
        assert chainops.SNAPSHOT_LEAD_TEXT in path.read_text() or "SNAPSHOT_LEAD_TEXT" in path.read_text(), path.name
    # a proposal carries no window of its own: the window is the pinned rules', and the copy does not say otherwise
    copy = (root / "config" / "copy" / "public.yaml").read_text()
    assert "unless the proposal says otherwise" not in copy
    assert 'closes_at=now + int(rules["window_days"]) * D' in inspect.getsource(portal.submit)
    cfg = load_config(root / "config")
    assert lint_public_copy(cfg) == []


# ---- XE-4318: a public read does not wait on the node with a pooled connection in hand ---------------------

async def test_a_public_read_asks_the_node_without_holding_a_database_connection(monkeypatch):
    import asyncio
    import inspect

    from dao.api import legal, public
    from dao.services import portal, records
    # the legal identifier: the node first, the database last
    src = inspect.getsource(legal.identifier)
    assert max(src.index("records.public_keyset(ctx)"), src.index("records.onchain_registry(ctx)")) < src.index("EventLog.head(db)")
    # the snapshot preview: the rows, then the connection goes back, then the node
    order = []

    class Db:
        async def commit(self):
            order.append("released")
    pr = SimpleNamespace(hash="1" * 64, status="open", rules={}, opened_at=10 ** 18)

    async def get(db, h):
        order.append("rows")
        return pr

    async def eligibility(ctx_, pr_, account, is_agent):
        order.append("node")
        return {}, [], True, 1
    monkeypatch.setattr(portal, "get", get)
    monkeypatch.setattr(portal, "eligibility", eligibility)
    ctx = SimpleNamespace(config=SimpleNamespace(agent_accounts=set()))
    request = SimpleNamespace(client=SimpleNamespace(host="10.78.0.1"))
    assert (await public.snapshot(request, "a" * 64, ctx, Db(), proposal="1" * 64))["weight"] == 1
    assert order == ["rows", "released", "node"]
    # and the reads every public page shares are one at a time: twenty requests on a slow node are one read,
    # which the caller that happened to start it does not take away by leaving
    monkeypatch.setattr(records, "_public_reads", {})
    monkeypatch.setattr(records, "_public_reading", {})
    asked, gate, keyset = [], asyncio.Event(), {"keys": [], "threshold": 2}

    async def slow():
        asked.append(1)
        await gate.wait()
        return keyset
    ctx = SimpleNamespace(chain=SimpleNamespace(dao_keyset=slow))
    waiting = [asyncio.ensure_future(records.public_keyset(ctx)) for _ in range(20)]
    for _ in range(3):
        await asyncio.sleep(0)
    waiting[0].cancel()
    gate.set()
    answers = await asyncio.gather(*waiting, return_exceptions=True)
    assert len(asked) == 1 and isinstance(answers[0], asyncio.CancelledError) and answers[1:] == [keyset] * 19
    assert records._public_reading == {}
    assert await records.public_keyset(ctx) == keyset and len(asked) == 1, "and one per interval, as before"


# ---- XE-5883: the chat store is read once the stream is open, so the two overlap ---------------------------

async def test_the_backfill_is_read_after_the_stream_is_open_and_before_anything_from_it():
    import inspect

    import httpx

    from dao import worker as worker_mod
    from xe import client as xc
    order = []

    class Stream(httpx.AsyncByteStream):
        async def __aiter__(self):
            order.append("first bytes read")
            yield b'data: {"id":"1"}\n\n'

    def node(status):
        def handler(request):
            order.append("stream requested")
            return httpx.Response(status, stream=Stream())
        return _node(handler)

    async def caught_up():
        order.append("store read")
    c = node(200)
    got = [item async for item in c.chat_events({"account": "a"}, caught_up)]
    assert got == [{"id": "1"}] and order == ["stream requested", "store read", "first bytes read"]
    await c.aclose()
    # a store that cannot be read ends the stream before anything from it is taken in: a live envelope
    # stored over an unread backlog would move the cursor past the backlog
    order.clear()

    async def unreadable():
        raise xc.XeError(0, "ReadTimeout")
    c = node(200)
    with pytest.raises(xc.XeError):
        async for item in c.chat_events({"account": "a"}, unreadable):
            order.append(("taken in", item))
    assert order == ["stream requested"]
    await c.aclose()
    # a stream the node refused is not one to catch up behind
    order.clear()
    c = node(401)
    with pytest.raises(xc.XeError):
        async for item in c.chat_events({"account": "a"}, caught_up):
            pass
    assert order == ["stream requested"]
    await c.aclose()
    # and the worker reads the store nowhere else: one backfill, handed to the stream
    src = inspect.getsource(worker_mod.Worker.chat_loop)
    assert src.count("inbox.backfill(") == 1 and "ctx.chain.chat_events(proof, caught_up)" in src
    assert src.index("async def caught_up") < src.index("inbox.backfill(") < src.index("ctx.chain.chat_events(")


# ---- XE-6983: a failure's own text goes to the server's log, and a response says only that it failed -------

async def test_no_response_carries_the_text_of_a_failure_the_service_did_not_write(monkeypatch, caplog):
    import ast
    from fastapi import HTTPException
    from dao.api import public
    from dao.services import portal, records
    from xe.client import XeError
    secret = "connection to server at 10.0.0.5, port 5432 failed: SELECT index FROM log_head"

    # the sites: a raise of an HTTP error may quote an exception only where the handler names errors whose
    # text this code wrote (a refused signature, a refused keyset or op), never a node's or the database's
    own = {"KeyError_", "StateChainError", "HTTPException"}
    for path in sorted((ROOT / "dao").rglob("*.py")):
        for h in ast.walk(ast.parse(path.read_text())):
            if not (isinstance(h, ast.ExceptHandler) and h.name):
                continue
            caught = {ast.unparse(t).split(".")[-1] for t in (h.type.elts if isinstance(h.type, ast.Tuple) else [h.type])}
            for r in ast.walk(h):
                if isinstance(r, ast.Raise) and isinstance(r.exc, ast.Call) and "HTTPException" in ast.unparse(r.exc.func):
                    quoted = any(isinstance(n, ast.Name) and n.id == h.name
                                 for a in [*r.exc.args, *(k.value for k in r.exc.keywords)] for n in ast.walk(a))
                    assert not quoted or caught <= own, f"{path.name}:{r.lineno} answers with the text of {sorted(caught)}"

    # readiness: the database's words are logged and not returned
    async def down(db):
        raise RuntimeError(secret)
    monkeypatch.setattr(public.EventLog, "head", staticmethod(down))
    with caplog.at_level("WARNING"), pytest.raises(HTTPException) as e:
        await public.ready(SimpleNamespace(node=SimpleNamespace(network_id="n")), None)
    assert (e.value.status_code, e.value.detail) == (503, "database not ready") and secret in caplog.text

    # the fee check: a node failure that is not "no such block" leaves as the node error the application
    # answers with one fixed line, not as a response this function words from it
    class Db:
        async def execute(self, *a, **k):
            return SimpleNamespace(first=lambda: None)

    class Chain:
        async def block(self, h):
            raise XeError(500, secret)
    ctx = SimpleNamespace(config=SimpleNamespace(accounts={"fee": "xe_fee"}), chain=Chain())
    with pytest.raises(XeError):
        await portal._verify_fee(ctx, Db(), "ab" * 32, "xe_author", 1)

    # what is kept where a reader sees it (a row a route returns, an entry on the log, the health record):
    # the words of a failure this code or the protocol package worded, and of anything else only its kind
    from dao import faults
    from dao.signer import SignerError
    from xe.statechain import StateChainError
    for ours in (XeError(503, "node is syncing"), StateChainError("keyset needs at least one key"), SignerError("no fee key"),
                 HTTPException(409, "held by a seat")):
        assert faults.worded(ours) and faults.reason(ours) == (ours.detail if isinstance(ours, HTTPException) else str(ours))

    class Driver(ValueError):
        pass
    for theirs in (RuntimeError(secret), ValueError(secret), KeyError(secret), Driver(secret), OSError(secret)):
        assert not faults.worded(theirs) and faults.reason(theirs) == type(theirs).__name__
    assert faults.reason(XeError(400, "x" * 900)) == str(XeError(400, "x" * 900))[:300] and len(faults.reason(XeError(400, "x" * 900), 500)) == 500
    caplog.clear()
    with caplog.at_level("WARNING"):
        assert records._fault("log", RuntimeError(secret)) == "RuntimeError" and secret in caplog.text
    assert records._fault("node", XeError(503, "node is syncing")) == str(XeError(503, "node is syncing"))
    src = (ROOT / "dao/services/records.py").read_text()
    assert src.count('_error"] = _fault(') == 7 and '_error"] = str(e)' not in src

    # the sites, again: under a handler that catches everything, the exception's own text goes to a log
    # call and nowhere else (not onto a row, into an entry, or into a response)
    for path in sorted([*(ROOT / "dao").rglob("*.py"), *(ROOT / "xe").rglob("*.py")]):
        tree = ast.parse(path.read_text())
        parent = {c: p for p in ast.walk(tree) for c in ast.iter_child_nodes(p)}
        for h in ast.walk(tree):
            if not (isinstance(h, ast.ExceptHandler) and h.name):
                continue
            caught = {ast.unparse(t).split(".")[-1] for t in (h.type.elts if isinstance(h.type, ast.Tuple) else [h.type])}
            if not caught & {"Exception", "BaseException"}:
                continue
            for n in ast.walk(h):
                if not (isinstance(n, ast.Name) and n.id == h.name):
                    continue
                use = parent[n]
                if not (isinstance(use, ast.FormattedValue) or (isinstance(use, ast.Call) and ast.unparse(use.func) in ("str", "repr"))):
                    continue
                logged, at = False, use
                while at is not h and not logged:
                    logged = isinstance(at, ast.Call) and ast.unparse(at.func).split(".")[0] in ("log", "logging")
                    at = parent[at]
                assert logged, f"{path.name}:{n.lineno} keeps the text of whatever was raised"

    # a transport failure is the node client's to word, and it words its kind: the library's own message
    # carries the address it dialled
    import httpx

    def refuse(request):
        raise httpx.ConnectError(secret)
    c = _node(refuse)
    with pytest.raises(XeError) as e:
        await c.statechain_tip()
    assert str(e.value) == "node unreachable: ConnectError" and e.value.transient
    await c.aclose()

    # What the service has to tell an operator it raises as its own: the words are kept, on the row or the
    # entry they were written for. A bare RuntimeError saying the same is not ours to tell from the rest, so
    # nothing in the services, the chain operations or the worker raises one.
    from dao.log import LogError
    told = "settlement was begun under the memo-nonce scheme (nonce ab12cd34)"
    assert faults.reason(faults.Fault(told), 500) == told and faults.reason(RuntimeError(told), 500) == "RuntimeError"
    assert faults.reason(LogError("harness key will not sign: scope")) == "harness key will not sign: scope"
    for path in [*(ROOT / "dao" / "services").glob("*.py"), ROOT / "dao" / "chainops.py", ROOT / "dao" / "worker.py"]:
        for n in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(n, ast.Raise) and isinstance(n.exc, ast.Call):
                assert ast.unparse(n.exc.func) not in ("RuntimeError", "ValueError", "TypeError", "Exception"), \
                    f"{path.name}:{n.lineno} words a failure under a type whose words are not kept"


# ---- XE-10085: a setting the template offers is read ------------------------------------------------------

def test_the_log_level_in_the_template_is_the_level_both_entry_points_set():
    import logging
    from dao.settings import Settings
    assert Settings(_env_file=None, LOG_LEVEL="debug").logging_level == logging.DEBUG
    assert Settings(_env_file=None, LOG_LEVEL=" Warning ").logging_level == logging.WARNING
    for bad in ("verbose", "", "10", "notset"):
        with pytest.raises(ValueError):
            Settings(_env_file=None, LOG_LEVEL=bad)
    assert "LOG_LEVEL=" in (ROOT / ".env.example").read_text()
    for entry in ("dao/main.py", "dao/worker.py"):
        src = (ROOT / entry).read_text()
        assert "basicConfig(level=get_settings().logging_level" in src and "level=logging.INFO" not in src, entry


# ---- XE-10697, XE-8172: the schema the migrations build is the one the models declare ---------------------

def test_the_migrations_build_the_timestamps_and_the_indexes_the_models_declare():
    import importlib.util
    from sqlalchemy import DateTime
    from dao.models import Base
    path = ROOT / "alembic/versions/0007_timestamps_and_indexes.py"
    spec = importlib.util.spec_from_file_location("migration_0007", path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    tables = Base.metadata.sorted_tables
    required = {(t.name, c.name) for t in tables for c in t.columns if isinstance(c.type, DateTime) and not c.nullable}
    assert set(m.TIMESTAMPS) == required and len(m.TIMESTAMPS) == len(required) == 9
    # 0001 is where each was created without NOT NULL, and no other migration creates a timestamp column
    initial = (ROOT / "alembic/versions/0001_initial.py").read_text()
    loose = [line for line in initial.splitlines() if "sa.DateTime(timezone=True), server_default" in line]
    assert len(loose) == 9 and not any("nullable=False" in line for line in loose)
    declared = {i.name: (t.name, tuple(c.name for c in i.columns)) for t in tables for i in t.indexes}
    assert {name: (table, columns) for name, table, columns in m.INDEXES} == {n: declared[n] for n, _, _ in m.INDEXES}
    # and every index, under the name its migration gave it: a database built from the models (the tests')
    # is the one the migrations build (the deployment's)
    import re
    made = {name: (table, columns) for name, table, columns in m.INDEXES}
    for version in sorted((ROOT / "alembic/versions").glob("0*.py")):
        for name, table, cols in re.findall(r'op\.create_index\("(\w+)", "(\w+)", \[([^\]]*)\]', version.read_text()):
            made[name] = (table, tuple(re.findall(r'"(\w+)"', cols)))
    assert declared == made and len(made) == 17

    class Op:
        def __init__(self):
            self.did = []

        def __getattr__(self, name):
            return lambda *a, **k: self.did.append((name, a, k))
    m.op = up = Op()
    m.upgrade()
    steps = iter(up.did)
    for table, column in m.TIMESTAMPS:
        (fill, (statement,), _), (alter, target, how) = next(steps), next(steps)
        assert fill == "execute" and str(statement) == f"UPDATE {table} SET {column} = now() WHERE {column} IS NULL"
        assert (alter, target, how["nullable"]) == ("alter_column", (table, column), False)
    assert [(n, a) for n, a, _ in steps] == [("create_index", (name, table, list(cols))) for name, table, cols in m.INDEXES]
    m.op = down = Op()
    m.downgrade()
    assert [n for n, _, _ in down.did] == ["drop_index"] * 3 + ["alter_column"] * 9
    assert all(k["nullable"] is True for n, _, k in down.did if n == "alter_column")


# ---- XE-10901: a field that took a seed is emptied when the attempt ends, and never shows it --------------

def test_the_seed_field_is_masked_and_emptied_before_the_key_is_tried():
    import re
    box = (ROOT / "dao/templates/_keybox.html").read_text()
    field = re.search(r'<input[^>]*id="seed"[^>]*>', box).group(0)
    assert 'type="password"' in field and 'autocomplete="off"' in field and 'spellcheck="false"' in field
    js = (ROOT / "dao/static/signer.js").read_text()
    handler = js[js.index('$("#keyform")'):js.index('$("#keyforget")')]
    assert handler.index('field.value = ""') < handler.index("Signer.setSeed(seed)"), "emptied before the load can fail"
    assert js.count('$("#seed")') == 1, "the field is read in one place"
    # masked is still a form field: the stylesheet's rule for a text input names it too
    css = (ROOT / "dao/static/site.css").read_text()
    assert css.count("input[type=text]") == css.count("input[type=password]") == 2
    # the one field on any page that takes key material
    for page in (ROOT / "dao/templates").glob("*.html"):
        text = page.read_text()
        assert page.name == "_keybox.html" or not re.search(r'<input[^>]*(seed|secret|private)', text, re.I), page.name


# ---- sweep of XE-4318: the one unauthenticated read that asks the node on every request --------------------

def test_the_session_read_returns_its_connection_before_it_asks_the_node():
    import inspect

    from dao.api import members
    src = inspect.getsource(members.get_session)
    assert src.index("sessions.get(db, sid)") < src.index("await release(db)") < src.index("sessions.is_stale(ctx, s)")
    assert "(db" not in src[src.index("await release(db)") + len("await release(db)"):], "and reads nothing after"


# ---- sweep of XE-3845: the command line takes a difficulty as the inbox publishes it, and nothing looser ---

def test_the_cli_takes_a_difficulty_as_published_and_refuses_what_is_not_one():
    from typer.testing import CliRunner

    from dao import cli
    runner, env = CliRunner(), {"XE_SEED": KeyPair.generate().seed.hex()}
    base = ["sign-request", "xe-dao/inbox/v1", "{}", "--dao", "xe_dao", "--network", "testnet-x", "--pow"]
    for spelling in ("0x0000000000000001", "0X01", "1", "0000000000000001"):
        r = runner.invoke(cli.app, [*base, spelling], env=env)
        assert r.exit_code == 0 and "pow_nonce" in json.loads(r.output), (spelling, r.output)
    # a prefix alone, a sign, a space, a separator, a digit that is not ASCII, and a number past 64 bits,
    # which no nonce meets and the search for which would not end
    for bad in ("0x", "zz", "+1", " 1", "1_0", "0x0x1", "١", "1" + "0" * 16, "0x1" + "0" * 16):
        r = runner.invoke(cli.app, [*base, bad], env=env)
        assert r.exit_code != 0 and "pow_nonce" not in r.output, bad


# ---- XE-4017: a v1 event's public and ref are in no hash, so a seal binds them ------------------------------

async def test_the_seal_over_the_v1_events_covers_each_ones_index_public_and_ref():
    """The hash of an event written before the v2 envelope does not cover `public` or `ref`. One sealing entry
    records a digest over every such row's (index, public, ref), and a replay rebuilds it: any of the three
    changed on any row, a row dropped, or two rows exchanged, is another digest."""
    from dao import log as log_mod

    def sealed(rows):
        seal = log_mod.Seal()
        for row in rows:
            seal.add(*row)
        return seal.payload()

    rows = [(0, False, "inbox:1"), (1, True, ""), (2, True, "proposal:ab")]
    assert sealed(rows) == sealed(rows) and sealed(rows)["rows"] == 3 and sealed(rows)["through"] == 2
    others = ([(0, True, "inbox:1"), *rows[1:]], [(0, False, "inbox:2"), *rows[1:]], [rows[1], rows[0], rows[2]], rows[:2],
              [*rows[:2], (3, True, "proposal:ab")], [*rows[:2], (2, True, "proposal:a"), (3, True, "b")])
    assert len({sealed(o)["digest"] for o in others} | {sealed(rows)["digest"]}) == len(others) + 1
    assert sealed([])["rows"] == 0 and sealed([])["through"] == -1
    # a seal no key signed binds nothing: without the harness key none is written, and nothing is read for it
    assert await log_mod.EventLog(Signer({}, {})).seal_legacy(None) is None


async def test_a_replay_fails_a_v1_event_that_is_not_as_it_was_sealed(monkeypatch):
    """The rule, at the one place every verification goes through (`/v1/log/verify`, the health check and
    `dao verify-log` all call it): once the seal is on the log, `public` and `ref` of each v1 event are
    checked by the replay, as they already were for each v2 event by its hash."""
    import inspect

    from dao import worker as worker_mod
    from dao.log import SEAL_KIND, UNSEALED, EventLog, Head, Seal, log_key
    from dao.services import records

    kp = KeyPair.generate()

    def chain(rows):
        evs, prev = [], "0" * 64
        for i, (kind, payload, public, ref, v) in enumerate(rows):
            h = event_hash(i, 1, kind, "harness", payload, prev, public=public, ref=ref, v=v)
            evs.append(SimpleNamespace(index=i, ts=1, kind=kind, actor="harness", payload=payload, prev_hash=prev, hash=h,
                                       signer=kp.pub_key_hex, signature=kp.sign_hex(bytes.fromhex(h)), public=public,
                                       ref=ref, v=v))
            prev = h
        return evs

    async def replay(evs):
        async def head(db):
            return Head(len(evs) - 1, evs[-1].hash)

        async def iter_all(db, batch=1000, upto=None):
            for ev in evs:
                yield ev

        class Db:
            async def execute(self, q):
                return SimpleNamespace(scalar=lambda: len(evs) - 1)

        monkeypatch.setattr(EventLog, "head", staticmethod(head))
        monkeypatch.setattr(EventLog, "iter_all", staticmethod(iter_all))
        return await EventLog.verify(Db(), kp.pub_key_hex)

    old = [("old", {"i": 0}, False, "inbox:1", 1), ("old", {"i": 1}, True, "", 1)]
    seal = Seal()
    seal.add(0, False, "inbox:1")
    seal.add(1, True, "")
    new = ("test", {}, True, "", 2)

    # XE-14510: v1 events with no seal over them are checked by nothing, and the replay says so itself
    res = await replay(chain([*old, new]))
    assert not res["ok"] and res["first_error"] == UNSEALED and res["count"] == 3
    assert res["legacy"] == {"rows": 2, "sealed": False}, "the log as it was before there was a seal"
    res = await replay(chain([new, new]))
    assert res["ok"] and "legacy" not in res, "and a log with no v1 event answers as it always did"

    evs = chain([*old, new, (SEAL_KIND, seal.payload(), True, "", 2)])
    res = await replay(evs)
    assert res["ok"] and res["count"] == 4 and res["legacy"] == {"rows": 2, "sealed": True}
    for i, field, value in ((0, "public", True), (0, "ref", "proposal:x"), (1, "public", False), (1, "ref", "inbox:1")):
        was = getattr(evs[i], field)
        setattr(evs[i], field, value)
        res = await replay(evs)
        assert not res["ok"] and res["first_error"] == "the v1 events are not as they were sealed at 3", (i, field)
        setattr(evs[i], field, was)
    assert (await replay(evs))["ok"]

    # the envelope a row says it was hashed under is one of the two there are, and is the one it was
    for i, v, error in ((2, 3, "unknown envelope at 2"), (0, 0, "unknown envelope at 0"), (0, 2, "hash mismatch at 0"),
                        (2, 1, "hash mismatch at 2")):
        was, evs[i].v = evs[i].v, v
        assert (await replay(evs))["first_error"] == error
        evs[i].v = was
    # one spelling of a signature
    evs[1].signature = evs[1].signature.upper()
    assert (await replay(evs))["first_error"] == "bad signature at 1"
    evs[1].signature = evs[1].signature.lower()
    assert (await replay(evs))["ok"]
    # nothing is written under the old envelope after the seal: a row that says it was is refused
    late = chain([*old, new, (SEAL_KIND, seal.payload(), True, "", 2), ("old", {}, True, "", 1)])
    assert (await replay(late))["first_error"] == "v1 event at 4, after the v1 rows were sealed"

    # the worker writes the seal before each health check, and a check that finds v1 events unsealed is not ok
    assert "seal_legacy" in inspect.getsource(worker_mod.Worker._seal_legacy_log)
    job = inspect.getsource(worker_mod.Worker.job_health)
    assert job.index("_seal_legacy_log()") < job.index("health_pass(")
    # XE-14510: the three that ask whether the log verifies take the replay's answer and decide nothing of
    # their own. None reads `legacy`, and each asks under the same key (`log_key`).
    from dao import cli
    from dao.api import public as public_api
    askers = {"health": inspect.getsource(records.health), "route": inspect.getsource(public_api.log_verify),
              "command": inspect.getsource(cli.verify_log)}
    for who, src in askers.items():
        assert "log_key(ctx.signer)" in src and '"legacy"' not in src and ".get(\"sealed\")" not in src, who
    assert 'detail["log_verified"] = bool(ver.get("ok"))' in askers["health"]
    assert 'typer.Exit(0 if res["ok"] else 1)' in askers["command"]
    assert log_key(Signer({}, {})) == "" and log_key(Signer({"harness": kp}, {"harness": {"event.sign"}})) == kp.pub_key_hex


# ---- XE-3020: an integer field is encoded as the integer it is, or the encoder refuses ----------------------

def test_an_integer_field_is_encoded_as_the_integer_it_is_or_refused():
    """The encoders masked a number to its field's width, so 2^64 + 5 was hashed and signed as 5 while the
    block's JSON said 2^64 + 5; and `int()` took a bool, a float or a string of digits. One test of an
    integer field (`exact_uint`), asked by every encoder, with its own error."""
    import dataclasses
    import inspect

    from xe import chat, encoding, statechain
    from xe.chat import ChatError, compute_envelope_id
    from xe.encoding import BLOCK_UINT64, Block, EncodingError, hash_block
    from xe.keys import KeyError_, exact_uint
    from xe.statechain import StateBlock, StateChainError, hash_state_block
    top = 2**64 - 1
    not_a_u64 = (2**64, 2**64 + 5, -1, True, False, 1.0, "5", None)
    assert exact_uint(0, 64, "x") == 0 and exact_uint(top, 64, "x") == top and exact_uint(2**32 - 1, 32, "x") == 2**32 - 1
    for bad in not_a_u64:
        with pytest.raises(KeyError_, match=r"invalid x: want an integer from 0 to 2\^64 - 1"):
            exact_uint(bad, 64, "x")
    with pytest.raises(KeyError_):
        exact_uint(2**32, 32, "x")

    a, good = "ab" * 32, "cd" * 32

    def block(**over):
        return Block(**{**dict(type="send", account=a, previous="0" * 64, balance=5, timestamp=1, asset="XE",
                               destination=good, amount=5), **over})
    # every integer a block carries, by name, whatever its type hashes: `to_json` sends each one
    assert {f.name for f in dataclasses.fields(Block) if f.type == "int"} == set(BLOCK_UINT64)
    assert hash_block(block(balance=top, timestamp=top, amount=top, pow_nonce=top), "net")
    for name in BLOCK_UINT64:
        for bad in not_a_u64:
            with pytest.raises(EncodingError, match=f"invalid {name}: want an integer"):
                hash_block(block(**{name: bad}), "net")
    # and the two integers a block holds inside another field
    assert hash_block(block(type="multisig_open", keyset={"keys": [a, good], "threshold": 2}), "net")
    for bad in (2**32, -1, True, 2.0, "2", None):
        with pytest.raises(EncodingError, match="keyset threshold"):
            hash_block(block(type="multisig_open", keyset={"keys": [a, good], "threshold": bad}), "net")
    assert hash_block(block(type="lease", attestations=[{"public_key": a, "timestamp": top, "signature": "00"}]), "net")
    for bad in not_a_u64:
        with pytest.raises(EncodingError, match="attestation timestamp"):
            hash_block(block(type="lease", attestations=[{"public_key": a, "timestamp": bad, "signature": "00"}]), "net")

    # a state block's index and timestamp, and an envelope's timestamp
    assert hash_state_block(StateBlock(index=top, prev_hash=good, ops=[], timestamp=top))
    for bad in not_a_u64:
        for over in (dict(index=bad), dict(timestamp=bad)):
            with pytest.raises(StateChainError, match="want an integer"):
                hash_state_block(StateBlock(**{**dict(index=1, prev_hash=good, ops=[], timestamp=1), **over}))
        with pytest.raises(ChatError, match="envelope timestamp"):
            compute_envelope_id("f", "p", "t", "m", bad)
    assert compute_envelope_id("f", "p", "t", "m", top)
    # nothing in the three masks a number to its field's width
    for mod in (encoding, statechain, chat):
        assert "0xFFFFFFFFFFFFFFFF" not in inspect.getsource(mod), mod.__name__


# ---- XE-14118: a block the node refuses for a field it carries is refused before it is signed --------------

def test_a_burn_or_a_mint_that_names_a_source_or_a_destination_is_refused_before_it_is_signed():
    """Neither field is in what a burn or a mint hashes, and both go out in its JSON, where the node refuses
    the block for carrying them. The memo was refused here on the types that do not hash it; these were not."""
    from xe.encoding import Block, EncodingError, hash_block, sign_block
    kp, other = KeyPair.generate(), "cd" * 32

    def block(t, **over):
        return Block(type=t, account=kp.address, previous="0" * 64, balance=5, timestamp=1, asset="XE", amount=5, **over)
    for t in ("burn", "mint"):
        assert sign_block(block(t), kp, "net").signature, "the control: the same block without them is signed"
        for over in (dict(source=other), dict(destination=other), dict(source=other, destination=other)):
            b = block(t, **over)
            with pytest.raises(EncodingError, match=f"source and destination not allowed on {t} blocks"):
                sign_block(b, kp, "net")
            assert b.signature == "" and b.hash == "", "and nothing was put on it"
            with pytest.raises(EncodingError):
                hash_block(b, "net")
    with pytest.raises(EncodingError, match="memo not allowed on mint blocks"):
        hash_block(block("mint", memo="m"), "net")
    # the types that hash the two fields still take them
    assert hash_block(block("send", destination=other), "net") and hash_block(block("receive", source=other), "net")


# ---- XE-3108: an envelope is built only as the verifier and the node accept it -----------------------------

def test_an_envelope_with_no_message_is_refused_before_it_is_signed_or_worked_for():
    from xe.chat import ChatError, new_envelope, verify_envelope
    kp, to = KeyPair.generate(), "cd" * 32
    # refused, not searched for: at this difficulty a search would end in TimeoutError
    with pytest.raises(ChatError, match="message is empty"):
        new_envelope(kp, to, "", difficulty=2**64 - 1, deadline_s=0.01)
    env = new_envelope(kp, to, "x", difficulty=1)
    verify_envelope(env, difficulty=1)
    env.message = ""
    with pytest.raises(ChatError, match="missing required fields"):
        verify_envelope(env, difficulty=1)   # the reader's rule, which the builder now keeps too


# ---- XE-14351: every proof-of-work search ends, in a nonce or in a refusal ---------------------------------

def test_every_proof_of_work_search_ends_in_a_nonce_or_a_refusal(monkeypatch):
    """`compute_http_pow` had a loop of its own with no deadline: `dao sign-request --pow ffffffffffffffff`
    ran until it was killed. One loop (`search_nonce`), and no search takes "no deadline"."""
    import inspect

    from typer.testing import CliRunner

    from dao import auth, cli
    from xe import chat, pow as xpow
    target = b"\x00" * 64
    for f in (xpow.compute_pow, auth.compute_http_pow, chat.new_envelope):
        assert inspect.signature(f).parameters["deadline_s"].default == xpow.WORKER_POW_DEADLINE_S, f.__name__
    assert inspect.signature(xpow.search_nonce).parameters["deadline_s"].default is inspect.Parameter.empty
    for f in (xpow.compute_pow, auth.compute_http_pow):
        src = inspect.getsource(f)
        assert "search_nonce(" in src and "while" not in src, f.__name__
    for search in (lambda: xpow.compute_pow(b"\x00" * 32, 2**64 - 1, 0.05),
                   lambda: auth.compute_http_pow(target, 2**64 - 1, 0.05),
                   lambda: xpow.search_nonce(lambda nonce: False, 0.05)):
        with pytest.raises(TimeoutError, match="no proof of work found"):
            search()
    nonce = auth.compute_http_pow(target, 1 << 60)
    assert 0 <= nonce < 2**64 and auth.validate_http_pow(target, nonce, 1 << 60)
    nonce = xpow.compute_pow(b"\x00" * 32, 1 << 60)
    assert 0 <= nonce < 2**64 and xpow.validate_pow(b"\x00" * 32, nonce, 1 << 60)

    # the command says so and stops: a usage error, with nothing printed that could be sent
    real = auth.compute_http_pow
    monkeypatch.setattr(auth, "compute_http_pow", lambda t, d: real(t, d, 0.05))
    r = CliRunner().invoke(cli.app, ["sign-request", "xe-dao/inbox/v1", "{}", "--dao", "xe_dao", "--network", "testnet-x",
                                     "--pow", "f" * 16], env={"XE_SEED": KeyPair.generate().seed.hex()})
    assert r.exit_code == 2 and "pow_nonce" not in r.output, r.output

    # the two searches that are not a caller of those: the outbox ends its pass on one that ran out of
    # time (ten rows searching for the whole deadline each held every other job of the worker), and the
    # browser's loop has a deadline of its own
    from dao.services import fees, inbox
    src = inspect.getsource(inbox.flush_outbox)
    at = src.index("isinstance(e, TimeoutError)")
    assert "WORKER_POW_DEADLINE_S" in src and src.index("return n", at) < src.index("continue", at)
    assert "isinstance(e, TimeoutError)" in inspect.getsource(fees.settle_due)
    js = (ROOT / "dao/static/signer.js").read_text(encoding="utf-8")
    loop = js[js.index("async pow("):js.index("body(payload")]
    assert "Date.now() - started > POW_DEADLINE_MS" in loop and "throw new Error" in loop


# ---- XE-14157: what is returned as a keyset has its keys and its threshold ---------------------------------

async def test_the_treasury_row_shows_a_keyset_or_says_there_is_none():
    """`keyset_of` passed an object with no keys through as the keyset of an account that is not multisig,
    and the records page read `keys` off it: Jinja found `dict.keys`, and the page was a 500. The client
    returns a keyset or None, the service keeps only that shape, and the row says which."""
    from dao.services import records
    from dao.ui import templates
    text = (ROOT / "dao/templates/records.html").read_text(encoding="utf-8")
    row = next(line for line in text.splitlines() if line.startswith("{% for name, t in treasury.items() %}"))
    tmpl = templates.env.from_string(row)
    k1, k2, addr, answer = "ab" * 32, "cd" * 32, "e" * 64, {}

    async def balances(account):
        return {"XE": 5_000_000}

    async def keyset_of(account):
        return answer["ks"]
    ctx = SimpleNamespace(config=SimpleNamespace(accounts={"treasury": addr, "dao": addr, "fee": ""}),
                          chain=SimpleNamespace(balances=balances, keyset_of=keyset_of))
    none = "none: not a multisig account"
    for ks, says in (({"keys": [k1.upper(), k2], "threshold": 2, "address": "x"}, "2 of 2"), (None, none),
                     # and whatever else a client might hand over is not shown as a keyset either
                     ({"address": "x"}, none), ({}, none), ({"keys": "abcd", "threshold": 1}, none)):
        answer["ks"] = ks
        t = await records._treasury(ctx)
        shaped = t["treasury"]["keyset"]
        assert shaped is None or (set(shaped) == {"keys", "threshold"} and isinstance(shaped["keys"], list)), ks
        html = tmpl.render(treasury=t)
        assert says in html and html.count(none) == (0 if says == "2 of 2" else 1), (ks, html)
    # an account that could not be read says that, and not that it has no keyset
    from xe.client import XeError

    async def down(account):
        raise XeError(503, "the node refused", said="busy")      # as the client raises it: its words, then the node's
    ctx.chain.keyset_of = down
    html = tmpl.render(treasury=await records._treasury(ctx))
    assert "could not be read from the node" in html and none not in html
    # and the balances that were read are still shown beside it
    assert "XE<br>" in html and "busy" not in html


# ---- XE-3877: what is shown of an open session is what its gates count -------------------------------------

def test_what_is_shown_of_an_open_session_is_what_its_gates_count():
    """`to_dict`, the members' page and the session events gave everything a session held over the threshold
    it was created under; the gates count the keys in the keyset now against the threshold now. After a
    rotation the page read "2/2" on a session held at one of two. One count (`sessions.counted`)."""
    import inspect

    from dao import ui
    from dao.api import members
    from dao.services import records, sessions

    def sess(status, approvals, signatures):
        return SimpleNamespace(
            id="s1", kind="parameter", title="T", status=status, ops=[], ops_digest="d" * 64, required_approvals=2,
            approvals=[{"public_key": k, "seat": k, "timestamp": 1} for k in approvals],
            block={"index": 1, "prev_hash": "0" * 64, "timestamp": 0, "hash": "h" * 64}, block_hash="h" * 64,
            block_signatures=[{"public_key": k, "signature": "s"} for k in signatures], rebuilds=0,
            submitted_index=None, submitted_hash="", error="", resolution_id="", not_before=None, created_at=None)
    same = {"keys": ["k1", "gone"], "threshold": 2}
    rotated = {"keys": ["k1", "k3"], "threshold": 2}        # `gone` left the keyset after it approved and signed
    raised = {"keys": ["k1", "gone", "k3"], "threshold": 3}
    for status in sessions.OPEN:
        s = sess(status, ["k1", "gone"], ["k1", "gone"])
        for ks in (same, rotated, raised):
            d = sessions.to_dict(s, ks)
            assert d["counted"] and d["required_approvals"] == ks["threshold"]
            # what a reader adds up answers the gates' question as the gates answer it
            assert (len(d["approvals"]) >= d["required_approvals"]) == sessions.approvals_met(s, ks), ks
            assert (len(d["block_signatures"]) >= d["required_approvals"]) == sessions.signatures_met(s, ks), ks
            assert [a["public_key"] for a in d["approvals"]] == [x["public_key"] for x in sessions.counted(s.approvals, ks)]
        assert sessions.approvals_met(s, same) and not sessions.approvals_met(s, rotated) and not sessions.approvals_met(s, raised)
        d = sessions.to_dict(s, rotated)
        assert len(d["approvals"]) == 1 and d["block_signatures"] == ["k1"] and d["set_aside"] == ["gone"]
        assert "set_aside" not in sessions.to_dict(s, same)
        # a keyset that could not be read: nothing is counted and nothing is said to be
        for unread in (None, {"error": "the node did not answer", "keys": [], "threshold": 0}):
            d = sessions.to_dict(s, unread)
            assert d["counted"] is False and d["required_approvals"] is None and len(d["approvals"]) == 2 and "set_aside" not in d
    # one that has ended shows what it holds and the number it was made under: a record, not counted again
    for status in ("submitted", "failed", "cancelled"):
        d = sessions.to_dict(sess(status, ["k1", "gone"], ["k1", "gone"]), rotated)
        assert d["counted"] is False and d["required_approvals"] == 2 and len(d["approvals"]) == 2
        assert d["block_signatures"] == ["k1", "gone"] and "set_aside" not in d

    # the figure in each session event and in the health check is that count
    for f, figure in ((sessions.approve, '"approvals": len(counted(s.approvals, ks))'),
                      (sessions.rebuild, '"approvals": len(counted(s.approvals, ks))'),
                      (sessions.sign, '"signatures": len(counted(s.block_signatures, ks))')):
        assert figure in inspect.getsource(f), f.__name__
    assert "sessions.counted(s.block_signatures, ks_now)" in inspect.getsource(records.health)
    # no caller shows a session without saying against which keyset, and the page prints `to_dict`'s figures
    assert inspect.signature(sessions.to_dict).parameters["ks"].default is inspect.Parameter.empty
    for mod in (members, records, ui):
        assert "to_dict(s)" not in inspect.getsource(mod) and '"sess_dict": sessions.to_dict' not in inspect.getsource(mod), mod.__name__
    page = (ROOT / "dao/templates/members.html").read_text(encoding="utf-8")
    for raw in ("s.approvals|length", "s.block_signatures|length", "s.required_approvals"):
        assert raw not in page, raw
    assert "d.approvals|length" in page and "d.block_signatures|length" in page and "d.set_aside" in page
    # the keyset a route counts against is asked for with nothing held: after the commit, or after `release`
    for route in (members.approve_session, members.rebuild_session, members.sign_session_block, members.cancel_session):
        src = inspect.getsource(route)
        assert src.index("await db.commit()") < src.index("_shown(ctx, s)"), route.__name__
    for route in (members.get_session, members.list_sessions):
        src = inspect.getsource(route)
        assert src.index("await release(db)") < src.index("public_keyset(ctx)" if route is members.list_sessions else "_shown(ctx, s)")


# ---- XE-14195: what a node says in refusing is for the server's log, and for nothing a caller is given -------

async def test_what_a_node_says_in_refusing_is_logged_and_is_in_nothing_a_caller_is_given(caplog):
    """The rule, across every call the client has: an answer that is not 2xx becomes an XeError whose text is
    this module's, worded from the status. What was sent with it (the node's error, or the error page of
    whatever stands in front of the node) is on `said` and in the server's log, and nowhere a caller
    stores or publishes: not `str(e)`, not `message`, not `faults.reason`, not what `/ready` returns."""
    import inspect
    import logging

    import httpx

    from dao.faults import reason
    from xe import client as xc
    secret = "upstream build-7f3a on 10.0.0.12 refused"
    a, proof = "a" * 64, {"account": "a" * 64, "challenge": "00", "signature": "00", "pub_key": "00"}
    reply = {}
    c = _node(lambda request: reply["v"](request))
    blk, sblk = SimpleNamespace(type="send", to_json=lambda: {}), SimpleNamespace(to_wire=lambda: "{}")

    async def stream():
        async for _ in c.chat_events(proof):
            pass
    calls = {
        "node": c.node, "chain": lambda: c.chain(a), "full_chain": lambda: c.full_chain(a), "chain_end": lambda: c.chain_end(a),
        "tip": lambda: c.tip(a), "keyset_of": lambda: c.keyset_of(a), "pending_for": lambda: c.pending_for(a),
        "balances": lambda: c.balances(a), "block": lambda: c.block("b" * 64), "submit_block": lambda: c.submit_block(blk),
        "statechain_tip": c.statechain_tip, "statechain_block": lambda: c.statechain_block(1),
        "statechain_key": lambda: c.statechain_key("dao.x"), "dao_keyset": c.dao_keyset,
        "submit_statechain_block": lambda: c.submit_statechain_block(sblk), "directory": lambda: c.directory(a),
        "directory_register": lambda: c.directory_register({}), "chat_challenge": c.chat_challenge,
        "chat_messages": lambda: c.chat_messages(proof), "chat_send": lambda: c.chat_send({}), "chat_events": stream,
    }
    # every call the client has is in the list, so one added later is one this test is asked about
    have = {n for n, f in vars(xc.XeClient).items()
            if not n.startswith("_") and (inspect.iscoroutinefunction(f) or inspect.isasyncgenfunction(f))}
    assert set(calls) == have - {"aclose", "ready"}

    def as_json(status):
        return httpx.Response(status, json={"error": secret}, extensions={"reason_phrase": secret.encode()})

    def as_page(status):
        return httpx.Response(status, content=f"<html><h1>Bad gateway</h1>{secret}</html>".encode(),
                              extensions={"reason_phrase": secret.encode()})
    caplog.set_level(logging.DEBUG, logger=xc.log.name)
    for status in (400, 401, 403, 409, 413, 429, 500, 502, 503):
        for body in (as_json, as_page):
            reply["v"] = lambda request, s=status, b=body: b(s)
            for name, call in calls.items():
                caplog.clear()
                with pytest.raises(xc.XeError) as e:
                    await call()
                err = e.value
                assert err.status == status, (name, status, str(err))
                for shown in (str(err), err.message, reason(err), repr(err.args)):
                    assert secret not in shown and "10.0.0.12" not in shown, (name, status, shown)
                assert secret in err.said, (name, status)
                assert any(secret in r.getMessage() and r.levelno == logging.WARNING for r in caplog.records), (name, status)
    # a 404 is the node's way of saying "not there": worded the same way, and not logged as a fault
    reply["v"] = lambda request: as_json(404)
    caplog.clear()
    with pytest.raises(xc.XeError) as e:
        await c.block("b" * 64)
    assert e.value.status == 404 and secret not in str(e.value) and secret in e.value.said
    assert [r.levelno for r in caplog.records if secret in r.getMessage()] == [logging.DEBUG]
    # /ready is stored by the health check and returned by the public health route: flags and counts only
    for status in (200, 503):
        reply["v"] = lambda request, s=status: httpx.Response(s, json={"status": secret, "error": secret, "synced": False, "peers": 0})
        ok, said = await c.ready()
        # and of an answer that is not a 200, nothing but its status: the names of its fields are its text too
        assert ok is (status == 200) and said == ({"synced": False, "peers": 0, "http_status": 200} if ok else {"http_status": status})
        reply["v"] = lambda request, s=status: httpx.Response(s, json={f"upstream-10.0.0.12-{secret}": True, "request_id": 88213})
        ok, said = await c.ready()
        assert secret not in json.dumps(said) and (ok or said == {"http_status": status})
        reply["v"] = lambda request, s=status: as_page(s)
        assert await c.ready() == (status == 200, {"http_status": status})
    await c.aclose()


# ---- XE-14105 / XE-14164 / XE-14180: what is kept of a node's answer is what was asked for, at a bounded size ----

async def test_a_node_answer_is_kept_as_its_named_fields_at_a_bounded_size():
    """The rule: of an object a node returns, the harness keeps the fields it reads, each an integer, a
    flag or a string of bounded length, and an answer is read within a bound set for what it is. Asserted
    over every read that returns an object or a list of them."""
    import httpx

    from xe import client as xc
    a, proof = "a" * 64, {"account": "a" * 64, "challenge": "00", "signature": "00", "pub_key": "00"}
    reply = {}
    c = _node(lambda request: httpx.Response(200, content=reply["v"]))
    big = "x" * 50_000
    extra = {"padding": big, "nested": {"a": [big]}, "list": [1, 2, 3]}

    def kept(v):
        """Everything in `v` is a bounded scalar: nothing of the padding came through."""
        if isinstance(v, dict):
            return all(len(str(k)) <= xc.MAX_FIELD_CHARS and kept(x) for k, x in v.items())
        if isinstance(v, (list, tuple)):
            return all(kept(x) for x in v)
        return v is None or isinstance(v, (bool, int)) or (isinstance(v, str) and len(v) <= xc.MAX_FIELD_CHARS)

    block = {"type": "send", "account": a, "previous": "0", "asset": "XE", "balance": 5, "amount": 1, "timestamp": 2,
             "hash": "h" * 64, "finalized": True}
    # each read, with an answer that is what it returns plus fields nobody asked for
    reads = [
        (lambda: c.block("h" * 64), {**block, **extra}),
        (lambda: c.chain(a), {"blocks": [{**block, **extra}], "total": 1, **extra}),
        (lambda: c.full_chain(a), {"blocks": [{**block, **extra}], "total": 1, **extra}),
        (lambda: c.chain_end(a), {"blocks": [{**block, **extra}], "total": 1, **extra}),
        (lambda: c.pending_for(a), {"pending": [{"send_hash": "s" * 64, "amount": 1, "asset": "XE", **extra}], **extra}),
        (c.statechain_tip, {"index": 4, "timestamp": 9, "hash": "4" * 64, **extra}),
        (lambda: c.statechain_block(4), {"index": 4, "timestamp": 9, "hash": "4" * 64, "ops": [extra], **extra}),
        (c.node, {"network_id": "xe-test", "id": "n", "version": "1", "pow_difficulty": "ff", **extra}),
        (lambda: c.directory(a), {"account": a, "name": "dao", **extra}),
        (lambda: c.keyset_of(a), {"keys": ["ab" * 32], "threshold": 1, **extra}),
        (c.dao_keyset, {"keys": ["ab" * 32], "threshold": 1, **extra}),
        (c.chat_challenge, {"challenge": "ab" * 16, **extra}),
        (lambda: c.balances(a), {"balances": {"XE": 5}, **extra}),
    ]
    for call, answer in reads:
        reply["v"] = json.dumps(answer).encode()
        got = await call()
        assert got and kept(got), got
        assert big not in json.dumps(got)
    # a field the harness does read, at a length no such field has, is refused and not cut short
    for call, answer in ((lambda: c.block("h" * 64), {**block, "hash": big}), (lambda: c.chain(a), {"blocks": [{**block, "memo": big}], "total": 1}),
                         (lambda: c.pending_for(a), {"pending": [{"send_hash": big, "amount": 1}]}),
                         (lambda: c.statechain_block(4), {"index": 4, "hash": big}), (c.node, {"network_id": big})):
        reply["v"] = json.dumps(answer).encode()
        with pytest.raises(xc.XeError) as e:
            await call()
        assert e.value.status == 0 and "longer than" in e.value.message, e.value.message

    # a state value is read within its own bound, not the general one (XE-14164)
    reply["v"] = json.dumps({"key": "dao.x", "value": "v" * 1000}).encode()
    assert await c.statechain_key("dao.x") == "v" * 1000
    reply["v"] = json.dumps({"key": "dao.x", "value": "v" * xc.MAX_STATE_VALUE_BYTES}).encode()
    with pytest.raises(xc.XeError) as e:
        await c.statechain_key("dao.x")
    assert e.value.status == 0 and str(xc.MAX_STATE_VALUE_BYTES) in e.value.message
    assert xc.MAX_STATE_VALUE_BYTES < xc.MAX_BODY_BYTES

    # an answer of more values than any honest one holds is refused before it is parsed: each empty object
    # is three bytes on the wire and a Python object in memory
    reply["v"] = b"[" + b"{}," * xc.MAX_VALUES + b"{}]"
    assert len(reply["v"]) < xc.MAX_BODY_BYTES
    for call in (lambda: c.chain(a), lambda: c.pending_for(a), lambda: c.statechain_block(4)):
        with pytest.raises(xc.XeError) as e:
            await call()
        assert e.value.status == 0 and "more than" in e.value.message, e.value.message
    # and a read whose answer is a short object is not read past the size of one, whatever is sent
    assert xc.MAX_STATE_VALUE_BYTES <= xc.MAX_SMALL_BYTES < len(reply["v"])
    small = (c.node, c.ready, c.statechain_tip, c.dao_keyset, c.chat_challenge, lambda: c.keyset_of(a), lambda: c.balances(a),
             lambda: c.directory(a), lambda: c.block("h" * 64))
    for call in small:
        with pytest.raises(xc.XeError) as e:
            await call()
        assert e.value.status == 0 and f"exceeds {xc.MAX_SMALL_BYTES}" in e.value.message, e.value.message
    reply["v"] = json.dumps({"account": a, **{f"field{i}": i for i in range(1000)}}).encode()
    assert len(await c.directory(a)) == xc.MAX_PLAIN_FIELDS, "and of the fields nobody named, a bounded number are kept"

    # the chat store: as many items as a node keeps for an account, each no longer than an envelope, and
    # kept only if it is shaped like one (XE-14180)
    env = {"id": "1", "from": a, "to": a, "message": "hello", "timestamp": 1, "signature": "s", "pub_key": "p", "pow_nonce": 1}
    reply["v"] = json.dumps([env, {**env, "id": "2", "nested": {"a": 1}}, {}, 5, "x", [env], {**env, "id": "3"}]).encode()
    assert [m.get("id") for m in await c.chat_messages(proof)] == ["1", None, "3"], "one item that is not an envelope costs that item"
    reply["v"] = b"[" + b",".join([b"{}"] * (xc.CHAT_STORE_ENVELOPES + 1)) + b"]"
    with pytest.raises(xc.XeError) as e:
        await c.chat_messages(proof)
    assert "more than" in e.value.message
    reply["v"] = json.dumps([{**env, "message": "m" * (xc.MAX_ENVELOPE_JSON_CHARS + 1)}]).encode()
    with pytest.raises(xc.XeError) as e:
        await c.chat_messages(proof)
    assert "longer than any envelope" in e.value.message
    await c.aclose()


# ---- XE-14160: a block of ours names a tip and a balance that were true at one moment ------------------------

async def test_a_block_is_built_on_a_tip_and_a_balance_read_at_one_moment(monkeypatch):
    """The rule: every block the harness builds on an account chain takes its `previous` and the balance
    it leaves from one moment of that chain, and where the chain grew between the two reads nothing is
    built. The sites are the two that build one: `_tip` (a receive) and `_build_out` (a send, a burn)."""
    from dao import chainops
    from xe.client import XeError
    monkeypatch.setattr(chainops, "_offered", {})
    kp = KeyPair.generate()
    send_hash = "5" * 64

    class Node:
        """An account whose chain grows by one block as its balance is read, `moves` times."""

        def __init__(self, moves):
            self.moves, self.height, self.submitted = moves, 3, []

        def _hash(self):
            return f"{self.height:064x}"

        async def tip(self, address):
            return self._hash()

        async def chain_end(self, address):
            return self.height, {"hash": self._hash(), "finalized": True}

        async def balances(self, address):
            if self.moves:
                self.moves, self.height = self.moves - 1, self.height + 1
            return {"XE": 1000 * self.height}

        async def pending_for(self, address):
            return [{"send_hash": send_hash, "source": "s", "destination": address, "amount": 7, "asset": "XE", "timestamp": 0}]

        async def submit_block(self, block):
            self.submitted.append(block)

    def ctx_for(node):
        return SimpleNamespace(chain=node, signer=SimpleNamespace(keypair=lambda name, scope: kp),
                               node=SimpleNamespace(network_id="xe-test", pow_difficulty=0))

    async def not_paused():
        return False
    still = f"{3:064x}"
    # a chain that stays where it is: the pair is the pair, and the block names it
    assert await chainops._tip(Node(0), kp.address) == (still, {"XE": 3000})
    builders = {"send": lambda ctx: chainops.build_send(ctx, "fee", "block.send", "d" * 64, 500),
                "burn": lambda ctx: chainops.build_burn(ctx, "fee", "block.burn", 500)}
    for type_, build in builders.items():
        out = await build(ctx_for(Node(0)))
        assert (out["type"], out["previous"], out["balance"], out["at"]) == (type_, still, 2500, 3)
    node = Node(0)
    assert await chainops.receive_pending(ctx_for(node), "fee", not_paused) == 1
    assert (node.submitted[0].previous, node.submitted[0].balance, node.submitted[0].source) == (still, 3007, send_hash)
    # a chain that grew between the reads: a tip from before the block and a balance from after it are
    # not a pair, and nothing is built or offered on them
    with pytest.raises(XeError) as e:
        await chainops._tip(Node(1), kp.address)
    assert e.value.transient and "moved" in e.value.message
    for type_, build in builders.items():
        with pytest.raises(XeError) as e:
            await build(ctx_for(Node(1)))
        assert e.value.transient and "moved" in e.value.message, type_
    chainops._offered.clear()
    node = Node(1)
    assert await chainops.receive_pending(ctx_for(node), "fee", not_paused) == 0
    assert node.submitted == [] and chainops._offered == {}, "and the send is held to nothing: it was offered nothing"
    # the pass after it reads a chain that has stopped moving, and builds
    assert await chainops.receive_pending(ctx_for(node), "fee", not_paused) == 1
    assert (node.submitted[0].previous, node.submitted[0].balance) == (f"{4:064x}", 4007)


# ---- sibling sweep of the seventh pass: the rules above, at the sites the reports did not name -------------

def test_a_schedule_gives_a_name_once_a_matter_is_in_one_list_and_a_scope_is_in_the_glossary(tmp_path):
    """XE-14108 and XE-14107 at the sites beside the ones reported: a name given twice in any of the
    files (YAML keeps the last and says nothing), a matter the agents both decide and do not, and a seat
    whose scopes were checked against a glossary that is not there."""
    import copy
    import shutil

    import yaml

    from dao.config import _OneOfEachName, schedule_b_faults, schedule_c_faults
    d = tmp_path / "config"
    shutil.copytree(ROOT / "config", d)
    load_config(d)
    for name in ("schedule_b.yaml", "schedule_c.yaml", "registry.yaml", "copy/public.yaml", "copy/legal.yaml", "copy/kill_list.yaml"):
        text = (d / name).read_text(encoding="utf-8")
        top = next(line.split(":")[0] for line in text.splitlines() if line[:1].isalpha() and ":" in line)
        (d / name).write_text(f"{text}\n{top}: 1\n", encoding="utf-8")
        with pytest.raises(ValueError, match="a second time") as e:
            load_config(d)
        assert name.rpartition("/")[2] in str(e.value) and repr(top) in str(e.value), name
        (d / name).write_text(text, encoding="utf-8")
    load_config(d)

    def read(text):
        return yaml.load(text, Loader=_OneOfEachName)
    with pytest.raises(ValueError, match="'fee_micro_xe' a second time"):
        read("open_vote:\n  fee_micro_xe: 1\n  quorum_wallets: 3\n  fee_micro_xe: 2\n")   # inside a section too
    with pytest.raises(ValueError, match="a second time"):
        read("seats:\n  - {id: a, id: b}\n")
    # one name in two mappings is two names
    assert read("a: {b: 1}\nc: {b: 2}\n") == {"a": {"b": 1}, "c": {"b": 2}}
    # a merge key splices names in without their being read as a mapping, so it is refused with them
    for merged in ("x: &x {a: 1, b: 1}\ny: {<<: *x, a: 2}\n", "y:\n  <<: {a: 1, a: 2}\n  b: 1\n"):
        with pytest.raises(ValueError, match="merges another mapping in"):
            read(merged)

    c = load_config(ROOT / "config")
    c.schedule_b, c.schedule_c = copy.deepcopy(c.schedule_b), copy.deepcopy(c.schedule_c)
    assert schedule_b_faults(c) == [] and schedule_c_faults(c) == []
    decided = c.schedule_b["agents_decide"][0]
    c.schedule_b["agents_do_not_decide"].append(f" {decided.upper()} ")
    faults = schedule_b_faults(c)
    assert len(faults) == 1 and faults[0].startswith("agents_decide and agents_do_not_decide both hold"), faults
    scoped = [s for s in c.schedule_c["agent_seats"] if s.get("tool_scopes")]
    del c.schedule_c["tool_scopes"]
    faults = schedule_c_faults(c)
    assert scoped and len(faults) == len(scoped) and all("from the glossary" in f for f in faults), faults


def test_a_registration_and_an_envelope_are_built_only_as_their_verifiers_accept_them():
    """XE-3020 and XE-3108 at the two builders they did not name. A registration signs its timestamp as
    decimal digits, so it is an integer in the field or the encoder refuses; and neither builder signs
    (or searches a proof of work for) what its own verifier refuses for an empty field."""
    import dataclasses

    from xe.chat import ChatError, new_envelope
    from xe.directory import DirectoryError, canonical_bytes, new_registration, verify_registration
    kp, to = KeyPair.generate(), "cd" * 32
    for ts in (True, 1.5, "5", -1, 2**64, None):
        with pytest.raises(DirectoryError, match="registration timestamp"):
            canonical_bytes("xe-test", "a", "b", "peer", ts)
    for ts in (True, 1.5, "5", -1, 2**64):
        with pytest.raises(DirectoryError):
            new_registration(kp, "xe-test", "peer", timestamp_ns=ts)
    for peer, ts, says in (("", None, "missing node_peer"), ("peer", 0, "missing timestamp")):
        with pytest.raises(DirectoryError, match=says):
            new_registration(kp, "xe-test", peer, timestamp_ns=ts)
    reg = new_registration(kp, "xe-test", "peer", timestamp_ns=2**64 - 1)
    verify_registration(reg, "xe-test")
    with pytest.raises(DirectoryError):
        verify_registration(dataclasses.replace(reg, timestamp=True), "xe-test")   # 1 to Python, "True" to `str`
    # refused, not searched for: at this difficulty a search would end in TimeoutError
    for kw, says in (({"to": ""}, "recipient is empty"), ({"to": to, "timestamp_ns": 0}, "timestamp is zero")):
        with pytest.raises(ChatError, match=says):
            new_envelope(kp, kw.pop("to"), "x", difficulty=2**64 - 1, deadline_s=0.01, **kw)


async def test_a_refusal_to_authorise_is_the_nodes_answer_and_not_the_accounts(monkeypatch):
    """A definite refusal to read one account's chain is that account's answer and it weighs nothing
    (XE-1706). A 401, 403 or 407 is not one: it is about who asked, and since every refusal is worded
    alike (XE-14195) the status is all that tells them apart. It waits, as a node that did not answer."""
    from dao.services import portal
    from xe.client import XeError
    ctx = SimpleNamespace(chain=None)
    for status, the_accounts in ((413, True), (400, True), (422, True), (401, False), (403, False), (407, False),
                                 (503, False), (0, False)):
        async def snapshot(chain, account, at, asset, _status=status):
            raise XeError(_status, "refused", said="said by whatever answered")     # as the client raises it
        monkeypatch.setattr(portal, "account_snapshot", snapshot)
        if not the_accounts:
            with pytest.raises(XeError):
                await portal.eligibility_at(ctx, {}, 5, "a" * 64, False)
            continue
        snap, reasons, participating, weight = await portal.eligibility_at(ctx, {}, 5, "a" * 64, False)
        assert snap["unreadable"] and not participating and weight == 0, status
        assert "said by whatever answered" not in json.dumps([snap, reasons]), status


async def test_a_reply_is_not_queued_to_a_message_that_names_no_sender():
    from dao.services import inbox
    v = SimpleNamespace(payload={"text": "hello"}, actor="seat:founder-a", seat=SimpleNamespace(id="founder-a"))
    with pytest.raises(HTTPException) as e:
        await inbox.reply(None, None, SimpleNamespace(from_account=""), v)   # refused before anything is read or written
    assert e.value.status_code == 409 and "no sender" in e.value.detail
