"""Every template parses; public templates pass the copy lint."""

import re
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from dao.config import LEGAL_TEMPLATES, PUBLIC_TEMPLATES, lint_public_copy, load_config, public_template_prose

ROOT = Path(__file__).resolve().parents[1]
TPL = ROOT / "dao" / "templates"


def test_templates_parse():
    env = Environment(loader=FileSystemLoader(str(TPL)))
    for p in sorted(TPL.glob("*.html")):
        env.parse(p.read_text(encoding="utf-8"), filename=str(p))


def test_no_dict_method_shadowing():
    """Jinja resolves `d.keys` to dict.keys (the method), not d["keys"]. Data keys that collide with dict
    method names must use subscript syntax. Found the hard way on /records."""
    bad = re.compile(r"\b\w+\.(keys|values|items|get|update|pop|copy|clear)\b(?!\()")
    hits = []
    for p in sorted(TPL.glob("*.html")):
        text = re.sub(r"<script.*?</script>", " ", p.read_text(encoding="utf-8"), flags=re.S)
        for m in re.finditer(r"{[{%].*?[}%]}", text, flags=re.S):
            if bad.search(m.group(0)):
                hits.append(f"{p.name}: {m.group(0)}")
    assert hits == []


def test_example_decision_record_is_complete_and_public_register():
    """The worked example at /decisions/example defines the record shape; keep it whole and clean."""
    import yaml
    from dao.config import _flatten_strings
    rec = yaml.safe_load((ROOT / "config" / "examples" / "decision_record.yaml").read_text(encoding="utf-8"))
    assert rec["example"] is True
    for key in ("item", "inputs", "seats", "rebuttals", "risk_review", "synthesis", "cost", "human_decision", "execution"):
        assert key in rec, key
    cfg = load_config(ROOT / "config")
    seat_ids = {a.id for a in cfg.agent_seats}
    for s in rec["seats"] + [rec["risk_review"]]:
        assert s["seat"] in seat_ids, s["seat"]
        for field in ("model", "prompt_hash", "position", "confidence", "summary", "counter_argument", "would_change_my_mind"):
            assert field in s, f"{s['seat']} missing {field}"
    assert rec["synthesis"]["seat"] == "orchestrator"
    assert {"recommendation", "confidence", "dissent", "would_change_my_mind", "reasons"} <= set(rec["synthesis"])
    assert lint_public_copy(cfg, _flatten_strings(rec)) == []


def test_public_templates_pass_copy_lint():
    """One list, held by the package and read by the command and by this test (XE-5986): every template
    file is in exactly one register, and every public one is clean."""
    cfg = load_config(ROOT / "config")
    on_disk = sorted(p.name for p in TPL.glob("*.html"))
    assert sorted([*PUBLIC_TEMPLATES, *LEGAL_TEMPLATES]) == on_disk, "a template belongs to one register"
    assert len(public_template_prose()) == len(PUBLIC_TEMPLATES)
    assert lint_public_copy(cfg, public_template_prose()) == []
    # the command is this check and nothing narrower
    import inspect

    from dao import cli
    assert "public_template_prose()" in inspect.getsource(cli.copy_lint) and ".html" not in inspect.getsource(cli.copy_lint)


def test_page_scripts_run_after_the_signer_they_call():
    """XE-8209. A page's own script runs as the body ends and calls `$`, `$$`, `say` and `XeSigner`, which
    signer.js defines. So signer.js is an ordinary blocking script in base.html's head, before the scripts
    block, and every template with a scripts block gets it from base.html."""
    base = (TPL / "base.html").read_text(encoding="utf-8")
    tags = re.findall(r"<script\b[^>]*signer\.js[^>]*>", base)
    assert len(tags) == 1 and not re.search(r"\b(defer|async|type=)", tags[0]), tags
    assert base.index(tags[0]) < base.index("</head>") < base.index("{% block scripts %}")
    pages = [p for p in sorted(TPL.glob("*.html")) if "{% block scripts %}" in p.read_text(encoding="utf-8") and p.name != "base.html"]
    assert {p.name for p in pages} >= {"proposal_new.html", "proposal.html", "inbox.html", "members.html"}
    for p in pages:
        text = p.read_text(encoding="utf-8")
        assert text.startswith('{% extends "base.html" %}'), p.name
        assert "signer.js" not in text, f"{p.name}: the signer is loaded once, by base.html"
    # and the page says which deployment its signatures are for (XE-2068): the signer reads it from <html>
    assert 'data-dao="{{ dao_account }}"' in base and 'data-network="{{ network_id }}"' in base


def test_the_agent_vote_rule_is_stated_once_and_is_the_rule_the_tally_applies():
    """XE-5988. Three pages describe how agent seats vote; they call one macro, and nothing else in the
    templates states the stipend or the share."""
    from dao.ui import templates
    cfg = load_config(ROOT / "config")
    said = templates.env.get_template("_rules.html").module.agent_vote(cfg)
    share = int(cfg.open_vote["agents"]["max_weight_share"] * 100)
    assert f"at most {share}% of the weight humans decided with (for plus against)" in said
    assert "what its account holds at the snapshot" in said and "fixed" not in said
    for name in ("how.html", "seat.html", "seats.html"):
        assert "{{ rules.agent_vote(cfg) }}" in (TPL / name).read_text(encoding="utf-8"), name
    for p in sorted(TPL.glob("*.html")):
        if p.name != "_rules.html":
            text = p.read_text(encoding="utf-8")
            assert "max_weight_share" not in text and "stipend_micro_xe" not in text, p.name



# ---- XE-7744: the log entry page prints the recipe its entry was hashed under, and every input to it -------

def test_the_log_entry_page_recipe_reproduces_the_hash_of_the_entry_it_is_on():
    import hashlib
    from types import SimpleNamespace

    from dao.canonical import canonical_json
    from dao.log import event_hash
    from dao.ui import templates
    tmpl = templates.env.get_template("log_entry.html")
    copy = SimpleNamespace(labels=SimpleNamespace(log="Log"))
    fields = dict(index=7, ts=1_794_000_000_000_000_000, kind="note.test", actor="harness", payload={"a": [1, "x"]}, prev_hash="ab" * 32)
    seen = set()
    for v, public, ref in ((1, True, ""), (2, True, "proposal:" + "c" * 64), (2, True, "")):
        h = event_hash(**fields, public=public, ref=ref, v=v)
        e = SimpleNamespace(**fields, hash=h, public=public, ref=ref, v=v, signer="", signature="")
        html = "".join(tmpl.blocks["content"](tmpl.new_context({"e": e, "copy": copy})))
        recipe = re.search(r'id="recipe">hash = sha256\("(xe-dao/event/v\d)\\0" \|\| canonical_json\(\{([a-z_, ]+)\}\)\)', html)
        assert recipe, html
        domain, names = recipe.group(1), recipe.group(2).split(", ")
        assert domain == f"xe-dao/event/v{v}"
        # a reader who follows the line, with the values the page shows, gets the hash the page shows
        body = {n: getattr(e, n) for n in names}
        assert hashlib.sha256(domain.encode() + b"\x00" + canonical_json(body)).hexdigest() == h, v
        assert f"<th>v</th><td>{v}</td>" in html and "<th>public</th><td>true</td>" in html
        assert f"<code>{e.ts}</code>" in html and f"<code>{e.prev_hash}</code>" in html
        assert f'<code>"{ref}"</code>' in html, "ref is shown as the JSON string that is hashed, empty or not"
        seen.add(domain)
    assert seen == {"xe-dao/event/v1", "xe-dao/event/v2"}
    assert event_hash(**fields, public=True, ref="", v=1) != event_hash(**fields, public=True, ref="", v=2)


# ---- XE-9465: the live page's stream starts from what the page was rendered with ---------------------------

def test_the_live_page_opens_its_stream_after_the_newest_entry_it_rendered():
    from types import SimpleNamespace

    from dao.ui import templates
    tmpl = templates.env.get_template("live.html")
    script = "".join(tmpl.blocks["scripts"](tmpl.new_context({"events": [SimpleNamespace(index=41), SimpleNamespace(index=40)]})))
    assert "var newest = 41;" in script
    assert "new EventSource('/v1/events' + (newest >= 0 ? '?after=' + newest : ''))" in script
    assert "e.index <= newest) return;" in script and "newest = e.index;" in script, "what both halves hold is shown once"
    empty = "".join(tmpl.blocks["scripts"](tmpl.new_context({"events": []})))
    assert "var newest = -1;" in empty
    assert "new EventSource('/v1/events')" not in script


# ---- XE-9345 / XE-7018 / XE-6758 / XE-4714 / XE-10590: a document names only what exists -------------------

def test_the_documents_name_tests_endpoints_and_rules_that_exist():
    deploy = (ROOT / "docs" / "DEPLOY.md").read_text(encoding="utf-8")
    defined = set(re.findall(r"^(?:async )?def (test_\w+)\(", "".join(p.read_text(encoding="utf-8") for p in (ROOT / "tests").glob("test_*.py")), flags=re.M))
    named = set(re.findall(r"`(test_\w+)`", deploy))
    assert named and named <= defined, named - defined
    # the node's read endpoints, as the client asks for them and as MAINNET_REQS lists them
    client = (ROOT / "xe" / "client.py").read_text(encoding="utf-8")
    asked = set(re.findall(r'(?:_get|_found)\(f?"(/[^"]*)"', client)) | set(re.findall(r'\("GET", "(/[^"]*)"', client))
    asked = {re.sub(r"\{[^}]*\}", "{}", p) for p in asked}
    reqs = (ROOT / "docs" / "MAINNET_REQS.md").read_text(encoding="utf-8")
    table = reqs[reqs.index("## 2."):reqs.index("## 3.")]
    listed = {re.sub(r"\{[^}]*\}", "{}", p) for p in re.findall(r"`GET (/[^`]*)`", table)}
    assert asked == listed, f"asked and not listed: {asked - listed}; listed and not asked: {listed - asked}"
    assert "leading-zero" not in reqs and "at least the difficulty" in reqs
    # the settlement the README describes is the one fees.py performs
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    fees_src = (ROOT / "dao" / "services" / "fees.py").read_text(encoding="utf-8")
    assert "the nonce rides in the memo" not in readme and "committed to the row before it is offered" in readme
    assert '"settle_block"' in fees_src and "settle_nonce" in fees_src, "the scheme the README now describes"
    assert "sha256(nonce_le8 || signing_digest || pub_key)" in readme
    # the brief's row for /v1/decisions says what the route returns
    brief = (ROOT / "docs" / "BRIEF.md").read_text(encoding="utf-8")
    row = next(ln for ln in brief.splitlines() if ln.startswith("| `GET /v1/decisions`"))
    assert "all decisions across the three paths" not in row and "/v1/legal/resolutions" in row and "/v1/members/sessions" in row
    # and the deployment guide names the setting the harness now refuses to sign without (XE-12620)
    assert "XE_NETWORK_ID" in deploy and "XE_NETWORK_ID=" in (ROOT / ".env.example").read_text(encoding="utf-8")
