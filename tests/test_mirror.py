"""Every page has a markdown twin; /llms.txt reads like the public register."""

from pathlib import Path

from dao.config import lint_public_copy, load_config
from dao.mirror import MarkdownMirror, build_llms_txt, html_to_markdown, md_path, md_target, site_path, wants_markdown

ROOT = Path(__file__).resolve().parents[1]

PAGE = """<!doctype html><html><head><title>Seats · testnet</title></head><body>
<header><nav><a href="/">DAO</a><a href="/proposals">Proposals</a></nav></header>
<main><div class="wrap">
<h1>Seats</h1>
<p class="sub">Nine seats. <a href="/how-it-works">How it works</a>.</p>
<div class="keybox">signer box, never in markdown</div>
<svg viewBox="0 0 10 10" aria-label="Flow: item arrives, people decide"><rect/></svg>
<table><tr><th>Role</th><th>Status</th></tr><tr><td><a href="/seats/research">Research</a></td><td>designed</td></tr></table>
<details><summary>What is a seat?</summary><p>A role with instructions.</p></details>
<form><input type="text"><button>Sign</button></form>
<script>alert(1)</script>
</div></main>
<footer>footer stuff</footer></body></html>"""


def test_md_paths_round_trip():
    assert md_target("/seats.md") == "/seats"
    assert md_target("/seats/legal-and-compliance.md") == "/seats/legal-and-compliance"
    assert md_target("/index.md") == "/"
    assert md_target("/.md") == "/"
    assert md_target("/seats") is None
    assert md_target("/v1/charter.md") is None
    assert md_target("/static/readme.md") is None
    assert md_path("/") == "/index.md"
    assert md_path("/seats/research") == "/seats/research.md"
    for p in ("/", "/seats", "/decisions/example", "/proposals/abc123"):
        assert md_target(md_path(p)) == p


def test_accept_negotiation_leaves_browsers_alone():
    assert wants_markdown("text/markdown")
    assert wants_markdown("text/markdown, text/plain;q=0.9")
    assert not wants_markdown("text/html,application/xhtml+xml,*/*;q=0.8")
    assert not wants_markdown("text/html, text/markdown;q=0.9")
    assert not wants_markdown("")


def test_html_to_markdown_keeps_the_page_and_drops_the_chrome():
    md = html_to_markdown(PAGE, "https://dao.test.network/seats")
    assert md.startswith("<!-- Seats · testnet -->\n*Markdown view of <https://dao.test.network/seats>.")
    assert "# Seats" in md
    assert "[How it works](https://dao.test.network/how-it-works)" in md   # relative links made absolute
    assert "| Role | Status |" in md and "| --- | --- |" in md               # tables survive as GFM
    assert "[Research](https://dao.test.network/seats/research)" in md
    assert "**What is a seat?**" in md and "A role with instructions." in md
    assert "*Flow: item arrives, people decide*" in md                        # the diagram's words, not its shapes
    for gone in ("signer box", "alert(1)", "Sign", "footer stuff", "Proposals"):
        assert gone not in md, gone
    assert "\n\n\n" not in md


def test_user_text_stays_text_in_the_twin():
    """XE-0507: what a page showed as characters cannot become markdown or HTML in the mirror."""
    page = """<html><head><title>x --> y</title></head><body><main>
<h1>A &lt;b&gt;title&lt;/b&gt; [here](http://evil)</h1>
<p class="small">reason: ![img](https://t.example/p.gif) &lt;script&gt;alert(1)&lt;/script&gt; # not a heading</p>
<pre>body
```
# not fenced out
```</pre>
</main></body></html>"""
    md = html_to_markdown(page, "https://dao.test.network/proposals/abc")
    assert md.startswith("<!-- x - -› y -->\n")                     # the title cannot close its own comment
    assert "[here](http://evil)" not in md and "\\[here\\](http://evil)" in md   # brackets escaped: text, not a link
    assert "![img]" not in md and "!\\[img\\]" in md                   # no images
    assert "<script>" not in md and "\\<script\\>" in md               # no raw HTML
    assert "\n# not a heading" not in md
    # the body's own fence cannot close the fence around it
    assert "\n````\nbody\n```\n# not fenced out\n```\n````\n" in md


def test_llms_txt_is_public_register_and_points_at_markdown():
    cfg = load_config(ROOT / "config")
    text = build_llms_txt(cfg, "https://dao.test.network/", "testnet-0005", cfg.mode)
    assert text.startswith("# XE DAO\n\n> ")
    assert lint_public_copy(cfg, [text]) == []
    assert "https://dao.test.network/index.md" in text
    assert "https://dao.test.network/charter.md" in text
    for a in cfg.agent_seats:
        assert f"https://dao.test.network/seats/{a.slug}.md" in text, a.id
    assert "https://dao.test.network/v1/events" in text
    assert "https://dao.test.network//" not in text


# ---- XE-7815 / XE-7861: the request path is the requester's text wherever it is written back ------------

HOSTILE = ["//evil.example/x", "///evil.example/x", "/\\evil.example/x", "/a\n# Heading\n[x](https://evil.example)",
           "/a>[x](https://evil.example)<b", "/a b", '/a"onmouseover="x', "/proposals/abc123/"]


def test_a_link_to_this_site_is_a_path_on_this_site():
    for path in HOSTILE:
        for href in (site_path(path), md_path(path)):
            assert href.startswith("/") and not href.startswith("//"), (path, href)
            assert not set(href) & set('\\<>"\n\r\t '), (path, href)
    assert md_path("//evil.example/x") == "/evil.example/x.md"
    assert site_path("/seats/legal-and-compliance") == "/seats/legal-and-compliance"   # an ordinary path is untouched


async def _twin(path, base_url, accept=b"text/markdown"):
    """The markdown the mirror serves for a request, over a page that links to its own twin as base.html does."""
    async def app(scope, receive, send):
        html = (f'<html><head><title>t</title></head><body><main><p>hi</p>'
                f'<a href="{md_path(scope["path"])}">this page as markdown</a></main></body></html>')
        await send({"type": "http.response.start", "status": 404, "headers": [(b"content-type", b"text/html; charset=utf-8")]})
        await send({"type": "http.response.body", "body": html.encode()})

    sent = []

    async def send(message):
        sent.append(message)

    async def receive():
        return {"type": "http.request", "body": b""}

    scope = {"type": "http", "method": "GET", "scheme": "https", "path": path,
             "headers": [(b"accept", accept), (b"host", b"evil.example")]}
    await MarkdownMirror(app, base_url)(scope, receive, send)
    return sent[1]["body"].decode()


async def test_the_twin_names_this_site_and_its_head_is_one_line_with_one_link():
    for path in HOSTILE:
        for via in (path, path + ".md"):
            md = await _twin(via, "https://dao.test.network", b"text/markdown" if via == path else b"*/*")
            comment, head, blank = md.split("\n")[:3]
            assert comment == "<!-- t -->" and blank == "", (via, md)
            assert head.startswith("*Markdown view of <https://dao.test.network/") and head.endswith("for reading.*"), (via, head)
            assert head.count("<") == 1 and head.count(">") == 1 and "](" not in head and " # " not in head, (via, head)
            assert not head.startswith("*Markdown view of <https://dao.test.network//"), (via, head)
            # every link in the twin is on this site
            import re
            for url in re.findall(r"\]\(([^)]*)\)", md):
                assert url.startswith("https://dao.test.network/") and not url.startswith("https://dao.test.network//"), (via, url)
    # the Host header is the requester's too: with no configured address the twin gives the path, not a host
    md = await _twin("/seats", "")
    assert "evil.example" not in md and "*Markdown view of </seats>." in md

