"""`dao` command line: keys, offline signing, log verification, copy lint, registry preview."""

from __future__ import annotations

import asyncio
import getpass
import json
import os
from pathlib import Path

import typer

from xe.keys import KeyPair, derive_address

app = typer.Typer(help="XE DAO harness tools", no_args_is_help=True)
keys_app = typer.Typer(help="Company key file (harness, dao, fee, agent:<id>)", no_args_is_help=True)
app.add_typer(keys_app, name="keys")


def _settings():
    from .settings import get_settings
    return get_settings()


def _passphrase(explicit: str | None) -> str:
    return explicit or os.environ.get("DAO_SIGNER_PASSPHRASE") or getpass.getpass("signer passphrase: ")


# ---- keys -------------------------------------------------------------------------------------

@keys_app.command("init")
def keys_init(path: Path = typer.Option(None, help="defaults to DAO_SIGNER_KEYFILE"), passphrase: str = typer.Option(None)):
    """Create the encrypted keyfile with harness, dao and fee keys. Prints addresses to publish."""
    from .signer import Signer
    p = path or _settings().signer_keyfile
    infos = Signer.init_keyfile(p, _passphrase(passphrase))
    typer.echo(f"wrote {p}")
    for i in infos.values():
        typer.echo(f"  {i.name:10} pub {i.public_key}  account {i.address}  scopes {','.join(i.scopes)}")
    typer.echo("\nPut the dao and fee accounts into config/schedule_c.yaml → accounts. Neither needs funding: "
               "the fee account only ever refunds or burns what it received.")


@keys_app.command("add")
def keys_add(name: str, path: Path = typer.Option(None), passphrase: str = typer.Option(None)):
    """Add a key (e.g. agent:research) to the keyfile."""
    from .signer import Signer
    p = path or _settings().signer_keyfile
    i = Signer.add_key(p, _passphrase(passphrase), name)
    typer.echo(f"{i.name} pub {i.public_key} account {i.address} scopes {','.join(i.scopes)}")


@keys_app.command("show")
def keys_show(path: Path = typer.Option(None), passphrase: str = typer.Option(None)):
    """List keys, public keys, accounts and scopes. Never prints seeds."""
    from .signer import Signer
    p = path or _settings().signer_keyfile
    s = Signer.load(p, _passphrase(passphrase))
    for i in s.infos():
        typer.echo(f"{i.name:12} pub {i.public_key}  account {i.address}  scopes {','.join(i.scopes)}")


@keys_app.command("new-seat-key")
def new_seat_key():
    """Generate a personal ed25519 key for a seat holder. Run this on YOUR machine, not the server.
    Keep the seed; publish the public key in schedule_c.yaml."""
    kp = KeyPair.generate()
    typer.echo(f"seed (secret, keep offline): {kp.seed.hex()}")
    typer.echo(f"public key (publish):         {kp.pub_key_hex}")
    typer.echo(f"account address:              {kp.address}")


# ---- offline signing ------------------------------------------------------------------------

@app.command("sign")
def sign(digest: str = typer.Option(..., help="32-byte hex digest shown by the web form"),
         seed: str = typer.Option(None, help="64-hex seed; or set XE_SEED")):
    """Sign a digest offline with a personal key (for browsers without Ed25519 WebCrypto)."""
    s = seed or os.environ.get("XE_SEED") or getpass.getpass("seed hex: ")
    kp = KeyPair.from_seed_hex(s)
    typer.echo(json.dumps({"pub_key": kp.pub_key_hex, "signature": kp.sign_hex(bytes.fromhex(digest))}))


@app.command("sign-request")
def sign_request(domain: str = typer.Argument(..., help="e.g. xe-dao/vote/v1"),
                 payload: str = typer.Argument(..., help="JSON payload"),
                 seed: str = typer.Option(None, help="64-hex seed; or set XE_SEED"),
                 pow_difficulty: str = typer.Option(None, "--pow", help="hex difficulty from GET /v1/inbox; adds pow_nonce")):
    """Produce a complete SignedRequest body for curl."""
    import time
    from .auth import compute_http_pow
    from .canonical import digest as _digest
    s = seed or os.environ.get("XE_SEED") or getpass.getpass("seed hex: ")
    kp = KeyPair.from_seed_hex(s)
    p = json.loads(payload)
    ts = time.time_ns()
    d = _digest(domain.encode() + b"\x00", {"payload": p, "timestamp": ts})
    out = {"payload": p, "timestamp": ts, "pub_key": kp.pub_key_hex, "signature": kp.sign_hex(d)}
    if pow_difficulty:
        out["pow_nonce"] = compute_http_pow(d, int(pow_difficulty, 16))
    typer.echo(json.dumps(out))


@app.command("address")
def address(pub_key: str):
    """Account address for a public key."""
    typer.echo(derive_address(pub_key))


# ---- log, copy, registry --------------------------------------------------------------------

@app.command("verify-log")
def verify_log():
    """Replay the event log and check every hash and signature."""
    from .db import session
    from .log import EventLog

    async def go():
        async with session() as db:
            return await EventLog.verify(db)
    res = asyncio.run(go())
    typer.echo(json.dumps(res, indent=1))
    raise typer.Exit(0 if res["ok"] else 1)


@app.command("copy-lint")
def copy_lint(config_dir: Path = typer.Option(None)):
    """Fail if any kill-list phrase appears in the public copy register or public templates."""
    from .config import lint_public_copy, load_config
    cfg = load_config(config_dir or _settings().config_dir)
    tpl_dir = Path(__file__).parent / "templates"
    public_templates = ["home.html", "proposals.html", "proposal.html", "proposal_new.html", "seats.html", "decisions.html",
                        "inbox.html", "log.html", "log_entry.html", "base.html"]
    extra = []
    for name in public_templates:
        p = tpl_dir / name
        if p.exists():
            # strip Jinja and HTML roughly; lint the prose
            import re
            text = re.sub(r"{[{%#].*?[}%#]}", " ", p.read_text(encoding="utf-8"), flags=re.S)
            text = re.sub(r"<script.*?</script>", " ", text, flags=re.S)
            text = re.sub(r"<[^>]+>", " ", text)
            extra.append(text)
    v = lint_public_copy(cfg, extra)
    if v:
        for line in v:
            typer.echo(f"  {line}")
        typer.echo(f"{len(v)} violation(s)")
        raise typer.Exit(1)
    typer.echo("clean")


@app.command("registry")
def registry_preview():
    """Print the dao.registry value as it would be written, with its compact byte form and sha256."""
    import hashlib
    from xe.statechain import compact_json
    from .context import build_context
    from .services.records import registry_value
    ctx = build_context()
    val = registry_value(ctx)
    raw = compact_json(val)
    typer.echo(json.dumps(val, indent=1))
    typer.echo(f"\ncompact bytes: {len(raw.encode())}  sha256 {hashlib.sha256(raw.encode()).hexdigest()}")


@app.command("health")
def health():
    """One-off health check against the node and database."""
    from .context import build_context
    from .db import session
    from .services.records import health as _health

    async def go():
        ctx = build_context()
        await ctx.refresh_node()
        async with session() as db:
            return await _health(ctx, db)
    typer.echo(json.dumps(asyncio.run(go()), indent=1, default=str))


if __name__ == "__main__":
    app()
