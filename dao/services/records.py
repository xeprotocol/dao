"""Chain-facing records: dao.registry, weekly anchors, treasury reads, health."""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from xe.client import XeError

from ..context import Context
from ..log import EventLog
from ..models import Anchor, HealthCheck, SigningSession, TreasurySnapshot
from . import sessions


# ---- dao.registry ---------------------------------------------------------------------------

def registry_value(ctx: Context) -> dict:
    """The exact object that goes under dao.registry. Keep key order stable; it is hashed."""
    r = ctx.config.registry
    val = {
        "entity": r.get("entity", ""),
        "jurisdiction": r.get("jurisdiction", ""),
        "form": r.get("form", ""),
        "formation_date": r.get("formation_date", "") or "",
        "registered_office": r.get("registered_office", ""),
        "email": r.get("email", ""),
        "statement": " ".join((r.get("statement", "") or "").split()),
        "update_authority": r.get("update_authority", "sys.dao_keyset"),
        "surfaces": r.get("surfaces", {}),
        "repository": r.get("repository", ""),
        "licence": r.get("licence", ""),
        "charter_sha256": ctx.config.charter_hash,
        "accounts": {k: v for k, v in {
            "dao": ctx.signer.address("dao") if ctx.signer.has("dao") else ctx.config.accounts.get("dao", ""),
            "fee": ctx.signer.address("fee") if ctx.signer.has("fee") else ctx.config.accounts.get("fee", ""),
            "treasury": ctx.config.accounts.get("treasury", ""),
        }.items() if v},
        "log_signer": ctx.signer.public_key("harness") if ctx.signer.has("harness") else "",
        "version": 1,
    }
    return val


async def onchain_registry(ctx: Context) -> dict | None:
    try:
        return await ctx.chain.statechain_key("dao.registry")
    except XeError:
        return None


async def open_registry_session(ctx: Context, db: AsyncSession, actor: str) -> dict:
    ops = [{"action": "set", "key": "dao.registry", "value": registry_value(ctx)}]
    s = await sessions.create(ctx, db, kind="registry", title="Write dao.registry", ops=ops, actor=actor)
    return sessions.to_dict(s)


# ---- anchors ----------------------------------------------------------------------------------

async def latest_anchor(db: AsyncSession) -> Anchor | None:
    return (await db.execute(select(Anchor).order_by(Anchor.n.desc()).limit(1))).scalar_one_or_none()


async def open_anchor_session(ctx: Context, db: AsyncSession, actor: str = "harness") -> dict:
    head = await EventLog.head(db)
    last = await latest_anchor(db)
    n = (last.n + 1) if last else 1
    value = {"n": n, "event_index": head.index, "head_hash": head.hash, "ts": time.time_ns(),
             "prev_anchor": (last.head_hash if last else ""), "log": f"{ctx.settings.public_base_url}/v1/log"}
    ops = [{"action": "set", "key": f"dao.anchor.{n}", "value": value}]
    s = await sessions.create(ctx, db, kind="anchor", title=f"Anchor {n}: log head {head.hash[:12]} at index {head.index}",
                              ops=ops, actor=actor)
    db.add(Anchor(n=n, event_index=head.index, head_hash=head.hash, session_id=s.id))
    return sessions.to_dict(s)


async def note_anchor_submitted(db: AsyncSession, session_id: str, index: int, h: str) -> None:
    a = (await db.execute(select(Anchor).where(Anchor.session_id == session_id))).scalar_one_or_none()
    if a:
        a.statechain_index = index
        a.statechain_hash = h


async def anchors(db: AsyncSession, limit: int = 50) -> list[dict]:
    rows = (await db.execute(select(Anchor).order_by(Anchor.n.desc()).limit(limit))).scalars().all()
    return [{"n": a.n, "event_index": a.event_index, "head_hash": a.head_hash, "session_id": a.session_id,
             "statechain_index": a.statechain_index, "statechain_hash": a.statechain_hash,
             "created_at": a.created_at.isoformat() if a.created_at else None} for a in rows]


# ---- treasury (read-only) ---------------------------------------------------------------------

async def treasury(ctx: Context) -> dict:
    accts = {
        "treasury": ctx.config.accounts.get("treasury", ""),
        "dao": ctx.signer.address("dao") if ctx.signer.has("dao") else ctx.config.accounts.get("dao", ""),
        "fee": ctx.signer.address("fee") if ctx.signer.has("fee") else ctx.config.accounts.get("fee", ""),
    }
    out = {}
    for name, addr in accts.items():
        if not addr:
            out[name] = {"address": "", "balances": {}, "note": "not configured"}
            continue
        try:
            bals = await ctx.chain.balances(addr)
            ks = await ctx.chain.keyset_of(addr) if name == "treasury" else None
            out[name] = {"address": addr, "balances": bals, "keyset": ks}
        except XeError as e:
            out[name] = {"address": addr, "balances": {}, "error": str(e)}
    return out


async def snapshot_treasury(ctx: Context, db: AsyncSession) -> TreasurySnapshot:
    t = await treasury(ctx)
    snap = TreasurySnapshot(ts=time.time_ns(), balances=t)
    db.add(snap)
    return snap


# ---- health -----------------------------------------------------------------------------------

TIP_STALE_S = 6 * 3600        # a tip older than this means the state chain is not advancing
SESSION_AGING_S = 24 * 3600   # a session approving/signing for longer than this is reported
ANCHOR_OVERDUE_S = 14 * 86400  # weekly anchor; twice the cadence without one degrades
STALE_CHECKS = 3               # /v1/health is stale (and not ok) after this many missed cadences
WINDOW_30D_NS = 30 * 86400 * 1_000_000_000


def cadence_s(ctx: Context) -> int:
    return int(ctx.config.cadence.get("health_check_minutes", 10)) * 60


def _keyset_shape(ks: dict | None) -> dict | None:
    if not isinstance(ks, dict) or not isinstance(ks.get("keys"), list):
        return None
    return {"keys": sorted(str(k).lower() for k in ks["keys"]), "threshold": int(ks.get("threshold") or 0)}


async def expected_keyset(db: AsyncSession) -> dict | None:
    """The keyset the members last wrote through a keyset session; before any, the keyset as it was when
    the harness started watching (the earliest health check that saw one)."""
    s = (await db.execute(select(SigningSession).where(SigningSession.kind == "keyset", SigningSession.status == "submitted")
                          .order_by(SigningSession.updated_at.desc()).limit(1))).scalar_one_or_none()
    if s is not None:
        for op in s.ops or []:
            try:
                return _keyset_shape(json.loads(op.get("value", "")))
            except (ValueError, TypeError):
                continue
    first = (await db.execute(select(HealthCheck).where(HealthCheck.detail["keyset"].astext.isnot(None))
                              .order_by(HealthCheck.ts.asc()).limit(1))).scalar_one_or_none()
    return first.detail.get("keyset") if first else None


async def health(ctx: Context, db: AsyncSession, record: bool = False) -> dict:
    """The 10-minute check (BRIEF §8/§9): chain reachable, tip advancing, keyset unchanged, log consistent,
    signer up, last anchor age, pending signatures aging. Each leg compares what it fetches against the
    chain's own timestamps or the members' own records; a leg that cannot fetch records `<leg>_error`; any
    error or mismatch makes `ok` false, which the worker posts as `health.degraded`. A keyset that is not
    the one the members last wrote stays not ok until a keyset session writes it (BRIEF §13)."""
    detail: dict = {"node_url": ctx.settings.xe_node_url, "network_id": ctx.node.network_id}
    ok = True
    now = time.time_ns()
    prev = await last_health(db) or {}

    try:   # chain reachable
        ready, body = await ctx.chain.ready()
        detail["node_ready"] = ready
        detail["node"] = body if isinstance(body, dict) else {"body": str(body)[:200]}
        ok = ok and bool(ready)
    except Exception as e:
        detail["node_ready"] = False
        detail["node_error"] = str(e)[:300]

    try:   # tip advancing
        tip = await ctx.chain.statechain_tip()
        detail["statechain_tip"] = {"index": tip.get("index"), "hash": tip.get("hash"), "timestamp": tip.get("timestamp")}
        age_s = (now - int(tip.get("timestamp", 0))) / 1e9
        detail["statechain_tip_age_s"] = round(age_s)
        if age_s > TIP_STALE_S:
            detail["tip_stale"] = True
            ok = False
    except Exception as e:
        detail["statechain_error"] = str(e)[:300]

    try:   # keyset unchanged
        ks = _keyset_shape(await ctx.chain.dao_keyset())
        if ks is None:
            raise ValueError("node returned no keyset")
        detail["keyset"] = ks
        if prev.get("keyset") and ks != prev["keyset"]:
            await ctx.events.append(db, "keyset.changed", "harness", {"from": prev["keyset"], "to": ks}, public=True)
        expected = await expected_keyset(db)
        if expected and ks != expected:
            detail["keyset_unexpected"] = {"live": ks, "expected": expected}
            ok = False
    except Exception as e:
        detail["keyset_error"] = str(e)[:300]

    try:   # log consistent
        head = await EventLog.head(db)
        detail["log_head"] = {"index": head.index, "hash": head.hash}
        ver = await EventLog.verify_cached(db, ctx.signer.public_key("harness") if ctx.signer.has("harness") else "")
        detail["log_verified"] = bool(ver.get("ok"))
        if not ver.get("ok"):
            detail["log_first_error"] = ver.get("first_error")
            ok = False
    except Exception as e:
        detail["log_error"] = str(e)[:300]

    detail["signer_keys"] = [k.name for k in ctx.signer.infos()]   # signer up
    if not ctx.signer.has("harness"):
        detail["signer_error"] = "no harness key: events cannot be signed"

    try:   # last anchor age
        a = await latest_anchor(db)
        detail["last_anchor"] = {"n": a.n, "age_s": round(now / 1e9 - a.created_at.timestamp())} if a else None
        if a and detail["last_anchor"]["age_s"] > ANCHOR_OVERDUE_S:
            detail["anchor_overdue"] = True
            ok = False
    except Exception as e:
        detail["anchor_error"] = str(e)[:300]

    try:   # pending signatures aging
        cutoff = datetime.fromtimestamp((now - SESSION_AGING_S * 1_000_000_000) / 1e9, tz=timezone.utc)
        aging = (await db.execute(select(SigningSession).where(SigningSession.status.in_(("approving", "signing")),
                                                               SigningSession.created_at < cutoff))).scalars().all()
        detail["sessions_aging"] = [{"id": s.id, "kind": s.kind, "status": s.status,
                                     "signatures": len(s.block_signatures or []), "required": s.required_approvals}
                                    for s in aging]
    except Exception as e:
        detail["sessions_error"] = str(e)[:300]

    dao_addr = ctx.signer.address("dao") if ctx.signer.has("dao") else ""
    if dao_addr:   # directory
        try:
            detail["directory_registered"] = (await ctx.chain.directory(dao_addr)) is not None
        except Exception as e:
            detail["directory_error"] = str(e)[:300]

    errors = sorted(k for k in detail if k.endswith("_error"))
    if errors:
        detail["errors"] = errors
        ok = False
    detail["ok"] = ok
    detail["ts"] = now
    if record:
        db.add(HealthCheck(ts=now, ok=ok, detail=detail))
    return detail


def health_age_s(last: dict | None, now_ns: int | None = None) -> int | None:
    if not last or not last.get("ts"):
        return None
    return round(((now_ns or time.time_ns()) - int(last["ts"])) / 1e9)


def health_is_stale(ctx: Context, last: dict | None, now_ns: int | None = None) -> bool:
    """A check older than STALE_CHECKS cadences means the worker is not running; it is not ok (XE-0908)."""
    age = health_age_s(last, now_ns)
    return age is None or age > STALE_CHECKS * cadence_s(ctx)


async def last_health(db: AsyncSession) -> dict | None:
    row = (await db.execute(select(HealthCheck).order_by(HealthCheck.ts.desc()).limit(1))).scalar_one_or_none()
    return row.detail if row else None


async def uptime_30d(ctx: Context, db: AsyncSession) -> dict:
    """Checks that should have run but did not count as failures, so a stopped worker lowers the figure
    instead of freezing it (XE-0908)."""
    now = time.time_ns()
    since = now - WINDOW_30D_NS
    total = int((await db.execute(select(func.count()).select_from(HealthCheck).where(HealthCheck.ts >= since))).scalar_one())
    good = int((await db.execute(select(func.count()).select_from(HealthCheck).where(HealthCheck.ts >= since, HealthCheck.ok.is_(True)))).scalar_one())
    first = (await db.execute(select(func.min(HealthCheck.ts)))).scalar_one()
    if first is None:
        return {"checks": 0, "ok": 0, "expected": 0, "fraction": None}
    window_s = min(WINDOW_30D_NS, now - int(first)) / 1e9
    expected = max(total, int(window_s // cadence_s(ctx)))
    return {"checks": total, "ok": good, "expected": expected, "fraction": (good / expected) if expected else None}
