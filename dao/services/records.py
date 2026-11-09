"""Chain-facing records: dao.registry, weekly anchors, treasury reads, health."""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from xe.client import XeError

from ..context import Context
from ..db import serialize
from ..log import EventLog
from ..models import Anchor, Event, HealthCheck, SigningSession, TreasurySnapshot
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
            "dao": ctx.config.accounts.get("dao", ""),
            "fee": ctx.config.accounts.get("fee", ""),
            "treasury": ctx.config.accounts.get("treasury", ""),
        }.items() if v},
        "log_signer": ctx.signer.public_key("harness") if ctx.signer.has("harness") else "",
        "version": 1,
    }
    return val


# ---- public node reads -------------------------------------------------------------------------
#
# The public pages and /v1/legal/* read the keyset, the registry and the treasury balances from the node on
# every request. Each is the same for everyone and changes on the order of weeks, so one read serves every
# caller for a few seconds: an unauthenticated burst costs the node one round trip per leg per window, not
# one per request (XE-0959). Member and worker paths that act on the keyset read it directly.

PUBLIC_READ_TTL_S = 10
_public_reads: dict[str, tuple[float, object]] = {}


async def _shared(key: str, read):
    now = time.monotonic()
    hit = _public_reads.get(key)
    if hit and now - hit[0] < PUBLIC_READ_TTL_S:
        return hit[1]
    value = await read()
    _public_reads[key] = (now, value)
    return value


async def public_keyset(ctx: Context) -> dict:
    """sys.dao_keyset for display; an unreachable node is shown as {"error": ...}, not raised."""
    async def read():
        try:
            return await ctx.chain.dao_keyset()
        except XeError as e:
            return {"error": str(e), "keys": [], "threshold": 0}
    return await _shared("keyset", read)


async def onchain_registry(ctx: Context) -> dict | None:
    async def read():
        try:
            return await ctx.chain.statechain_key("dao.registry")
        except XeError:
            return None
    return await _shared("registry", read)


async def open_registry_session(ctx: Context, db: AsyncSession, actor: str) -> dict:
    ops = [{"action": "set", "key": "dao.registry", "value": registry_value(ctx)}]
    s = await sessions.create(ctx, db, kind="registry", title="Write dao.registry", ops=ops, actor=actor)
    return sessions.to_dict(s)


# ---- anchors ----------------------------------------------------------------------------------

async def latest_anchor(db: AsyncSession, *, written: bool = False) -> Anchor | None:
    """The newest anchor; `written=True` for only those that reached the chain. Numbering counts the one in
    flight, and `open_anchor_session` serialises on the number, so two sessions never take the same n
    (XE-1435); health counts only what was written (XE-0990)."""
    q = select(Anchor).order_by(Anchor.n.desc()).limit(1)
    if written:
        q = q.where(Anchor.statechain_index.isnot(None))
    return (await db.execute(q)).scalar_one_or_none()


async def open_anchor_session(ctx: Context, db: AsyncSession, actor: str = "harness") -> dict:
    await serialize(db, "anchor.n")   # two opens at once take consecutive numbers (XE-1435)
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
    return await _shared("treasury", lambda: _treasury(ctx))


async def _treasury(ctx: Context) -> dict:
    accts = {
        "treasury": ctx.config.accounts.get("treasury", ""),
        "dao": ctx.config.accounts.get("dao", ""),
        "fee": ctx.config.accounts.get("fee", ""),
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
    detail: dict = {"node_url": ctx.settings.xe_node_url, "network_id": ctx.node.network_id, "cadence_s": cadence_s(ctx)}
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

    try:   # last anchor age: measured from the last written anchor, or from the DAO's start if there is none (XE-1618)
        a = await latest_anchor(db, written=True)
        detail["last_anchor"] = {"n": a.n, "age_s": round(now / 1e9 - a.created_at.timestamp())} if a else None
        unanchored_s = detail["last_anchor"]["age_s"] if a else (now - (await started_at(db) or now)) / 1e9
        if unanchored_s > ANCHOR_OVERDUE_S:
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


async def started_at(db: AsyncSession) -> int | None:
    """When the DAO started: the first event in its log, in ns. The clock every "since the beginning"
    measure runs from, so a leg that has no rows of its own (no anchor written, no health check recorded)
    is measured against the DAO's age rather than against nothing (XE-1618, XE-1620)."""
    first = (await db.execute(select(func.min(Event.ts)))).scalar_one()
    return int(first) if first is not None else None


async def uptime_30d(ctx: Context, db: AsyncSession) -> dict:
    """Checks that should have run but did not count as failures, so a stopped worker lowers the figure
    instead of freezing it (XE-0908). Expected checks run from the DAO's start, not from the first check
    the worker happened to record, so a worker that started late or never does not score full (XE-1620)."""
    now = time.time_ns()
    since = now - WINDOW_30D_NS
    rows = (await db.execute(select(HealthCheck.ts, HealthCheck.ok, HealthCheck.detail["cadence_s"].astext)
                             .where(HealthCheck.ts >= since).order_by(HealthCheck.ts.asc()))).all()
    total = len(rows)
    good = sum(1 for _, ok, _ in rows if ok)
    first = await started_at(db)
    if first is None:
        return {"checks": 0, "ok": 0, "expected": 0, "fraction": None}
    expected = max(total, expected_checks([(int(ts), int(c) if c else None) for ts, _, c in rows], max(since, first), now, cadence_s(ctx)))
    return {"checks": total, "ok": good, "expected": expected, "fraction": (good / expected) if expected else None}


def expected_checks(rows: list[tuple[int, int | None]], start_ns: int, now_ns: int, default_s: int) -> int:
    """How many checks the window should hold: each stretch of it is divided by the cadence that was in
    force then, as the check that opened the stretch recorded it, so a cadence change rewrites nothing
    behind it (XE-1639). A row without a recorded cadence (written before this was kept) uses the current
    one; the stretch before the first check uses that check's cadence."""
    if now_ns <= start_ns:
        return 0
    edges = [(start_ns, (rows[0][1] if rows and rows[0][1] else default_s))]
    edges += [(ts, c or default_s) for ts, c in rows if ts > start_ns]
    expected = 0
    for i, (ts, cadence) in enumerate(edges):
        end = edges[i + 1][0] if i + 1 < len(edges) else now_ns
        expected += int((end - ts) / (max(int(cadence), 1) * 1_000_000_000) + 0.5)   # nearest whole check
    return expected
