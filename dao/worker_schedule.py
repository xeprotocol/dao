"""Cadence from Schedule B turned into due-times. Shared by the worker and /v1/schedule/next."""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .context import Context
from .models import ScheduleRun

NS = 1_000_000_000


def _next_daily(now: datetime, hour: int) -> datetime:
    t = now.replace(hour=hour, minute=0, second=0, microsecond=0)
    return t if t > now else t + timedelta(days=1)


def _next_weekly(now: datetime, weekday: int, hour: int) -> datetime:
    # weekday: Monday = 1 ... Sunday = 7 (Schedule B convention)
    target = (weekday - 1) % 7
    t = now.replace(hour=hour, minute=0, second=0, microsecond=0)
    days = (target - now.weekday()) % 7
    t = t + timedelta(days=days)
    return t if t > now else t + timedelta(days=7)


def _next_monthly(now: datetime, day: int, hour: int = 9) -> datetime:
    t = now.replace(day=min(day, 28), hour=hour, minute=0, second=0, microsecond=0)
    if t > now:
        return t
    y, m = (now.year + (now.month // 12), (now.month % 12) + 1)
    return t.replace(year=y, month=m)


def job_table(ctx: Context) -> dict[str, dict]:
    c = ctx.config.cadence
    now = datetime.now(timezone.utc)
    return {
        "health": {"every_s": int(c.get("health_check_minutes", 10)) * 60, "desc": "node reachable, tip advancing, keyset unchanged, log replays, sessions ageing, directory"},
        "directory": {"every_s": int(c.get("directory_reregister_minutes", 20)) * 60, "desc": "re-register the DAO account in the node directory"},
        "fees": {"every_s": 60, "desc": "receive pending fees; refund or burn settled ones"},
        "outbox": {"every_s": 30, "desc": "send queued replies over chat"},
        "timers": {"every_s": 60, "desc": "close votes whose window ended; expire pauses; publish overdue pause posts; promote timelocked sessions"},
        "sessions": {"every_s": 120, "desc": "rebuild signing-session blocks when the tip has moved and no signatures are pending"},
        "daily": {"at": _next_daily(now, int(c.get("daily_note_hour_utc", 8))), "desc": "daily state note into the log; treasury snapshot"},
        "weekly": {"at": _next_weekly(now, int(c.get("weekly_review_weekday", 1)), int(c.get("weekly_review_hour_utc", 9))), "desc": "weekly review note"},
        "anchor": {"at": _next_weekly(now, int(c.get("anchor_weekday", 1)), int(c.get("anchor_hour_utc", 9))), "desc": "open the weekly anchor session (dao.anchor.n)"},
        "monthly": {"at": _next_monthly(now, int(c.get("monthly_report_day", 1))), "desc": "monthly summary note"},
    }


async def last_runs(db: AsyncSession) -> dict[str, int]:
    rows = (await db.execute(select(ScheduleRun))).scalars().all()
    return {r.job: r.last_run_ts for r in rows}


async def mark_run(db: AsyncSession, job: str, detail: dict | None = None) -> None:
    row = (await db.execute(select(ScheduleRun).where(ScheduleRun.job == job))).scalar_one_or_none()
    if row is None:
        db.add(ScheduleRun(job=job, last_run_ts=time.time_ns(), detail=detail or {}))
    else:
        row.last_run_ts = time.time_ns()
        row.detail = detail or {}


def due_interval(last_ts: int | None, every_s: int) -> bool:
    return last_ts is None or time.time_ns() - last_ts >= every_s * NS


def due_at(last_ts: int | None, at: datetime, period_s: int) -> bool:
    """A dated job is due when its most recent scheduled time has passed and we have not run since."""
    prev = at - timedelta(seconds=period_s)
    prev_ns = int(prev.timestamp() * NS)
    return time.time_ns() >= prev_ns and (last_ts is None or last_ts < prev_ns)


async def next_runs(ctx: Context, db: AsyncSession) -> list[dict]:
    table = job_table(ctx)
    last = await last_runs(db)
    out = []
    for name, j in table.items():
        lr = last.get(name)
        if "every_s" in j:
            nxt = (lr or 0) + j["every_s"] * NS if lr else time.time_ns()
            out.append({"job": name, "desc": j["desc"], "every_s": j["every_s"], "last_run": lr, "next_run": nxt})
        else:
            out.append({"job": name, "desc": j["desc"], "last_run": lr, "next_run": int(j["at"].timestamp() * NS),
                        "next_run_iso": j["at"].isoformat()})
    return out
