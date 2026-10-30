"""The worker: timers, chain listeners, cadence. Runs as its own container (`python -m dao.worker`).

Everything it does is either a read, a bounded company-key action permitted by Schedule B, or the
opening of a session that humans must sign. It never signs a state-chain block, never moves
treasury, never pauses.
"""

from __future__ import annotations

import asyncio
import logging
import signal
import time
from datetime import datetime, timezone

from sqlalchemy import select

from xe.chat import Envelope
from xe.client import XeError
from xe.directory import new_registration

from .auth import purge_seen_signatures
from .context import Context, build_context, set_context
from .db import session
from .log import EventLog
from .models import SigningSession
from .services import fees, inbox, pause, portal, records, sessions
from .worker_schedule import due_at, due_interval, job_table, last_runs, mark_run

log = logging.getLogger("dao.worker")
NS = 1_000_000_000


class Worker:
    def __init__(self, ctx: Context):
        self.ctx = ctx
        self.stop = asyncio.Event()
        self.chat_since = time.time_ns() - 24 * 3600 * NS

    # ---- jobs -----------------------------------------------------------------------------

    async def job_health(self):
        async with session() as db:
            d = await records.health(self.ctx, db, record=True)
            if not d["ok"]:
                await self.ctx.events.append(db, "health.degraded", "harness", {k: v for k, v in d.items() if k != "node"}, public=True)
            await mark_run(db, "health", {"ok": d["ok"]})
            await db.commit()

    async def job_directory(self):
        ctx = self.ctx
        if not ctx.signer.has("dao") or not ctx.node.network_id:
            return
        async with session() as db:
            try:
                kp = ctx.signer.keypair("dao", "directory.register")
                reg = new_registration(kp, ctx.node.network_id, ctx.directory_node_peer)
                await ctx.chain.directory_register(reg.to_json())
                await mark_run(db, "directory", {"ok": True})
            except Exception as e:
                log.warning("directory register failed: %s", e)
                await mark_run(db, "directory", {"ok": False, "error": str(e)[:300]})
                await ctx.events.append(db, "directory.register_failed", "harness", {"error": str(e)[:300]}, public=False)
            await db.commit()

    async def job_fees(self):
        async with session() as db:
            if await pause.is_paused(db):
                return
            try:
                await fees.receive_all(self.ctx, db)
                await fees.settle_due(self.ctx, db)
            except Exception as e:
                log.warning("fees: %s", e)
            await mark_run(db, "fees")
            await db.commit()

    async def job_outbox(self):
        async with session() as db:
            try:
                await inbox.flush_outbox(self.ctx, db)
            except Exception as e:
                log.warning("outbox: %s", e)
            await mark_run(db, "outbox")
            await db.commit()

    async def job_timers(self):
        async with session() as db:
            closed = await portal.close_due(self.ctx, db)
            if closed:
                log.info("closed %d proposals", len(closed))
            await pause.tick(self.ctx, db)
            # promote approved sessions whose timelock has run, once no pause is in force
            now = time.time_ns()
            if not await pause.is_paused(db):
                rows = (await db.execute(select(SigningSession).where(SigningSession.status == "approving"))).scalars().all()
                for s in rows:
                    if len(s.approvals) >= s.required_approvals and (not s.not_before or now >= s.not_before):
                        await sessions.rebuild(self.ctx, db, s)
            purged = await purge_seen_signatures(db)
            if purged:
                log.debug("purged %d expired signature claims", purged)
            await mark_run(db, "timers")
            await db.commit()

    async def job_sessions(self):
        """If a signing session's block is stale and nobody has signed it yet, rebuild quietly."""
        async with session() as db:
            paused = await pause.is_paused(db)
            rows = [] if paused else (await db.execute(select(SigningSession).where(SigningSession.status == "signing"))).scalars().all()
            for s in rows:
                try:
                    if not s.block_signatures and await sessions.is_stale(self.ctx, s):
                        await sessions.rebuild(self.ctx, db, s)
                    elif s.block_signatures and await sessions.is_stale(self.ctx, s):
                        # partial signatures over a stale block cannot be submitted; reset and say so
                        await self.ctx.events.append(db, "session.tip_moved", "harness", {
                            "session_id": s.id, "block_hash": s.block_hash, "had_signatures": len(s.block_signatures),
                        }, ref=f"session:{s.id}")
                        await sessions.rebuild(self.ctx, db, s)
                    if s.status == "submitted" and s.kind == "anchor":
                        await records.note_anchor_submitted(db, s.id, s.submitted_index, s.submitted_hash)
                except Exception as e:
                    log.warning("session %s: %s", s.id, e)
            # record anchors whose session submitted via the API
            subm = (await db.execute(select(SigningSession).where(SigningSession.status == "submitted", SigningSession.kind == "anchor"))).scalars().all()
            for s in subm:
                await records.note_anchor_submitted(db, s.id, s.submitted_index, s.submitted_hash)
            await mark_run(db, "sessions")
            await db.commit()

    async def job_daily(self):
        async with session() as db:
            head = await EventLog.head(db)
            counts = await portal.counts(db)
            snap = await records.snapshot_treasury(self.ctx, db)
            h = await records.last_health(db)
            await self.ctx.events.append(db, "note.daily", "harness", {
                "date": datetime.now(timezone.utc).date().isoformat(), "log_head": {"index": head.index, "hash": head.hash},
                "proposals": counts, "treasury": snap.balances, "health_ok": bool(h and h.get("ok")),
                "paused": await pause.is_paused(db), "network_id": self.ctx.node.network_id,
            })
            await mark_run(db, "daily")
            await db.commit()

    async def job_weekly(self):
        async with session() as db:
            up = await records.uptime_30d(db)
            open_sessions = await sessions.list_sessions(db, "signing")
            approving = await sessions.list_sessions(db, "approving")
            await self.ctx.events.append(db, "note.weekly", "harness", {
                "week_of": datetime.now(timezone.utc).date().isoformat(), "uptime_30d": up,
                "sessions_awaiting_signature": [s.id for s in open_sessions],
                "sessions_awaiting_approval": [s.id for s in approving],
                "proposals": await portal.counts(db),
            })
            await mark_run(db, "weekly")
            await db.commit()

    async def job_anchor(self):
        async with session() as db:
            if await pause.is_paused(db):
                return
            pending = [s for s in await sessions.list_sessions(db) if s.kind == "anchor" and s.status in ("approving", "signing")]
            if pending:
                log.info("anchor session %s still open; not opening another", pending[0].id)
            else:
                await records.open_anchor_session(self.ctx, db)
            await mark_run(db, "anchor")
            await db.commit()

    async def job_monthly(self):
        async with session() as db:
            await self.ctx.events.append(db, "note.monthly", "harness", {
                "month": datetime.now(timezone.utc).strftime("%Y-%m"), "proposals": await portal.counts(db),
                "uptime_30d": await records.uptime_30d(db), "anchors": await records.anchors(db, 6),
            })
            await mark_run(db, "monthly")
            await db.commit()

    # ---- chat listener --------------------------------------------------------------------

    async def chat_loop(self):
        ctx = self.ctx
        if not ctx.signer.has("dao"):
            log.info("no dao key; chat listener off")
            return
        me = ctx.signer.address("dao")
        while not self.stop.is_set():
            try:
                async with session() as db:
                    n = await inbox.backfill(ctx, db, self.chat_since)
                    await db.commit()
                    if n:
                        log.info("backfilled %d chat messages", n)
                proof = await inbox.read_proof(ctx)
                async for d in ctx.chain.chat_events(proof):
                    if self.stop.is_set():
                        break
                    env = Envelope.from_json(d)
                    if env.to != me:
                        continue
                    self.chat_since = max(self.chat_since, env.timestamp)
                    async with session() as db:
                        await inbox.store_envelope(ctx, db, env)
                        await db.commit()
            except (XeError, OSError, asyncio.TimeoutError) as e:
                log.warning("chat stream dropped: %s", e)
            except Exception as e:
                log.exception("chat loop error: %s", e)
            await asyncio.sleep(5)

    # ---- scheduler ------------------------------------------------------------------------

    async def scheduler(self):
        handlers = {
            "health": self.job_health, "directory": self.job_directory, "fees": self.job_fees, "outbox": self.job_outbox,
            "timers": self.job_timers, "sessions": self.job_sessions, "daily": self.job_daily, "weekly": self.job_weekly,
            "anchor": self.job_anchor, "monthly": self.job_monthly,
        }
        periods = {"daily": 86400, "weekly": 7 * 86400, "anchor": 7 * 86400, "monthly": 28 * 86400}
        while not self.stop.is_set():
            try:
                table = job_table(self.ctx)
                async with session() as db:
                    last = await last_runs(db)
                for name, j in table.items():
                    due = due_interval(last.get(name), j["every_s"]) if "every_s" in j else due_at(last.get(name), j["at"], periods[name])
                    if due:
                        try:
                            await handlers[name]()
                        except Exception as e:
                            log.exception("job %s failed: %s", name, e)
            except Exception as e:
                log.exception("scheduler: %s", e)
            try:
                await asyncio.wait_for(self.stop.wait(), timeout=15)
            except asyncio.TimeoutError:
                pass

    async def run(self):
        await self.ctx.refresh_node()
        async with session() as db:
            await self.ctx.events.append(db, "worker.started", "harness", {
                "network_id": self.ctx.node.network_id, "git_commit": self.ctx.settings.git_commit,
                "config_hashes": self.ctx.config.hashes, "signer_keys": [k.name for k in self.ctx.signer.infos()],
            })
            await db.commit()
        tasks = [asyncio.create_task(self.scheduler()), asyncio.create_task(self.chat_loop())]
        await self.stop.wait()
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        await self.ctx.aclose()


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    ctx = build_context()
    set_context(ctx)
    w = Worker(ctx)
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, w.stop.set)
    loop.run_until_complete(w.run())


if __name__ == "__main__":
    main()
