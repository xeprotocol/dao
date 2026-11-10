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

from xe.client import XeError
from xe.directory import new_registration

from .auth import purge_seen_signatures
from .context import Context, build_context, set_context
from .db import only_one, session
from .log import EventLog
from .models import SigningSession
from .services import fees, inbox, pause, portal, records, resolutions, sessions
from .worker_schedule import due_at, due_interval, job_table, last_runs, mark_run

log = logging.getLogger("dao.worker")
NS = 1_000_000_000


class Worker:
    def __init__(self, ctx: Context):
        self.ctx = ctx
        self.stop = asyncio.Event()

    # ---- jobs -----------------------------------------------------------------------------

    async def job_health(self):
        async with session() as db:
            d = await records.health(self.ctx, db, record=True)
            if not d["ok"]:
                await self.ctx.events.append(db, "health.degraded", "harness", {k: v for k, v in d.items() if k != "node"}, public=True)
            await mark_run(db, "health", {"ok": d["ok"]}, every_s=records.cadence_s(self.ctx))
            await db.commit()

    async def job_directory(self):
        """Keep the DAO's directory entry alive: a fresh signed registration every 20 minutes against the
        node's 30-minute TTL. This runs through a pause on purpose (XE-1445): the entry is addressability,
        not action. It names only the DAO's own node peer and moves nothing, and without it every chat
        sent to the DAO fails at the sender's node thirty minutes into a pause, while the inbox is one of
        the things a pause keeps open. The `dao` key's narrowest scope, `directory.register`, is all it uses."""
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

    @staticmethod
    async def _step(db, name: str, fn):
        """One step of a job. A job is a list of steps that do not depend on each other, and one of them
        failing never stops the ones behind it: the step is committed if it returns, rolled back and logged
        if it raises anything at all, and the job goes on either way. The first version of this guard named
        the one exception a step was expected to raise, and a step that raised another ended the job at that
        line on every pass, with the pause clock, the timelock and the purge behind it (XE-1967)."""
        try:
            out = await fn()
            await db.commit()
            return out
        except Exception as e:
            await db.rollback()
            log.warning("%s: %s: %s", name, type(e).__name__, e)
            return None

    async def job_fees(self):
        # One fee pass at a time, in this process or any other: a settlement is one block because one pass
        # builds it, and two passes over one row would each build their own.
        async with session() as db, only_one(db, "worker:fees") as alone:
            if not alone or await pause.is_paused(db):
                return
            await self._step(db, "fees: receive", lambda: fees.receive_all(self.ctx, db))
            await self._step(db, "fees: record receives", lambda: fees.record_receives(self.ctx, db))
            await self._step(db, "fees: settle", lambda: fees.settle_due(self.ctx, db))
            await mark_run(db, "fees")
            await db.commit()

    async def job_outbox(self):
        # One outbox pass at a time, for the reason there is one fee pass: a reply has one envelope because
        # one pass builds it, and two passes over one queued row would each build and send their own.
        async with session() as db, only_one(db, "worker:outbox") as alone:
            if not alone:
                return
            await self._step(db, "outbox", lambda: inbox.flush_outbox(self.ctx, db))
            await mark_run(db, "outbox")
            await db.commit()

    async def job_timers(self):
        async with session() as db:
            closed = await self._step(db, "close proposals", lambda: portal.close_due(self.ctx, db))
            if closed:
                log.info("closed %d proposals", len(closed))
            # open tallies catch up with a rule or seat change (XE-1664)
            await self._step(db, "re-derive open tallies", lambda: portal.rederive_open(self.ctx, db))
            # sessions owed to passed resolutions (XE-1710)
            await self._step(db, "sessions owed to resolutions", lambda: resolutions.open_deferred_sessions(self.ctx, db))
            await self._step(db, "pause clock", lambda: pause.tick(self.ctx, db))
            await self._step(db, "promote sessions", lambda: self._promote(db))
            purged = await self._step(db, "purge signature claims", lambda: purge_seen_signatures(db))
            if purged:
                log.debug("purged %d expired signature claims", purged)
            await mark_run(db, "timers")
            await db.commit()

    async def _promote(self, db) -> None:
        """Promote approved sessions whose timelock has run, once no pause is in force."""
        if await pause.is_paused(db):
            return
        now = time.time_ns()
        ks = None
        for sid in await self._session_ids(db, "approving"):
            # Each row is taken FOR UPDATE and committed on its own, so a member's cancel or approval
            # either waits for this pass or is seen by it; never overwritten (XE-0763).
            s = await self._take(db, sid, "approving")
            if s is None or (s.not_before and now < s.not_before):
                await db.rollback()
                continue
            try:
                ks = ks or await sessions.live_keyset(self.ctx)
                if sessions.approvals_met(s, ks):
                    await sessions.rebuild(self.ctx, db, s)
                await db.commit()
            except Exception as e:  # one session or a node hiccup must not hold up the ones behind it
                await db.rollback()
                log.warning("promote session %s: %s", sid, e)

    @staticmethod
    async def _session_ids(db, status: str) -> list[str]:
        return list((await db.execute(select(SigningSession.id).where(SigningSession.status == status))).scalars().all())

    @staticmethod
    async def _take(db, sid: str, status: str) -> SigningSession | None:
        """Lock one session for this pass, or skip it: None if a route holds it or it has left `status`."""
        q = select(SigningSession).where(SigningSession.id == sid, SigningSession.status == status).with_for_update(skip_locked=True)
        return (await db.execute(q)).scalar_one_or_none()

    async def job_sessions(self):
        """A signing session whose block is stale is rebuilt; one that holds a threshold of signatures and
        is not yet on the chain (its submit was deferred by a node that did not answer, XE-1677/XE-1689)
        is submitted again."""
        async with session() as db:
            paused = await pause.is_paused(db)
            ids = [] if paused else await self._session_ids(db, "signing")
            await db.commit()
            ks = None
            for sid in ids:
                s = await self._take(db, sid, "signing")
                if s is None:
                    await db.rollback()
                    continue
                try:
                    stale = await sessions.is_stale(self.ctx, s)
                    if not s.block_signatures and stale:
                        await sessions.rebuild(self.ctx, db, s)
                    elif s.block_signatures and stale:
                        # partial signatures over a stale block cannot be submitted; reset and say so. Unless
                        # the tip moved because this block is the tip (its submit was deferred and it has
                        # landed since): nothing moved under the session, and `rebuild` records it submitted.
                        if not await sessions.landed(self.ctx, s):
                            await self.ctx.events.append(db, "session.tip_moved", "harness", {
                                "session_id": s.id, "block_hash": s.block_hash, "had_signatures": len(s.block_signatures),
                            }, ref=f"session:{s.id}")
                        await sessions.rebuild(self.ctx, db, s)
                    else:
                        ks = ks or await sessions.live_keyset(self.ctx)
                        if sessions.ready_to_submit(s, ks):
                            await sessions.submit(self.ctx, db, s)
                    if s.status == "submitted" and s.kind == "anchor":
                        await records.note_anchor_submitted(db, s.id, s.submitted_index, s.submitted_hash)
                    await db.commit()
                except Exception as e:
                    await db.rollback()
                    log.warning("session %s: %s", sid, e)
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
                "proposals": counts, "treasury": snap.balances,
                "health_ok": bool(h and h.get("ok")) and not records.health_is_stale(self.ctx, h),
                "paused": await pause.is_paused(db), "network_id": self.ctx.node.network_id,
            })
            await mark_run(db, "daily")
            await db.commit()

    async def job_weekly(self):
        async with session() as db:
            up = await records.uptime_30d(self.ctx, db)
            pending = await sessions.open_sessions(db)
            await self.ctx.events.append(db, "note.weekly", "harness", {
                "week_of": datetime.now(timezone.utc).date().isoformat(), "uptime_30d": up,
                "sessions_awaiting_signature": [s.id for s in pending if s.status == "signing"],
                "sessions_awaiting_approval": [s.id for s in pending if s.status == "approving"],
                "proposals": await portal.counts(db),
            })
            await mark_run(db, "weekly")
            await db.commit()

    async def job_anchor(self):
        async with session() as db:
            if await pause.is_paused(db):
                return
            pending = await sessions.open_sessions(db, kind="anchor")
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
                "uptime_30d": await records.uptime_30d(self.ctx, db), "anchors": await records.anchors(db, 6),
            })
            await mark_run(db, "monthly")
            await db.commit()

    # ---- chat listener --------------------------------------------------------------------

    async def chat_loop(self):
        ctx = self.ctx
        if not ctx.signer.has("dao"):
            log.info("no dao key; chat listener off")
            return
        while not self.stop.is_set():
            try:
                # The backfill cursor comes from the stored inbox (inbox.chat_cursor), not from this loop: a
                # store that fails below raises out of the stream, and the next pass asks the node again from
                # what is on disk (XE-1651, XE-1666, XE-1768).
                async with session() as db:
                    n = await inbox.backfill(ctx, db)
                    await db.commit()
                    if n:
                        log.info("backfilled %d chat messages", n)
                proof = await inbox.read_proof(ctx)
                async for d in ctx.chain.chat_events(proof):
                    if self.stop.is_set():
                        break
                    async with session() as db:
                        await inbox.receive(ctx, db, d)
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
        while not self.stop.is_set():
            try:
                table = job_table(self.ctx)
                async with session() as db:
                    last = await last_runs(db)
                for name, j in table.items():
                    due = due_interval(last.get(name), j["every_s"]) if "every_s" in j else due_at(last.get(name), j["prev"])
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
