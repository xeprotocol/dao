"""Token buckets for the public write routes (XE-0032).

In-process, keyed by client IP and by signing account; uvicorn runs behind Caddy with --proxy-headers so
`request.client.host` is the real address. Good enough for one API process; a second layer belongs at the
proxy. Buckets are forgotten when they have been full for a while, so the table does not grow with the
set of addresses that ever wrote to us.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from fastapi import HTTPException, Request


@dataclass
class Limit:
    per_minute: float
    burst: int


# per route class: (per IP, per account)
INBOX = (Limit(10, 5), Limit(4, 2))
VOTE = (Limit(60, 20), Limit(12, 6))
PROPOSAL = (Limit(10, 5), Limit(2, 2))


class Buckets:
    def __init__(self, sweep_every_s: float = 300):
        self._b: dict[str, tuple[float, float]] = {}  # key -> (tokens, last_ts)
        self._sweep_every = sweep_every_s
        self._last_sweep: float | None = None

    def take(self, key: str, lim: Limit, now: float | None = None) -> float:
        """Take one token. Returns 0 when allowed, else the seconds until the next token."""
        now = time.monotonic() if now is None else now
        tokens, last = self._b.get(key, (float(lim.burst), now))
        tokens = min(float(lim.burst), tokens + (now - last) * lim.per_minute / 60.0)
        if tokens >= 1.0:
            self._b[key] = (tokens - 1.0, now)
            self._maybe_sweep(now)
            return 0.0
        self._b[key] = (tokens, now)
        return (1.0 - tokens) * 60.0 / lim.per_minute

    def _maybe_sweep(self, now: float) -> None:
        if self._last_sweep is None:
            self._last_sweep = now
            return
        if now - self._last_sweep < self._sweep_every:
            return
        self._last_sweep = now
        # anything that has had time to refill completely is indistinguishable from absent
        self._b = {k: v for k, v in self._b.items() if now - v[1] < self._sweep_every}


_buckets = Buckets()


def client_ip(request: Request) -> str:
    return (request.client.host if request.client else "") or "unknown"


def enforce(request: Request, limits: tuple[Limit, Limit], account: str | None = None) -> None:
    """429 with Retry-After when the IP or the account is over its limit. Call before any work."""
    ip_lim, acct_lim = limits
    wait = _buckets.take(f"ip:{client_ip(request)}", ip_lim)
    if not wait and account:
        wait = _buckets.take(f"acct:{account}", acct_lim)
    if wait:
        secs = max(1, int(wait + 0.999))
        raise HTTPException(429, "too many requests; slow down", headers={"Retry-After": str(secs)})
