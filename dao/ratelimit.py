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


@dataclass(frozen=True)
class RouteClass:
    """One class of route with its own buckets: a burst of inbox posts from an address does not spend the
    votes of everyone behind it (XE-0478)."""
    name: str
    ip: Limit
    account: Limit


INBOX = RouteClass("inbox", Limit(10, 5), Limit(4, 2))
VOTE = RouteClass("vote", Limit(60, 20), Limit(12, 6))
PROPOSAL = RouteClass("proposal", Limit(10, 5), Limit(2, 2))
SNAPSHOT = RouteClass("snapshot", Limit(30, 10), Limit(30, 10))   # read, but each one walks a whole account chain on the node


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


def _refuse(wait: float) -> None:
    if wait:
        secs = max(1, int(wait + 0.999))
        raise HTTPException(429, "too many requests; slow down", headers={"Retry-After": str(secs)})


def enforce_ip(request: Request, cls: RouteClass) -> None:
    """One token from the address's bucket for this class. Call first, before the signature is checked, so
    unsigned noise is refused cheaply; call once per request."""
    _refuse(_buckets.take(f"ip:{cls.name}:{client_ip(request)}", cls.ip))


def enforce_account(cls: RouteClass, account: str) -> None:
    """One token from the signing account's bucket for this class, once the signature has named it. The
    address is not charged again."""
    _refuse(_buckets.take(f"acct:{cls.name}:{account}", cls.account))
