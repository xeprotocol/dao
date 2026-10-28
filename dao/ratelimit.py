"""Rate limiting for public ingestion endpoints."""
from __future__ import annotations

import threading
import time
from collections import OrderedDict
from dataclasses import dataclass


@dataclass
class Bucket:
    tokens: float
    last_update: float


class TokenBucketLimiter:
    """In-memory token bucket rate limiter with LRU eviction."""

    def __init__(self, capacity: float, refill_rate: float, max_entries: int = 10_000):
        """
        :param capacity: Max tokens the bucket can hold (burst limit).
        :param refill_rate: Tokens added per second.
        :param max_entries: Max unique tracked keys before LRU eviction.
        """
        self.capacity = float(capacity)
        self.refill_rate = float(refill_rate)
        self.max_entries = max_entries
        self._buckets: OrderedDict[str, Bucket] = OrderedDict()
        self._lock = threading.Lock()

    def allow(self, key: str, cost: float = 1.0) -> bool:
        """Check if request with given cost is allowed, and consume tokens if allowed."""
        now = time.monotonic()
        with self._lock:
            bucket = self._buckets.get(key)
            if bucket is None:
                # Evict oldest entry if at capacity
                if len(self._buckets) >= self.max_entries:
                    self._buckets.popitem(last=False)
                # New bucket starts full
                tokens = self.capacity - cost
                if tokens < 0:
                    return False
                self._buckets[key] = Bucket(tokens=tokens, last_update=now)
                return True

            # Refill tokens based on elapsed time
            elapsed = now - bucket.last_update
            tokens = min(self.capacity, bucket.tokens + elapsed * self.refill_rate)
            bucket.last_update = now

            if tokens >= cost:
                bucket.tokens = tokens - cost
                self._buckets.move_to_end(key)
                return True
            else:
                bucket.tokens = tokens
                self._buckets.move_to_end(key)
                return False

    def reset(self) -> None:
        """Reset all tracked buckets (useful for tests)."""
        with self._lock:
            self._buckets.clear()


# Default rate limiters for inbox submissions:
# Per IP: burst of 5, 0.2 tokens/sec (1 token every 5s -> max 12/min sustained)
inbox_ip_limiter = TokenBucketLimiter(capacity=5.0, refill_rate=0.2, max_entries=20_000)

# Per Account / PubKey: burst of 3, 0.1 tokens/sec (1 token every 10s -> max 6/min sustained)
inbox_account_limiter = TokenBucketLimiter(capacity=3.0, refill_rate=0.1, max_entries=20_000)
