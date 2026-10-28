import time
import pytest
from dao.auth import _Seen, REPLAY_WINDOW_S


def test_replay_cache_does_not_evict_unexpired_entries():
    """Defeats the issue #51 attack: FIFO eviction allowing replay."""
    seen = _Seen(cap=3, ttl_s=60)
    vote_sig = "a" * 128

    # 1. First add succeeds
    assert seen.check_and_add(vote_sig) is True

    # 2. Immediate replay fails
    assert seen.check_and_add(vote_sig) is False

    # 3. Add more signatures up to and past capacity
    for i in range(5):
        seen.check_and_add(f"{i:0128x}")

    # 4. In old FIFO, vote_sig would be evicted and return True.
    # With TTL cache, unexpired vote_sig remains protected and replay is REJECTED.
    assert seen.check_and_add(vote_sig) is False


def test_replay_cache_expires_entries_after_ttl():
    seen = _Seen(cap=10, ttl_s=1)
    sig = "b" * 128
    assert seen.check_and_add(sig) is True
    assert seen.check_and_add(sig) is False

    # Mock time advancement
    seen._d[sig] = time.time() - 1
    # Expired entry is pruned and can be added anew
    assert seen.check_and_add(sig) is True
