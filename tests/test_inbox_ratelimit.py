"""Tests for inbox rate limiting and DoS prevention on log_head."""
import time
import pytest
from fastapi import HTTPException
from unittest.mock import MagicMock

from dao.ratelimit import TokenBucketLimiter, inbox_ip_limiter, inbox_account_limiter
from dao.auth import SignedRequest
from dao.api.public import inbox_post
from dao.canonical import DOMAIN_INBOX_HTTP, digest
from xe.keys import KeyPair


def test_token_bucket_limiter():
    limiter = TokenBucketLimiter(capacity=3.0, refill_rate=1.0)
    key = "test-ip-1"

    # 3 allowed
    assert limiter.allow(key) is True
    assert limiter.allow(key) is True
    assert limiter.allow(key) is True

    # 4th denied (burst exceeded)
    assert limiter.allow(key) is False

    # Wait for refill
    time.sleep(1.05)
    assert limiter.allow(key) is True
    assert limiter.allow(key) is False


def test_token_bucket_lru_eviction():
    limiter = TokenBucketLimiter(capacity=2.0, refill_rate=0.1, max_entries=2)
    assert limiter.allow("ip1") is True
    assert limiter.allow("ip2") is True
    # Inserting 3rd key evicts ip1
    assert limiter.allow("ip3") is True
    assert "ip1" not in limiter._buckets
    assert "ip2" in limiter._buckets
    assert "ip3" in limiter._buckets


@pytest.mark.asyncio
async def test_inbox_post_rate_limiting():
    inbox_ip_limiter.reset()
    inbox_account_limiter.reset()

    kp = KeyPair.generate()
    payload = {"message": "hello DAO"}
    ts = time.time_ns()
    h = digest(DOMAIN_INBOX_HTTP, {"payload": payload, "timestamp": ts})
    sig = kp.sign_hex(h)

    req = SignedRequest(
        payload=payload,
        timestamp=ts,
        pub_key=kp.pub_key_hex,
        signature=sig,
    )

    mock_request = MagicMock()
    mock_request.headers = {}
    mock_request.client.host = "192.168.1.100"

    mock_ctx = MagicMock()
    mock_db = MagicMock()

    # The first 3 should pass the account limiter (burst 3) and IP limiter (burst 5)
    # The 4th from same account should raise 429
    for i in range(3):
        # We test limiter directly
        assert inbox_account_limiter.allow(kp.address) is True
    
    assert inbox_account_limiter.allow(kp.address) is False

    # Now verify that inbox_post raises HTTPException 429
    with pytest.raises(HTTPException) as exc_info:
        await inbox_post(req, mock_ctx, mock_db, mock_request)
    assert exc_info.value.status_code == 429
    assert "rate limit exceeded" in exc_info.value.detail
