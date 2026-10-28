from unittest.mock import AsyncMock, MagicMock
import pytest
from fastapi import HTTPException

from dao.auth import Verified
from dao.services import inbox as inbox_svc
from dao.services import portal as portal_svc


@pytest.mark.asyncio
async def test_http_submit_rejects_nul_byte():
    ctx = MagicMock()
    ctx.signer.has.return_value = False
    ctx.config.accounts = {"dao": "0xdao"}
    db = AsyncMock()

    # NUL byte in message payload
    v = Verified(
        account="0xuser",
        pub_key="pub",
        signature="sig",
        timestamp=1000,
        payload={"message": "hello\x00world"},
    )

    with pytest.raises(HTTPException) as exc_info:
        await inbox_svc.http_submit(ctx, db, v)

    assert exc_info.value.status_code == 400
    assert "NUL byte" in exc_info.value.detail


@pytest.mark.asyncio
async def test_http_submit_rejects_control_characters():
    ctx = MagicMock()
    ctx.signer.has.return_value = False
    ctx.config.accounts = {"dao": "0xdao"}
    db = AsyncMock()

    # Disallowed control character (e.g. Bell \x07)
    v = Verified(
        account="0xuser",
        pub_key="pub",
        signature="sig",
        timestamp=1000,
        payload={"message": "hello\x07world"},
    )

    with pytest.raises(HTTPException) as exc_info:
        await inbox_svc.http_submit(ctx, db, v)

    assert exc_info.value.status_code == 400
    assert "control character" in exc_info.value.detail


@pytest.mark.asyncio
async def test_http_submit_accepts_valid_message_with_whitespace():
    ctx = MagicMock()
    ctx.signer.has.return_value = False
    ctx.config.accounts = {"dao": "0xdao"}
    ctx.events.append = AsyncMock()
    db = AsyncMock()

    v = Verified(
        account="0xuser",
        pub_key="pub",
        signature="sig",
        timestamp=1000,
        payload={"message": "Hello\n\tWorld!\r\nLine 2"},
    )

    msg = await inbox_svc.http_submit(ctx, db, v)
    assert msg.body == "Hello\n\tWorld!\r\nLine 2"
    assert msg.channel == "http"
    db.add.assert_called_once_with(msg)


@pytest.mark.asyncio
async def test_portal_submit_proposal_rejects_nul_byte():
    ctx = MagicMock()
    db = AsyncMock()

    v = Verified(
        account="0xuser",
        pub_key="pub",
        signature="sig",
        timestamp=1000,
        payload={"title": "Proposal\x00Title", "body": "Normal body"},
    )

    with pytest.raises(HTTPException) as exc_info:
        await portal_svc.submit(ctx, db, v)

    assert exc_info.value.status_code == 400
    assert "NUL byte" in exc_info.value.detail
