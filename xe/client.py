"""Async HTTP client for an XE node's REST API.

Reads are plain GETs. Writes are pre-signed blocks or envelopes; the node never signs for us.
Pagination follows the node: ?offset=&limit= (max 1000) for lists, ?start=&limit= for state-chain blocks.
"""

from __future__ import annotations

import json
from typing import Any, AsyncIterator

import httpx

from .encoding import Block
from .statechain import StateBlock

PAGE = 1000
MAX_CHAIN_PAGES = 100   # 100,000 blocks: far past any account the harness reads for weight or fees


class XeError(RuntimeError):
    def __init__(self, status: int, message: str):
        super().__init__(f"node returned {status}: {message}")
        self.status = status
        self.message = message


class XeClient:
    def __init__(self, base_url: str, timeout: float = 20.0, admin_token: str | None = None):
        self.base_url = base_url.rstrip("/")
        self._client = httpx.AsyncClient(base_url=self.base_url, timeout=timeout)
        self._admin_token = admin_token

    async def aclose(self) -> None:
        await self._client.aclose()

    # ---- plumbing -------------------------------------------------------------------------

    async def _get(self, path: str, **params: Any) -> Any:
        r = await self._client.get(path, params={k: v for k, v in params.items() if v is not None})
        return self._unwrap(r)

    async def _post_json(self, path: str, body: Any) -> Any:
        r = await self._client.post(path, json=body)
        return self._unwrap(r)

    async def _post_raw(self, path: str, body: str) -> Any:
        r = await self._client.post(path, content=body.encode("utf-8"), headers={"Content-Type": "application/json"})
        return self._unwrap(r)

    @staticmethod
    def _unwrap(r: httpx.Response) -> Any:
        if r.status_code >= 400:
            try:
                msg = r.json().get("error", r.text)
            except Exception:
                msg = r.text
            raise XeError(r.status_code, msg)
        if not r.content:
            return None
        return r.json()

    # ---- node -----------------------------------------------------------------------------

    async def manifest(self) -> dict:
        return await self._get("/")

    async def node(self) -> dict:
        return await self._get("/node")

    async def health(self) -> dict:
        return await self._get("/health")

    async def ready(self) -> tuple[bool, Any]:
        r = await self._client.get("/ready")
        try:
            body = r.json()
        except Exception:
            body = r.text
        return r.status_code == 200, body

    async def readiness(self) -> dict:
        return await self._get("/network/readiness")

    async def activations(self) -> dict:
        return await self._get("/network/activations")

    async def supply(self) -> dict:
        return await self._get("/supply")

    async def delegation(self) -> Any:
        return await self._get("/delegation")

    # ---- accounts ------------------------------------------------------------------------

    async def balance(self, address: str) -> dict:
        return await self._get(f"/accounts/{address}/balance")

    async def chain(self, address: str, offset: int = 0, limit: int = 1000) -> dict:
        return await self._get(f"/accounts/{address}/chain", offset=offset, limit=limit)

    async def full_chain(self, address: str) -> list[dict]:
        """Every block of an account, paged. The node's `total` ends the walk when it is honest; the page
        count ends it when it is not, so a node advertising two billion blocks cannot have the caller buffer
        them (XE-1189). An account past the bound is an error, not a truncated chain."""
        out: list[dict] = []
        offset = 0
        for _ in range(MAX_CHAIN_PAGES):
            page = await self.chain(address, offset=offset, limit=PAGE)
            blocks = page.get("blocks", [])
            out.extend(blocks)
            if len(blocks) < PAGE or len(out) >= int(page.get("total", 0)):
                return out
            offset += len(blocks)
        raise XeError(413, f"account chain exceeds {MAX_CHAIN_PAGES * PAGE} blocks")

    async def keyset_of(self, address: str) -> dict | None:
        try:
            return await self._get(f"/accounts/{address}/keyset")
        except XeError as e:
            if e.status == 404:
                return None
            raise

    async def accounts(self, offset: int = 0, limit: int = 1000) -> Any:
        return await self._get("/accounts", offset=offset, limit=limit)

    async def pending_for(self, address: str) -> list[dict]:
        """Pending sends to `address`, normalised to lower-case keys:
        {send_hash, source, destination, amount, asset, timestamp}."""
        res = await self._get(f"/pending/{address}")
        entries = res.get("pending", []) if isinstance(res, dict) else (res or [])
        out = []
        for p in entries or []:
            out.append({
                "send_hash": p.get("SendHash") or p.get("send_hash", ""),
                "source": p.get("Source") or p.get("source", ""),
                "destination": p.get("Destination") or p.get("destination", ""),
                "amount": int(p.get("Amount") or p.get("amount") or 0),
                "asset": p.get("Asset") or p.get("asset", "XE"),
                "timestamp": int(p.get("Timestamp") or p.get("timestamp") or 0),
            })
        return out

    async def balances(self, address: str) -> dict[str, int]:
        try:
            res = await self.balance(address)
        except XeError as e:
            if e.status == 404:
                return {}
            raise
        return {k: int(v) for k, v in (res.get("balances") or {}).items()}

    async def block(self, block_hash: str) -> dict:
        return await self._get(f"/blocks/{block_hash}")

    async def recent_blocks(self, limit: int = 100, since_ns: int | None = None) -> list[dict]:
        return await self._get("/blocks/recent", limit=limit, since=since_ns) or []

    async def submit_block(self, b: Block) -> Any:
        return await self._post_json(f"/blocks/{b.type}", b.to_json())

    # ---- state chain ---------------------------------------------------------------------

    async def statechain_tip(self) -> dict:
        return await self._get("/statechain/tip")

    async def statechain_blocks(self, start: int = 0, limit: int = 100) -> dict:
        return await self._get("/statechain/blocks", start=start, limit=limit)

    async def statechain_block(self, index: int) -> dict:
        return await self._get(f"/statechain/blocks/{index}")

    async def statechain_kv(self, prefix: str | None = None, offset: int = 0, limit: int = 1000) -> dict:
        return await self._get("/statechain/kv", prefix=prefix, offset=offset, limit=limit) or {}

    async def statechain_key(self, key: str) -> Any:
        """Returns the value, or None if the key is not set."""
        try:
            res = await self._get(f"/statechain/kv/{key}")
        except XeError as e:
            if e.status == 404:
                return None
            raise
        if isinstance(res, dict) and set(res.keys()) == {"key", "value"}:
            return res["value"]
        return res

    async def dao_keyset(self) -> dict:
        return await self._get("/statechain/keyset")

    async def submit_statechain_block(self, b: StateBlock) -> Any:
        return await self._post_raw("/statechain/blocks", b.to_wire())

    # ---- directory and chat --------------------------------------------------------------

    async def directory(self, account: str) -> dict | None:
        try:
            return await self._get(f"/directory/{account}")
        except XeError as e:
            if e.status == 404:
                return None
            raise

    async def directory_register(self, registration: dict) -> Any:
        return await self._post_json("/directory/register", registration)

    async def chat_challenge(self) -> dict:
        return await self._get("/chat/auth/challenge")

    async def chat_messages(self, proof: dict[str, str], since_ns: int = 0) -> list[dict]:
        return await self._get("/chat/messages", since=since_ns, **proof) or []

    async def chat_send(self, envelope: dict) -> Any:
        return await self._post_json("/chat/send", envelope)

    async def chat_events(self, proof: dict[str, str]) -> AsyncIterator[dict]:
        """Yield chat envelopes from the SSE stream for one account. Caller handles reconnects."""
        async with self._client.stream("GET", "/chat/events", params=proof, timeout=None) as r:
            if r.status_code >= 400:
                body = await r.aread()
                raise XeError(r.status_code, body.decode("utf-8", "replace"))
            async for line in r.aiter_lines():
                if not line or line.startswith(":"):
                    continue
                if line.startswith("data:"):
                    payload = line[5:].strip()
                    if payload:
                        try:
                            yield json.loads(payload)
                        except json.JSONDecodeError:
                            continue
