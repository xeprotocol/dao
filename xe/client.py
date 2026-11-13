"""Async HTTP client for an XE node's REST API.

Reads are plain GETs. Writes are pre-signed blocks or envelopes; the node never signs for us.
Pagination follows the node: ?offset=&limit= (max 1000) for lists.

The node is a separate program, and what it sends is input. This module is the one place that input is
received, so it is the one place it is bounded and given a shape:

- every call fails as `XeError` and nothing else (XE-1689, XE-1774, XE-2209);
- every response is read under a size cap and a total deadline, the chat stream under an idle limit and
  a line cap (XE-1935, XE-2305);
- every method returns the types its signature says. A field the harness does arithmetic on is an
  integer the database can hold or the response is refused as malformed; a field it compares is a
  string. Callers hold typed values and do not convert node data themselves (XE-2209);
- everything returned can be kept: no NaN, no NUL, no unpaired surrogate. Node data is stored in JSONB
  and text columns, and one value Postgres will not take fails the whole write it rides in on (`_parse`);
- only a 2xx is an answer. A redirect is not followed and is not a success; a read that comes back
  empty is malformed, not "nothing there". Only a 404 says nothing is there.

A method the harness does not call is not kept here: an untyped reader is a way round the rule.
"""

from __future__ import annotations

import asyncio
import json
import re
from dataclasses import dataclass
from typing import Any, AsyncIterator
from urllib.parse import quote

import httpx

from .encoding import Block
from .statechain import StateBlock

PAGE = 1000
MAX_CHAIN_PAGES = 100   # 100,000 blocks: far past any account the harness reads for weight or fees
# The largest honest response is a full page of account blocks, about 0.6 MiB; a state-chain block is at
# most 256 KiB. Nothing the harness asks for is close to this.
MAX_BODY_BYTES = 8 * 1024 * 1024
REQUEST_DEADLINE_S = 60.0   # the whole of one request, headers to last byte; httpx's own timeout bounds each gap
STREAM_IDLE_S = 90.0        # the node writes a ping to the chat stream every 20 seconds
MAX_STREAM_LINE = 64 * 1024  # a chat envelope carries at most 8,192 bytes of message
MAX_ERROR_CHARS = 500
MAX_READY_BYTES = 4096      # /ready is a short status object; the health check stores what it is given
MAX_CHALLENGE_CHARS = 256   # the chat challenge travels back in a query string
MAX_HASH_CHARS = 128        # a hash is 64 hex characters
INT_LIMIT = 2**63           # what a BIGINT column holds; every XE amount and nanosecond timestamp is far below it


def _seg(value: Any) -> str:
    """One path segment. A caller-supplied key, hash or address is data, never structure: `?`, `#`, `/`
    and the rest are percent-encoded so the node answers for the resource named, or 404s, and never for
    a different one (XE-1489). A value that is not text (an unpaired surrogate) names nothing a node holds,
    and fails as every other call that cannot be made does."""
    try:
        return quote(str(value), safe="")
    except UnicodeEncodeError as e:
        raise XeError(UNREACHABLE, f"path segment is not text: {str(e)[:100]}") from e


UNREACHABLE = 0   # XeError.status when the node gave no usable answer (connection, timeout, bad or oversized body)


class XeError(RuntimeError):
    """Every way a node call can fail: a status that is not 2xx, no connection, a timeout, a body that is
    too large, is not JSON, or is not the shape the method returns. Callers catch this one type; nothing
    from httpx, json or a type conversion escapes the client. `transient` says whether asking again later
    could succeed: the node said nothing about what was asked. A redirect is that too. It comes from
    whatever stands in front of the node, and a caller that took it for the node's refusal would end a
    signing session on a proxy's change of address."""

    def __init__(self, status: int, message: str):
        super().__init__(f"node returned {status}: {message}" if status else f"node unreachable: {message}")
        self.status = status
        self.message = message

    @property
    def transient(self) -> bool:
        return self.status in (UNREACHABLE, 408, 425, 429) or 300 <= self.status < 400 or self.status >= 500


# ---- shape -------------------------------------------------------------------------------------

def malformed(what: str) -> XeError:
    """A response that arrived and is not what the endpoint returns. Not an answer, so not acted on."""
    return XeError(UNREACHABLE, f"malformed response: {what}")


def _obj(v: Any, what: str) -> dict:
    if not isinstance(v, dict):
        raise malformed(f"{what} is not an object")
    return v


def _list(v: Any, what: str) -> list:
    if not isinstance(v, list):
        raise malformed(f"{what} is not a list")
    return v


def _u64(v: Any, what: str) -> int:
    """A JSON integer from 0 up to what the database holds (INT_LIMIT), or its decimal spelling. Not a
    bool, a float, null or anything else."""
    if isinstance(v, str) and v.isascii() and v.isdigit() and len(v) <= 20:
        v = int(v)
    if isinstance(v, bool) or not isinstance(v, int) or not 0 <= v < INT_LIMIT:
        raise malformed(f"{what} is not an unsigned integer in range")
    return v


def _keyset(v: Any, what: str, *, need: bool) -> dict:
    """A multisig keyset: {"keys": [lower-case str], "threshold": int}, the threshold between one and the
    number of keys. A threshold of zero would be met by no signatures at all, and one past the key count
    by none that exist. With `need` both fields must be there; without, an object that has no keys is
    passed through as it is (an account that is not multisig)."""
    ks = _typed(v, what, ints=("threshold",), need=("keys", "threshold") if need else ())
    if "keys" not in ks:
        return ks
    keys = _list(ks["keys"], f"{what}.keys")
    if any(not isinstance(k, str) for k in keys):
        raise malformed(f"{what}.keys holds a key that is not a string")
    if not 1 <= ks.get("threshold", 0) <= len(keys):
        raise malformed(f"{what}.threshold is not between 1 and the number of keys")
    return {**ks, "keys": [k.lower() for k in keys]}


# `\u0000` as JSON spells it: the escape, not the same six characters after an escaped backslash. A raw
# NUL byte inside a string is not JSON at all and the parser refuses it.
_NUL_ESCAPE = re.compile(r"(?<!\\)(?:\\\\)*\\u0000")


def _refuse_constant(name: str) -> Any:
    raise ValueError(f"{name} is not JSON")


def _parse(raw: bytes) -> Any:
    """JSON from the node, as values the harness can keep. Three things a lenient parser lets through are
    refused here, once, for every read and the chat stream alike: NaN and Infinity (not JSON, and not
    storable as JSON), a NUL character, and a surrogate with no pair (neither is text Postgres or UTF-8
    will take). A string carrying one would be stored by whoever read it and fail that write.

    The body is UTF-8 or it is refused. `json.loads` given bytes guesses UTF-16 and UTF-32 as well, and
    the NUL escape spelt in either would pass a search of the bytes and still parse to a NUL."""
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as e:
        raise XeError(UNREACHABLE, f"response is not JSON the harness can keep: {str(e)[:100]}") from e
    if _NUL_ESCAPE.search(text):
        raise XeError(UNREACHABLE, "response carries a NUL character")
    try:
        v = json.loads(text, parse_constant=_refuse_constant)
        json.dumps(v, ensure_ascii=False).encode("utf-8")
    except (ValueError, RecursionError) as e:   # not JSON, nested deeper than the parser will go, or not text
        raise XeError(UNREACHABLE, f"response is not JSON the harness can keep: {str(e)[:100]}") from e
    return v


def _typed(v: Any, what: str, *, ints: tuple[str, ...] = (), strs: tuple[str, ...] = (),
           need: tuple[str, ...] = ()) -> dict:
    """A copy of object `v` in which each named field, where present, is an integer (`ints`) or a string
    (`strs`). A null field is dropped, so `d.get(k, default)` means what it says. `need` fields must be
    there."""
    d = dict(_obj(v, what))
    for k in ints + strs:
        if d.get(k) is None:
            d.pop(k, None)
        elif k in ints:
            d[k] = _u64(d[k], f"{what}.{k}")
        elif not isinstance(d[k], str):
            raise malformed(f"{what}.{k} is not a string")
    for k in need:
        if k not in d:
            raise malformed(f"{what}.{k} is missing")
    return d


_BLOCK_INTS = ("balance", "timestamp", "amount", "duration", "start_time")
_BLOCK_STRS = ("type", "account", "previous", "asset", "source", "destination", "memo", "pub_key", "hash")


def account_block(v: Any) -> dict:
    """An account-chain block as the harness reads one: the fields it computes with are integers, the
    fields it compares are strings. Everything else passes through untouched."""
    d = _typed(v, "block", ints=_BLOCK_INTS, strs=_BLOCK_STRS)
    if d.get("attestations") is None:
        d.pop("attestations", None)
    else:
        atts = _list(d["attestations"], "block.attestations")
        d["attestations"] = [
            _typed(a, "block.attestation", ints=("timestamp",), strs=("public_key", "signature"))
            for a in atts
        ]
    return d


# What httpx raises for a request that could not be made or finished. InvalidURL is not an HTTPError: it
# is raised for a URL too long to send, which a node-supplied value in a path or query can cause.
_TRANSPORT = (httpx.HTTPError, httpx.InvalidURL)


def _refuse_compressed(r: httpx.Response) -> None:
    encoding = r.headers.get("content-encoding", "").strip().lower()
    if encoding not in ("", "identity"):
        raise XeError(UNREACHABLE, f"response is {encoding[:20]}-encoded; the harness asks for none and reads none")


@dataclass
class _Reply:
    status: int
    body: bytes

    def text(self) -> str:
        return self.body.decode("utf-8", "replace").replace("\x00", "")   # it ends up in error text that is stored

    def json(self) -> Any:
        return _parse(self.body)


class XeClient:
    def __init__(self, base_url: str, timeout: float = 20.0, transport: httpx.AsyncBaseTransport | None = None):
        self.base_url = base_url.rstrip("/")
        self._client = httpx.AsyncClient(base_url=self.base_url, timeout=timeout, transport=transport,
                                         headers={"Accept-Encoding": "identity"})

    async def aclose(self) -> None:
        await self._client.aclose()

    # ---- plumbing -------------------------------------------------------------------------

    async def _get(self, path: str, **params: Any) -> Any:
        r = await self._send("GET", path, params={k: v for k, v in params.items() if v is not None})
        if r.status < 300 and not r.body:
            raise malformed("a read came back empty")   # every read returns JSON; nothing at all is not "none"
        return self._unwrap(r)

    async def _post_json(self, path: str, body: Any) -> Any:
        return self._unwrap(await self._send("POST", path, json=body))

    async def _post_raw(self, path: str, body: str) -> Any:
        return self._unwrap(await self._send("POST", path, content=body.encode("utf-8"),
                                             headers={"Content-Type": "application/json"}))

    async def _send(self, method: str, path: str, **kw: Any) -> _Reply:
        """One request, read as it arrives: at most MAX_BODY_BYTES kept, at most REQUEST_DEADLINE_S spent.
        httpx's timeout bounds each silence, not the whole, and it buffers whatever is sent; a node that
        drips a byte at a time or answers with a gigabyte is held to these two bounds instead (XE-2305).
        The bytes counted are the bytes on the wire: the request asks for no compression, and an answer
        that is compressed anyway is refused unread, since a few kilobytes can unpack to gigabytes."""
        try:
            async with asyncio.timeout(REQUEST_DEADLINE_S):
                async with self._client.stream(method, path, **kw) as r:
                    _refuse_compressed(r)   # so the bytes below are the bytes sent, not what they unpack to
                    body = bytearray()
                    async for chunk in r.aiter_bytes():
                        body += chunk
                        if len(body) > MAX_BODY_BYTES:
                            raise XeError(UNREACHABLE, f"response exceeds {MAX_BODY_BYTES} bytes")
                    return _Reply(r.status_code, bytes(body))
        except _TRANSPORT as e:   # connect, read, write, pool timeouts, transport failures, a URL that cannot be sent
            raise XeError(UNREACHABLE, f"{type(e).__name__}: {str(e)[:200]}") from e
        except TimeoutError as e:
            raise XeError(UNREACHABLE, f"no complete response within {REQUEST_DEADLINE_S:.0f}s") from e
        except (ValueError, TypeError) as e:   # a body httpx will not encode (NaN, an unpaired surrogate): never sent
            raise XeError(UNREACHABLE, f"request could not be built: {type(e).__name__}: {str(e)[:200]}") from e

    @staticmethod
    def _unwrap(r: _Reply) -> Any:
        if r.status >= 300:   # an error, or a redirect: not followed, and not an answer
            msg = r.text()
            try:
                err = r.json()
                if isinstance(err, dict) and isinstance(err.get("error"), str):
                    msg = err["error"]
            except XeError:
                pass
            raise XeError(r.status, msg[:MAX_ERROR_CHARS])
        if not r.body:
            return None
        return r.json()

    async def _found(self, path: str) -> tuple[bool, Any]:
        """GET, as (found, value). Only a 404 is "not there", which is an answer; a JSON null that was
        found is a value, and the caller says whether it will take one."""
        try:
            return True, await self._get(path)
        except XeError as e:
            if e.status == 404:
                return False, None
            raise

    # ---- node -----------------------------------------------------------------------------

    async def node(self) -> dict:
        """The node's identity: `network_id`, `id` and `version` are strings where present. The two proof
        of work difficulties pass through for `xe.pow.parse_difficulty`, which is their one parser."""
        return _typed(await self._get("/node"), "node identity", strs=("network_id", "id", "version"))

    async def ready(self) -> tuple[bool, Any]:
        """(ready, what the node said): a short status object, or the first of the text if it is anything
        else. The health check stores it, so it is bounded here."""
        r = await self._send("GET", "/ready")
        body: Any = r.text()[:MAX_ERROR_CHARS]
        if len(r.body) <= MAX_READY_BYTES:
            try:
                body = r.json()
            except XeError:
                pass
        return r.status == 200, body

    # ---- accounts ------------------------------------------------------------------------

    async def chain(self, address: str, offset: int = 0, limit: int = PAGE) -> dict:
        """One page of an account's chain: {"blocks": [account_block], "total": int, ...}. A page holding
        more blocks than were asked for is malformed."""
        page = dict(_obj(await self._get(f"/accounts/{_seg(address)}/chain", offset=offset, limit=limit), "chain page"))
        blocks = [] if page.get("blocks") is None else _list(page["blocks"], "chain page.blocks")
        if len(blocks) > limit:
            raise malformed(f"chain page holds {len(blocks)} blocks; {limit} were asked for")
        page["blocks"] = [account_block(b) for b in blocks]
        page["total"] = 0 if page.get("total") is None else _u64(page["total"], "chain page.total")
        return page

    async def full_chain(self, address: str) -> list[dict]:
        """Every block of an account, paged. Only a page that comes back short ends the walk: the node's
        `total` is a claim, and ending on it let a node that understated it cut the chain to its first
        page with no error (XE-2353). The page count ends the walk when the pages never run short, so a
        node serving full pages forever cannot have the caller buffer them (XE-1189). An account past the
        bound is an error, not a truncated chain."""
        out: list[dict] = []
        for _ in range(MAX_CHAIN_PAGES):
            try:
                blocks = (await self.chain(address, offset=len(out), limit=PAGE))["blocks"]
            except XeError as e:
                if e.status == 404 and out:   # the account was there a page ago: this is not "no such account"
                    raise malformed(f"chain ends in a 404 after {len(out)} blocks") from e
                raise
            out.extend(blocks)
            if len(blocks) < PAGE:
                return out
        raise XeError(413, f"account chain is {MAX_CHAIN_PAGES * PAGE} blocks or longer, past what the harness reads whole")

    async def chain_end(self, address: str) -> tuple[int, dict | None]:
        """Where an account's chain ends: how many blocks it holds, and the last of them (with the node's
        `finalized` flag); (0, None) for an account with no chain. The count is also the place the next
        block takes. `total` says where the last block is, and the page read there proves it: asked for two
        blocks from the last offset, an honest node returns exactly one. Anything else means `total` is not
        the length of the chain, and a block built on what that page shows would be built on the wrong
        parent (XE-2353)."""
        try:
            first = await self.chain(address, offset=0, limit=1)
        except XeError as e:
            if e.status == 404:
                return 0, None
            raise
        total = first["total"]
        if total == 0:
            if first["blocks"]:
                raise malformed("chain total is 0 and the chain is not empty")
            return 0, None
        try:
            last = (await self.chain(address, offset=total - 1, limit=2))["blocks"]
        except XeError as e:
            if e.status == 404:   # the account answered a moment ago: its end is not "no such account"
                raise malformed(f"chain total {total} and a 404 where the chain ends") from e
            raise
        if len(last) != 1 or not last[0].get("hash"):
            raise malformed(f"chain total {total} is not where the chain ends")
        return total, last[0]

    async def tip(self, address: str) -> str:
        """The hash of an account's last block; "0" for an account with no chain."""
        _, last = await self.chain_end(address)
        return last["hash"] if last else "0"

    async def keyset_of(self, address: str) -> dict | None:
        """An account's multisig keyset (see `_keyset`), or None for an account the node does not know."""
        found, ks = await self._found(f"/accounts/{_seg(address)}/keyset")
        return _keyset(ks, "account keyset", need=False) if found else None

    async def pending_for(self, address: str) -> list[dict]:
        """Pending sends to `address`, normalised to lower-case keys:
        {send_hash, source, destination, amount, asset, timestamp}."""
        res = await self._get(f"/pending/{_seg(address)}")
        entries = res.get("pending") if isinstance(res, dict) else res
        out = []
        # an object with no list in it is an account with nothing pending; a bare null is not an answer
        for p in ([] if entries is None and isinstance(res, dict) else _list(entries, "pending")):
            p = _obj(p, "pending entry")
            row = {k: p.get(cap) if p.get(cap) is not None else p.get(k)
                   for k, cap in (("send_hash", "SendHash"), ("source", "Source"), ("destination", "Destination"),
                                  ("amount", "Amount"), ("asset", "Asset"), ("timestamp", "Timestamp"))}
            row = {"send_hash": "", "source": "", "destination": "", "amount": 0, "asset": "XE", "timestamp": 0,
                   **_typed(row, "pending entry", ints=("amount", "timestamp"), strs=("send_hash", "source", "destination", "asset"))}
            out.append(row)
        return out

    async def balances(self, address: str) -> dict[str, int]:
        found, res = await self._found(f"/accounts/{_seg(address)}/balance")
        if not found:
            return {}
        bals = _obj(res, "balance").get("balances")
        bals = {} if bals is None else _obj(bals, "balance.balances")
        return {str(k): _u64(v, f"balance of {str(k)[:16]}") for k, v in bals.items()}

    async def block(self, block_hash: str) -> dict:
        return account_block(await self._get(f"/blocks/{_seg(block_hash)}"))

    async def submit_block(self, b: Block) -> Any:
        return await self._post_json(f"/blocks/{_seg(b.type)}", b.to_json())

    # ---- state chain ---------------------------------------------------------------------

    async def statechain_tip(self) -> dict:
        """The latest state-chain block: `index` and `timestamp` integers, `hash` a string no longer than a
        hash is, all present. Every health check stores the hash, so a long one is refused."""
        tip = _typed(await self._get("/statechain/tip"), "state-chain tip", ints=("index", "timestamp"),
                     strs=("hash", "prev_hash"), need=("index", "timestamp", "hash"))
        if len(tip["hash"]) > MAX_HASH_CHARS:
            raise malformed("state-chain tip hash is longer than a hash")
        return tip

    async def statechain_block(self, index: int) -> dict:
        return _typed(await self._get(f"/statechain/blocks/{_seg(index)}"), "state-chain block",
                      ints=("index", "timestamp"), strs=("hash", "prev_hash"), need=("hash",))

    async def statechain_key(self, key: str) -> Any:
        """Returns the value, or None if the key is not set (a 404). The value is whatever JSON was written;
        a null where the node said the key was found is not "not set"."""
        found, res = await self._found(f"/statechain/kv/{_seg(key)}")
        if found and res is None:
            raise malformed("state-chain value is null")
        if isinstance(res, dict) and set(res.keys()) == {"key", "value"}:
            return res["value"]
        return res

    async def dao_keyset(self) -> dict:
        """`sys.dao_keyset`: {"keys": [lower-case str], "threshold": int}, both present, the threshold
        between one and the number of keys (see `_keyset`)."""
        ks = _keyset(await self._get("/statechain/keyset"), "keyset", need=True)
        return {"keys": ks["keys"], "threshold": ks["threshold"]}

    async def submit_statechain_block(self, b: StateBlock) -> Any:
        return await self._post_raw("/statechain/blocks", b.to_wire())

    # ---- directory and chat --------------------------------------------------------------

    async def directory(self, account: str) -> dict | None:
        found, entry = await self._found(f"/directory/{_seg(account)}")
        return _obj(entry, "directory entry") if found else None

    async def directory_register(self, registration: dict) -> Any:
        return await self._post_json("/directory/register", registration)

    async def chat_challenge(self) -> dict:
        ch = _typed(await self._get("/chat/auth/challenge"), "chat challenge", strs=("challenge",), need=("challenge",))
        if len(ch["challenge"]) > MAX_CHALLENGE_CHARS:
            raise malformed("chat challenge is longer than any the node issues")
        try:
            bytes.fromhex(ch["challenge"])
        except ValueError as e:
            raise malformed("chat challenge is not hex") from e
        return ch

    async def chat_messages(self, proof: dict[str, str], since_ns: int = 0) -> list[dict]:
        """The envelopes the node holds for the proving account, as objects. Whether each is an envelope is
        `xe.chat.Envelope.from_json`'s question, asked per item so one bad item costs one item."""
        msgs = await self._get("/chat/messages", since=since_ns, **proof)
        msgs = [] if msgs is None else _list(msgs, "chat messages")
        return [m for m in msgs if isinstance(m, dict)]

    async def chat_send(self, envelope: dict) -> Any:
        return await self._post_json("/chat/send", envelope)

    async def chat_events(self, proof: dict[str, str]) -> AsyncIterator[dict]:
        """Yield chat envelopes (JSON objects) from the SSE stream for one account. Caller handles
        reconnects. The stream is long-lived, so it has no total deadline; it has an idle limit instead:
        the node pings every 20 seconds, and a stream silent for STREAM_IDLE_S is a dead one that ends
        here as an XeError, so the listener reconnects and backfills (XE-1935). A line longer than any
        envelope ends it the same way before it is buffered (XE-2305)."""
        idle = httpx.Timeout(self._client.timeout.connect, read=STREAM_IDLE_S)
        try:
            async with self._client.stream("GET", "/chat/events", params=proof, timeout=idle) as r:
                if r.status_code >= 300:
                    raise XeError(r.status_code, f"chat stream refused: {r.reason_phrase}"[:MAX_ERROR_CHARS])
                _refuse_compressed(r)
                buf = bytearray()
                chunks = r.aiter_bytes().__aiter__()
                while True:
                    try:
                        async with asyncio.timeout(STREAM_IDLE_S):   # our own clock, whatever the transport does
                            chunk = await chunks.__anext__()
                    except StopAsyncIteration:
                        return
                    except TimeoutError as e:
                        raise XeError(UNREACHABLE, f"chat stream silent for {STREAM_IDLE_S:.0f}s") from e
                    buf += chunk
                    while (end := buf.find(b"\n")) >= 0:
                        if end > MAX_STREAM_LINE:
                            break   # a whole line past the cap, arrived in one piece: refused below like one that never ends
                        line = bytes(buf[:end]).strip()
                        del buf[:end + 1]
                        if not line.startswith(b"data:"):
                            continue
                        try:
                            item = _parse(line[5:])
                        except XeError:
                            continue
                        if isinstance(item, dict):
                            yield item
                    if len(buf) > MAX_STREAM_LINE:
                        raise XeError(UNREACHABLE, f"chat stream line exceeds {MAX_STREAM_LINE} bytes")
        except _TRANSPORT as e:
            raise XeError(UNREACHABLE, f"{type(e).__name__}: {str(e)[:200]}") from e
