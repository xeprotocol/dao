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
  string no longer than any the protocol writes. Callers hold typed values and do not convert node data
  themselves (XE-2209);
- every method returns the fields the harness reads and no others. What a node sends beside them is not
  typed or bounded by anything here, and a field passed through "untouched" is stored and served by
  whoever keeps the object it rode in on (XE-14105);
- what the node says when it refuses is input like the rest. It goes to the server's log from here, and
  an `XeError` is worded by this module from the status alone: the error's text is stored on rows and
  written to the log the public reads (XE-14195);
- everything returned can be kept: no NaN, no NUL, no unpaired surrogate. Node data is stored in JSONB
  and text columns, and one value Postgres will not take fails the whole write it rides in on (`_parse`);
- only a 2xx is an answer. A redirect is not followed and is not a success; a read that comes back
  empty is malformed, not "nothing there". Only a 404 says nothing is there.

A method the harness does not call is not kept here: an untyped reader is a way round the rule.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from dataclasses import dataclass
from typing import Any, AsyncIterator, Awaitable, Callable
from urllib.parse import quote

import httpx

from .encoding import Block
from .keys import is_hex
from .statechain import StateBlock

log = logging.getLogger("xe.client")

PAGE = 1000
MAX_CHAIN_PAGES = 100   # 100,000 blocks: far past any account the harness reads for weight or fees
# The largest honest response is a full page of account blocks, about 0.6 MiB; a state-chain block is at
# most 256 KiB. Nothing the harness asks for is close to this.
MAX_BODY_BYTES = 8 * 1024 * 1024
# The one read that is a whole store: /chat/messages answers with every envelope the node holds for the
# account past `since`, in one array with no limit to ask for. A node keeps 1,000 envelopes per account of
# up to 8,192 message bytes each, and its JSON writes some bytes as six (`<` as \u003c), so the largest
# answer an honest node can give is about 50 MB. The bound on this read is sized to that. Under the general
# bound a full store was an answer the harness could never take, and since the store only empties with
# time, never again: a thousand large envelopes from anyone closed the DAO's chat (XE-11882).
CHAT_STORE_ENVELOPES = 1000
MAX_CHAT_STORE_BYTES = CHAT_STORE_ENVELOPES * (6 * 8192 + 2048)
REQUEST_DEADLINE_S = 60.0   # the whole of one request, headers to last byte; httpx's own timeout bounds each gap
# The same read gets the time its size needs: 50 MB inside the general minute asks for 7 Mbit/s of every
# node, and a full store on a slower link was the same closed chat by the other bound.
CHAT_STORE_DEADLINE_S = 300.0
MAX_BALANCE_ASSETS = 256    # a balance is stored with every treasury snapshot and shown on the public pages
STREAM_IDLE_S = 90.0        # the node writes a ping to the chat stream every 20 seconds
MAX_STREAM_LINE = 64 * 1024  # a chat envelope carries at most 8,192 bytes of message
MAX_ERROR_CHARS = 500       # of what a node said in refusing, kept for the server's log
MAX_READY_BYTES = 4096      # /ready is a short status object; the health check stores what it is given
MAX_READY_FIELDS = 32
MAX_CHALLENGE_CHARS = 256   # the chat challenge travels back in a query string
MAX_HASH_CHARS = 128        # a hash is 64 hex characters
MAX_IDENT_CHARS = 128       # a network id, a node id, a version: short names the harness stores and publishes
# Any string field the harness reads from a node object. The longest the protocol writes in one is a
# 64-character hash or address, or a memo of 64 bytes; a field with a tighter bound of its own says so.
MAX_FIELD_CHARS = 256
# A state-chain value the harness reads is one it wrote (`dao.registry`: a few hundred bytes), and what
# it reads it serves to every caller of the public registry (XE-14164).
MAX_STATE_VALUE_BYTES = 64 * 1024
# How many JSON values one answer may hold. Bytes are not what parsing costs: an empty object is three
# bytes to send and some hundreds in memory, so an answer of nothing else, inside the byte bound, was
# thirty-five times its size once parsed (XE-14180). The largest honest answer is a page of a thousand
# blocks of some twenty fields each. The chat store has its own reader, which counts as it goes.
MAX_VALUES = 200_000
# One envelope in the node's store, as JSON: 8,192 message bytes, each of which the node may write as six,
# and its other fields.
MAX_ENVELOPE_JSON_CHARS = 6 * 8192 + 2048
MAX_ENVELOPE_FIELDS = 32
MAX_PLAIN_FIELDS = 32       # of the short scalar fields kept beside what a read names (`_plain`)
# The reads whose honest answer is a short object: the node's identity, a tip, a keyset, a balance, a
# directory entry, a challenge, one block. Each is read within this and not within the general bound,
# which is sized for a page of a thousand blocks: under that one a node could have every one of these
# calls read and parse eight megabytes that are then dropped, several times a health check (XE-14164).
MAX_SMALL_BYTES = 256 * 1024
MAX_KEYSET_KEYS = 256       # far past any keyset the protocol takes; a bound on what is kept, not a rule of it
_KEY_HEX = re.compile(r"[0-9a-fA-F]{64}")
_FIELD_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,31}")   # the name of a flag or a count in /ready: a word, not a sentence
INT_LIMIT = 2**63           # what a BIGINT column holds; every XE amount and nanosecond timestamp is far below it


def _seg(value: Any) -> str:
    """One path segment. A caller-supplied key, hash or address is data, never structure: `?`, `#`, `/`
    and the rest are percent-encoded so the node answers for the resource named, or 404s, and never for
    a different one (XE-1489). A value that is not text (an unpaired surrogate) names nothing a node holds,
    and fails as every other call that cannot be made does."""
    try:
        return quote(str(value), safe="")
    except UnicodeEncodeError as e:
        raise XeError(UNREACHABLE, "a path segment is not text") from e


UNREACHABLE = 0   # XeError.status when the node gave no usable answer (connection, timeout, bad or oversized body)


class XeError(RuntimeError):
    """Every way a node call can fail: a status that is not 2xx, no connection, a timeout, a body that is
    too large, is not JSON, or is not the shape the method returns. Callers catch this one type; nothing
    from httpx, json or a type conversion escapes the client. `transient` says whether asking again later
    could succeed: the node said nothing about what was asked. A redirect is that too. It comes from
    whatever stands in front of the node, and a caller that took it for the node's refusal would end a
    signing session on a proxy's change of address.

    The text is this module's or its caller's, never the node's. `said` is what the node (or the proxy in
    front of it) sent with a refusal, for the server's log and for nothing a caller is shown: the message
    is stored on sessions, fees and outbox rows, returned by public routes and written to the public log,
    and a proxy's error page names hosts and builds that are nobody's to publish (XE-14195). Nothing
    decides on either: a refusal is classified by `status` and by what the chain holds."""

    def __init__(self, status: int, message: str, said: str = ""):
        super().__init__(f"node returned {status}: {message}" if status else f"node unreachable: {message}")
        self.status = status
        self.message = message
        self.said = said

    @property
    def transient(self) -> bool:
        return self.status in (UNREACHABLE, 408, 425, 429) or 300 <= self.status < 400 or self.status >= 500

    @property
    def unsent(self) -> bool:
        """No connection to the node was made, so the node was shown nothing. Narrower than `transient`:
        a timeout once connected, or an answer that could not be kept, may be a request the node acted on."""
        return isinstance(self.__cause__, (httpx.ConnectError, httpx.ConnectTimeout, httpx.PoolTimeout))


def _refusal(status: int) -> str:
    """This module's words for a status that is not 2xx."""
    if 300 <= status < 400:
        return "a redirect, which is not followed"
    words = {400: "the request was refused as invalid", 401: "the request was not authorised",
             403: "the request was forbidden", 404: "nothing is there", 408: "the node timed out",
             409: "the request conflicts with what the node holds", 413: "the request was too large",
             429: "too many requests"}.get(status)
    if words is None:
        words = "the node failed" if status >= 500 else "the request was refused"
    return f"{words} (what the node said is in the server's log)"


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


def _keyset(v: Any, what: str) -> dict:
    """A multisig keyset: {"keys": [lower-case str], "threshold": int}, both there, the threshold between
    one and the number of keys. A threshold of zero would be met by no signatures at all, and one past the
    key count by none that exist. Nothing that is not that shape is returned as a keyset: an object with
    no keys used to pass through as it was, and the page that shows the treasury's keyset read `keys` off
    it and failed (XE-14157). An account that has no keyset is `keyset_of`'s None."""
    ks = dict(_obj(v, what))
    if ks.get("threshold") is None:
        ks.pop("threshold", None)
    else:
        ks["threshold"] = _u64(ks["threshold"], f"{what}.threshold")
    for k in ("keys", "threshold"):
        if k not in ks:
            raise malformed(f"{what}.{k} is missing")
    keys = _list(ks["keys"], f"{what}.keys")
    if len(keys) > MAX_KEYSET_KEYS:
        raise malformed(f"{what}.keys holds more than {MAX_KEYSET_KEYS} keys")
    if any(not isinstance(k, str) or not _KEY_HEX.fullmatch(k) for k in keys):
        # A keyset is stored with every health check and shown on the public pages. What is kept is keys:
        # 64 hex characters each, and a bounded number of them (XE-10109, XE-10320).
        raise malformed(f"{what}.keys holds a key that is not 64 hex characters")
    if len({k.lower() for k in keys}) != len(keys):
        raise malformed(f"{what}.keys names a key twice")   # so the bound below counts keys that exist
    if not 1 <= ks.get("threshold", 0) <= len(keys):
        raise malformed(f"{what}.threshold is not between 1 and the number of keys")
    return {**_plain(ks), "keys": [k.lower() for k in keys]}


def _plain(obj: dict) -> dict:
    """The short scalar fields of a node object. Whatever else a keyset answer carries beside its keys is
    not something the harness reads, and it is stored and published with the keys: an unbounded string or
    a nested megabyte there was the same stored bloat by the field next door (XE-10109)."""
    out: dict = {}
    for k, v in obj.items():
        if len(out) == MAX_PLAIN_FIELDS:   # and a bounded number of them: nobody reads past the first few
            break
        if len(str(k)) <= MAX_IDENT_CHARS and (v is None or isinstance(v, (bool, int))
                                               or (isinstance(v, str) and len(v) <= MAX_IDENT_CHARS)):
            out[k] = v
    return out


# `\u0000` as JSON spells it: the escape, not the same six characters after an escaped backslash. A raw
# NUL byte inside a string is not JSON at all and the parser refuses it.
_NUL_ESCAPE = re.compile(r"(?<!\\)(?:\\\\)*\\u0000")


def _refuse_constant(name: str) -> Any:
    raise ValueError(f"{name} is not JSON")


def _finite_float(text: str) -> float:
    f = float(text)
    if f != f or f in (float("inf"), float("-inf")):
        raise ValueError(f"{text[:24]} is not a finite number")
    return f


def _text(raw: bytes) -> str:
    """The body as text the harness can keep: UTF-8, with no NUL escape in it (see `_parse`)."""
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as e:
        raise XeError(UNREACHABLE, f"response is not JSON the harness can keep: {str(e)[:100]}") from e
    if _NUL_ESCAPE.search(text):
        raise XeError(UNREACHABLE, "response carries a NUL character")
    return text


def _parse(raw: bytes) -> Any:
    """JSON from the node, as values the harness can keep. Three things a lenient parser lets through are
    refused here, once, for every read and the chat stream alike: NaN and Infinity (not JSON, and not
    storable as JSON), a NUL character, and a surrogate with no pair (neither is text Postgres or UTF-8
    will take). A string carrying one would be stored by whoever read it and fail that write. A number
    too large to be finite is the first of these by another spelling: `1e400` is valid JSON that Python
    reads as infinity, so it is refused as it is read, and the keep-check writes with `allow_nan=False`
    so nothing non-finite passes by a route the reader did not think of (XE-2870).

    The body is UTF-8 or it is refused. `json.loads` given bytes guesses UTF-16 and UTF-32 as well, and
    the NUL escape spelt in either would pass a search of the bytes and still parse to a NUL.

    A body is refused unparsed when it could hold more than MAX_VALUES values. Every value but the first
    follows a comma or an opening bracket, so those are counted: an overcount where a string holds them,
    which nothing the harness reads through here does in number (hashes, addresses, 64-byte memos)."""
    if len(raw) > MAX_VALUES and raw.count(b",") + raw.count(b"[") + raw.count(b"{") > MAX_VALUES:
        raise XeError(UNREACHABLE, f"response holds more than {MAX_VALUES} values")
    text = _text(raw)
    try:
        v = json.loads(text, parse_constant=_refuse_constant, parse_float=_finite_float)
        json.dumps(v, ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (ValueError, RecursionError) as e:   # not JSON, nested deeper than the parser will go, or not text
        raise XeError(UNREACHABLE, f"response is not JSON the harness can keep: {str(e)[:100]}") from e
    return v


_JSON_SPACE = re.compile(r"[ \t\n\r]*")
_ITEM = json.JSONDecoder(parse_constant=_refuse_constant, parse_float=_finite_float)


def _store(raw: bytes) -> list[dict]:
    """The chat store's answer: a JSON array of envelopes, read one item at a time. The byte bound on
    this read is fifty megabytes because a full store of full messages is, and parsed whole that bound
    was also seventeen million empty objects: gigabytes of memory for an answer no store can give
    (XE-14180). Here an item is parsed from a window one envelope long, so no item costs more than that
    to read; it is kept if it is a flat object of a few fields that can be stored, which is what an
    envelope is, and counted either way; and an answer with more items than a store holds, or an item
    that does not end inside its window, is not a store and is refused whole."""
    text = _text(raw)
    at = _JSON_SPACE.match(text).end()
    if len(text) - at <= 16 and text[at:].strip() == "null":
        return []
    if text[at:at + 1] != "[":
        raise malformed("chat messages is not a list")
    at, out, seen = _JSON_SPACE.match(text, at + 1).end(), [], 0
    while text[at:at + 1] != "]":
        if seen:
            if text[at:at + 1] != ",":
                raise malformed("chat messages is not a list")
            at = _JSON_SPACE.match(text, at + 1).end()
        if seen == CHAT_STORE_ENVELOPES:
            raise malformed(f"chat store holds more than the {CHAT_STORE_ENVELOPES} items a node keeps for an account")
        try:
            item, used = _ITEM.raw_decode(text[at:at + MAX_ENVELOPE_JSON_CHARS])
        except (ValueError, RecursionError) as e:   # not JSON, or an item longer than any envelope
            raise malformed("a chat store item is not JSON, or is longer than any envelope") from e
        if _envelope_shaped(item):
            out.append(item)
        seen, at = seen + 1, _JSON_SPACE.match(text, at + used).end()
    if text[at + 1:at + 17].strip() or len(text) - at > 17:
        raise malformed("chat messages is not a list")
    return out


def _envelope_shaped(item: Any) -> bool:
    """A flat object of a few scalar fields, all of them text and numbers the database takes."""
    if not isinstance(item, dict) or len(item) > MAX_ENVELOPE_FIELDS:
        return False
    if not all(v is None or isinstance(v, (str, int, float)) for v in item.values()):
        return False
    try:
        json.dumps(item, ensure_ascii=False, allow_nan=False).encode("utf-8")
    except ValueError:   # an unpaired surrogate: one item that cannot be kept costs that item
        return False
    return True


def _typed(v: Any, what: str, *, ints: tuple[str, ...] = (), strs: tuple[str, ...] = (),
           need: tuple[str, ...] = (), flags: tuple[str, ...] = (), keep: tuple[str, ...] = ()) -> dict:
    """The named fields of object `v` and no others: each, where present, an integer (`ints`), a string of
    at most MAX_FIELD_CHARS (`strs`), or a boolean (`flags`). A null field is dropped, so
    `d.get(k, default)` means what it says, and so is a flag that is not a boolean: nothing reads it as
    true. `need` fields must be there. `keep` names fields returned as sent, for a caller that has their
    one parser.

    Fields that are not named are not returned. They were, "untouched", and untouched meant any type at
    any length up to the body cap, kept by whoever stored the object: a block hash of megabytes went into
    every vote's eligibility and every fee row read from it (XE-14105)."""
    src, d = _obj(v, what), {}
    for k in ints + strs + flags + keep:
        x = src.get(k)
        if x is None:
            continue
        if k in ints:
            x = _u64(x, f"{what}.{k}")
        elif k in strs:
            if not isinstance(x, str):
                raise malformed(f"{what}.{k} is not a string")
            if len(x) > MAX_FIELD_CHARS:
                raise malformed(f"{what}.{k} is longer than {MAX_FIELD_CHARS} characters")
        elif k in flags and not isinstance(x, bool):
            continue
        d[k] = x
    for k in need:
        if k not in d:
            raise malformed(f"{what}.{k} is missing")
    return d


_BLOCK_INTS = ("balance", "timestamp", "amount")
_BLOCK_STRS = ("type", "account", "previous", "asset", "source", "destination", "memo", "pub_key", "hash")


def account_block(v: Any) -> dict:
    """An account-chain block as the harness reads one: the fields it computes with are integers, the
    fields it compares are bounded strings, and `finalized` is the node's flag where it is a boolean.
    Nothing else of the block is returned."""
    return _typed(v, "block", ints=_BLOCK_INTS, strs=_BLOCK_STRS, flags=("finalized",))


# What httpx raises for a request that could not be made or finished. InvalidURL is not an HTTPError: it
# is raised for a URL too long to send, which a node-supplied value in a path or query can cause.
_TRANSPORT = (httpx.HTTPError, httpx.InvalidURL)


def _small() -> int:
    """The bound on a read whose answer is a short object (MAX_SMALL_BYTES), never past the general one."""
    return min(MAX_SMALL_BYTES, MAX_BODY_BYTES)


def _refuse_compressed(r: httpx.Response) -> None:
    encoding = r.headers.get("content-encoding", "").strip().lower()
    if encoding not in ("", "identity"):
        raise XeError(UNREACHABLE, "response is compressed; the harness asks for no encoding and reads none")


def _refused(status: int, said: str, request: str) -> XeError:
    """The error for an answer that is not 2xx: worded here from the status, with what was sent kept on
    it and written to the server's log, the one place it is read. A 404 is how the node says an account,
    a key or a block is not there, which most callers take as an answer, so it is not logged as a fault."""
    said = said[:MAX_ERROR_CHARS]
    log.log(logging.DEBUG if status == 404 else logging.WARNING, "node answered %d to %s: %r", status, request, said)
    return XeError(status, _refusal(status), said=said)


@dataclass
class _Reply:
    status: int
    body: bytes
    request: str = ""   # the method and path asked, for the log line a refusal gets

    def said(self) -> str:
        """What came back with a refusal, for the server's log: the node's `error` string where the body
        is its JSON error, otherwise the first of the body as text."""
        text = self.body[:4 * MAX_ERROR_CHARS].decode("utf-8", "replace")
        try:
            err = _parse(self.body) if len(self.body) <= MAX_READY_BYTES else None
            if isinstance(err, dict) and isinstance(err.get("error"), str):
                text = err["error"]
        except XeError:
            pass
        return text.replace("\x00", "")[:MAX_ERROR_CHARS]

    def json(self) -> Any:
        return _parse(self.body)


class XeClient:
    def __init__(self, base_url: str, timeout: float = 20.0, transport: httpx.AsyncBaseTransport | None = None):
        self.base_url = base_url.rstrip("/")
        # trust_env=False: the client talks to the one node it was given. httpx otherwise reads the proxy
        # variables of whatever environment the process runs in while the client is built, so node traffic
        # (signed blocks, read proofs) follows an HTTP(S)_PROXY nobody set for it, and a NO_PROXY entry
        # httpx cannot parse stops the process before it starts (XE-3350).
        self._client = httpx.AsyncClient(base_url=self.base_url, timeout=timeout, transport=transport,
                                         headers={"Accept-Encoding": "identity"}, trust_env=False)

    async def aclose(self) -> None:
        await self._client.aclose()

    # ---- plumbing -------------------------------------------------------------------------

    async def _get(self, path: str, *, max_bytes: int | None = None, deadline_s: float | None = None,
                   parse: Callable[[bytes], Any] = _parse, **params: Any) -> Any:
        r = await self._send("GET", path, max_bytes=max_bytes, deadline_s=deadline_s,
                             params={k: v for k, v in params.items() if v is not None})
        if r.status < 300 and not r.body:
            raise malformed("a read came back empty")   # every read returns JSON; nothing at all is not "none"
        return self._unwrap(r, parse)

    async def _post_json(self, path: str, body: Any) -> Any:
        return self._unwrap(await self._send("POST", path, json=body))

    async def _post_raw(self, path: str, body: str) -> Any:
        try:
            content = body.encode("utf-8")
        except ValueError as e:   # an unpaired surrogate: never sent, and only an XeError leaves the client (XE-4592)
            raise XeError(UNREACHABLE, f"request could not be built: {type(e).__name__}") from e
        return self._unwrap(await self._send("POST", path, content=content, headers={"Content-Type": "application/json"}))

    async def _send(self, method: str, path: str, *, max_bytes: int | None = None, deadline_s: float | None = None,
                    **kw: Any) -> _Reply:
        """One request, read as it arrives: at most `max_bytes` kept and at most `deadline_s` spent
        (MAX_BODY_BYTES and REQUEST_DEADLINE_S unless the read is one whose honest answer is known to be
        larger).
        httpx's timeout bounds each silence, not the whole, and it buffers whatever is sent; a node that
        drips a byte at a time or answers with a gigabyte is held to these two bounds instead (XE-2305).
        The bytes counted are the bytes on the wire: the request asks for no compression, and an answer
        that is compressed anyway is refused unread, since a few kilobytes can unpack to gigabytes."""
        limit = MAX_BODY_BYTES if max_bytes is None else max_bytes
        deadline = REQUEST_DEADLINE_S if deadline_s is None else deadline_s
        try:
            async with asyncio.timeout(deadline):
                async with self._client.stream(method, path, **kw) as r:
                    _refuse_compressed(r)   # so the bytes below are the bytes sent, not what they unpack to
                    body = bytearray()
                    async for chunk in r.aiter_bytes():
                        body += chunk
                        if len(body) > limit:
                            raise XeError(UNREACHABLE, f"response exceeds {limit} bytes")
                    return _Reply(r.status_code, bytes(body), f"{method} {path}")
        except _TRANSPORT as e:   # connect, read, write, pool timeouts, transport failures, a URL that cannot be sent
            # its kind and no more: the library's own words carry the address it dialled, and this message
            # is stored on rows and written to the log the public reads (XE-6983). The cause keeps them.
            raise XeError(UNREACHABLE, type(e).__name__) from e
        except TimeoutError as e:
            raise XeError(UNREACHABLE, f"no complete response within {deadline:.0f}s") from e
        except (ValueError, TypeError) as e:   # a body httpx will not encode (NaN, an unpaired surrogate): never sent
            raise XeError(UNREACHABLE, f"request could not be built: {type(e).__name__}") from e

    @staticmethod
    def _unwrap(r: _Reply, parse: Callable[[bytes], Any] = _parse) -> Any:
        if r.status >= 300:   # an error, or a redirect: not followed, and not an answer
            raise _refused(r.status, r.said(), r.request)
        if not r.body:
            return None
        return parse(r.body)

    async def _found(self, path: str, *, max_bytes: int | None = None) -> tuple[bool, Any]:
        """GET, as (found, value). Only a 404 is "not there", which is an answer; a JSON null that was
        found is a value, and the caller says whether it will take one."""
        try:
            return True, await self._get(path, max_bytes=max_bytes)
        except XeError as e:
            if e.status == 404:
                return False, None
            raise

    # ---- node -----------------------------------------------------------------------------

    async def node(self) -> dict:
        """The node's identity: `network_id`, `id` and `version` are strings where present. The two proof
        of work difficulties pass through for `xe.pow.parse_difficulty`, which is their one parser."""
        info = _typed(await self._get("/node", max_bytes=_small()), "node identity", strs=("network_id", "id", "version"),
                      keep=("pow_difficulty", "chat_pow_difficulty"))
        for name in ("pow_difficulty", "chat_pow_difficulty"):
            if not isinstance(info.get(name, ""), str) or len(info.get(name, "")) > MAX_IDENT_CHARS:
                info[name] = "malformed"   # a string its parser refuses, in place of whatever was sent
        for name in ("network_id", "id", "version"):
            # Stored with every health check, written into the log at each start and shown on every page:
            # a name, bounded like every other string kept from the node (XE-10109).
            if len(info.get(name, "")) > MAX_IDENT_CHARS:
                raise malformed(f"node identity {name} is longer than {MAX_IDENT_CHARS} characters")
        return info

    async def ready(self) -> tuple[bool, dict]:
        """(ready, status): the HTTP status as `http_status`, and beside it the flags and counts of the
        status object a 200 came with, under names that are single words. The health check stores this
        and the public health route returns it, so no text from the answer is in it: what answers when a
        node is down is as often the proxy in front of it, and its error page is not the DAO's to publish
        (XE-14223). What was said is in the server's log."""
        r = await self._send("GET", "/ready", max_bytes=_small())
        status: dict = {}
        # The flags and counts of a 200 only. An answer that is not one comes as often from the proxy as
        # from the node, and the names of its fields are its text as much as their values are.
        if r.status == 200 and len(r.body) <= MAX_READY_BYTES:
            try:
                body = r.json()
                if isinstance(body, dict):
                    status = {k: v for k, v in list(body.items())[:MAX_READY_FIELDS]
                              if _FIELD_NAME.fullmatch(k) and isinstance(v, (bool, int)) and abs(v) < INT_LIMIT}
            except XeError:
                pass
        if r.status != 200:
            log.warning("node answered %d to %s: %r", r.status, r.request, r.said())
        return r.status == 200, {**status, "http_status": r.status}

    # ---- accounts ------------------------------------------------------------------------

    async def chain(self, address: str, offset: int = 0, limit: int = PAGE) -> dict:
        """One page of an account's chain: {"blocks": [account_block], "total": int, ...}. A page holding
        more blocks than were asked for is malformed."""
        page = _obj(await self._get(f"/accounts/{_seg(address)}/chain", offset=offset, limit=limit), "chain page")
        blocks = [] if page.get("blocks") is None else _list(page["blocks"], "chain page.blocks")
        if len(blocks) > limit:
            raise malformed(f"chain page holds {len(blocks)} blocks; {limit} were asked for")
        return {"blocks": [account_block(b) for b in blocks],
                "total": 0 if page.get("total") is None else _u64(page["total"], "chain page.total")}

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
        """An account's multisig keyset (see `_keyset`), or None for an account that has none: one the
        node does not know, or one that is not multisig, answered with an object that names neither
        keys nor a threshold. Half a keyset (keys and no threshold, a threshold and no keys) is neither
        answer, and is refused."""
        found, ks = await self._found(f"/accounts/{_seg(address)}/keyset", max_bytes=_small())
        if not found:
            return None
        ks = _obj(ks, "account keyset")
        # No keys and no threshold is an account that is not multisig, however the node spells it: the
        # fields left out, null, or the zero values an encoder writes for an empty one. Anything else is
        # a keyset or is refused: keys with no threshold, a threshold with no keys.
        if ks.get("keys") in (None, []) and ks.get("threshold") in (None, 0) and ks.get("threshold") is not False:
            return None
        return _keyset(ks, "account keyset")

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
        found, res = await self._found(f"/accounts/{_seg(address)}/balance", max_bytes=_small())
        if not found:
            return {}
        bals = _obj(res, "balance").get("balances")
        bals = {} if bals is None else _obj(bals, "balance.balances")
        if len(bals) > MAX_BALANCE_ASSETS or any(len(str(k)) > MAX_IDENT_CHARS for k in bals):
            # what is kept is bounded here, as a keyset's keys are: this goes into every snapshot (XE-10109)
            raise malformed(f"balance holds more than {MAX_BALANCE_ASSETS} assets, or one named in more than "
                            f"{MAX_IDENT_CHARS} characters")
        return {str(k): _u64(v, "a balance") for k, v in bals.items()}

    async def block(self, block_hash: str) -> dict:
        return account_block(await self._get(f"/blocks/{_seg(block_hash)}", max_bytes=_small()))

    async def submit_block(self, b: Block) -> Any:
        return await self._post_json(f"/blocks/{_seg(b.type)}", b.to_json())

    # ---- state chain ---------------------------------------------------------------------

    async def statechain_tip(self) -> dict:
        """The latest state-chain block: `index` and `timestamp` integers, `hash` a string no longer than a
        hash is, all present. Every health check stores the hash, so a long one is refused."""
        tip = _typed(await self._get("/statechain/tip", max_bytes=_small()), "state-chain tip", ints=("index", "timestamp"),
                     strs=("hash", "prev_hash"), need=("index", "timestamp", "hash"))
        if len(tip["hash"]) > MAX_HASH_CHARS:
            raise malformed("state-chain tip hash is longer than a hash")
        return tip

    async def statechain_block(self, index: int) -> dict:
        return _typed(await self._get(f"/statechain/blocks/{_seg(index)}"), "state-chain block",
                      ints=("index", "timestamp"), strs=("hash", "prev_hash"), need=("hash",))

    async def statechain_key(self, key: str) -> Any:
        """Returns the value, or None if the key is not set (a 404). The value is whatever JSON was written,
        in an answer of at most MAX_STATE_VALUE_BYTES: it is served to whoever asks the public registry,
        and under the general bound that was eight megabytes of the node's choosing on every call
        (XE-14164). A null where the node said the key was found is not "not set"."""
        found, res = await self._found(f"/statechain/kv/{_seg(key)}", max_bytes=MAX_STATE_VALUE_BYTES)
        if isinstance(res, dict) and set(res.keys()) == {"key", "value"}:
            res = res["value"]   # the node's envelope is opened first, so the test below is of the value (XE-4592)
        if found and res is None:
            raise malformed("state-chain value is null")
        return res

    async def dao_keyset(self) -> dict:
        """`sys.dao_keyset`: {"keys": [lower-case str], "threshold": int}, both present, the threshold
        between one and the number of keys (see `_keyset`)."""
        ks = _keyset(await self._get("/statechain/keyset", max_bytes=_small()), "keyset")
        return {"keys": ks["keys"], "threshold": ks["threshold"]}

    async def submit_statechain_block(self, b: StateBlock) -> Any:
        return await self._post_raw("/statechain/blocks", b.to_wire())

    # ---- directory and chat --------------------------------------------------------------

    async def directory(self, account: str) -> dict | None:
        """The short scalar fields of an account's directory entry, or None where it has none. The
        harness asks whether the entry is there."""
        found, entry = await self._found(f"/directory/{_seg(account)}", max_bytes=_small())
        return _plain(_obj(entry, "directory entry")) if found else None

    async def directory_register(self, registration: dict) -> Any:
        return await self._post_json("/directory/register", registration)

    async def chat_challenge(self) -> dict:
        ch = _typed(await self._get("/chat/auth/challenge", max_bytes=_small()), "chat challenge", strs=("challenge",), need=("challenge",))
        if len(ch["challenge"]) > MAX_CHALLENGE_CHARS:
            raise malformed("chat challenge is longer than any the node issues")
        if not is_hex(ch["challenge"]):
            raise malformed("chat challenge is not hex")
        return ch

    async def chat_messages(self, proof: dict[str, str], since_ns: int = 0) -> list[dict]:
        """The envelopes the node holds for the proving account, as objects. Whether each is an envelope is
        `xe.chat.Envelope.from_json`'s question, asked per item so one bad item costs one item.

        The answer is read as a store (`_store`): at most CHAT_STORE_ENVELOPES items, each no longer than
        an envelope is and kept only if it is shaped like one."""
        return await self._get("/chat/messages", max_bytes=MAX_CHAT_STORE_BYTES, deadline_s=CHAT_STORE_DEADLINE_S,
                               parse=_store, since=since_ns, **proof)

    async def chat_send(self, envelope: dict) -> Any:
        return await self._post_json("/chat/send", envelope)

    async def chat_events(self, proof: dict[str, str],
                          opened: Callable[[], Awaitable[None]] | None = None) -> AsyncIterator[dict]:
        """Yield chat envelopes (JSON objects) from the SSE stream for one account. Caller handles
        reconnects. The stream is long-lived, so it has no total deadline; it has an idle limit instead:
        the node pings every 20 seconds, and a stream silent for STREAM_IDLE_S is a dead one that ends
        here as an XeError, so the listener reconnects and backfills (XE-1935). A line longer than any
        envelope ends it the same way before it is buffered (XE-2305).

        `opened` is awaited once the node has accepted the stream and before anything from it is yielded.
        The node sends a stream what arrives after it was opened and nothing from before, so that is the
        moment to read the store: what the store read misses the stream already has (XE-5883). If it
        raises, the stream ends there and nothing was yielded."""
        idle = httpx.Timeout(self._client.timeout.connect, read=STREAM_IDLE_S)
        try:
            async with self._client.stream("GET", "/chat/events", params=proof, timeout=idle) as r:
                if r.status_code >= 300:
                    # the reason phrase is the answerer's text like any body, and the body is not read
                    raise _refused(r.status_code, str(r.reason_phrase), "GET /chat/events")
                _refuse_compressed(r)
                if opened is not None:
                    await opened()
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
                        if _envelope_shaped(item):   # as the store read keeps them (`_store`)
                            yield item
                    if len(buf) > MAX_STREAM_LINE:
                        raise XeError(UNREACHABLE, f"chat stream line exceeds {MAX_STREAM_LINE} bytes")
        except _TRANSPORT as e:   # its kind and no more, as in `_send`: the library's words name the address dialled
            raise XeError(UNREACHABLE, type(e).__name__) from e
