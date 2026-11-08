"""FastAPI application: JSON API under /v1, server-rendered pages elsewhere."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.exc import DataError, IntegrityError, StatementError
from starlette.exceptions import HTTPException as StarletteHTTPException

from xe.client import XeError

from . import __version__
from .api import legal, members, public
from .config import lint_public_copy
from .context import get_context
from .db import session
from .mirror import MarkdownMirror
from .ui import router as ui_router

log = logging.getLogger("dao.app")
HERE = Path(__file__).parent


@asynccontextmanager
async def lifespan(app: FastAPI):
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    ctx = get_context()
    await ctx.refresh_node()
    violations = lint_public_copy(ctx.config)
    app.state.copy_violations = violations
    if violations:
        log.warning("public copy lint: %d violation(s): %s", len(violations), violations[:5])
    try:
        async with session() as db:
            await ctx.events.append(db, "api.started", "harness", {
                "version": __version__, "network_id": ctx.node.network_id, "git_commit": ctx.settings.git_commit,
                "config_hashes": ctx.config.hashes, "copy_lint_violations": len(violations),
            }, public=True)
            await db.commit()
    except Exception as e:
        log.warning("could not write api.started (database not ready?): %s", e)
    yield
    await ctx.aclose()


app = FastAPI(title="XE DAO", version=__version__, lifespan=lifespan, docs_url="/v1/docs", openapi_url="/v1/openapi.json")

app.include_router(public.router)
app.include_router(legal.router)
app.include_router(members.router)
app.include_router(ui_router)
app.mount("/static", StaticFiles(directory=str(HERE / "static")), name="static")
# every page as markdown: /x.md, /index.md, or Accept: text/markdown
app.add_middleware(MarkdownMirror, base_url=lambda: get_context().settings.public_base_url)

# The largest legitimate write is a resolution (50k chars of body plus ops of up to 64 KiB each); anything
# past a megabyte is not a request we have a route for, and is refused before it is parsed.
MAX_BODY_BYTES = 1 << 20


class BodyLimit:
    def __init__(self, app, limit: int = MAX_BODY_BYTES):
        self.app, self.limit = app, limit

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope.get("method") not in ("POST", "PUT", "PATCH"):
            return await self.app(scope, receive, send)
        declared = next((v for k, v in scope.get("headers", []) if k == b"content-length"), None)
        if declared is not None and declared.isdigit() and int(declared) > self.limit:
            return await self._refuse(send)
        seen = 0
        tripped = False
        answered = False

        async def counted():
            nonlocal seen, tripped
            msg = await receive()
            if msg["type"] == "http.request":
                seen += len(msg.get("body", b""))
                if seen > self.limit:
                    tripped = True
                    raise _TooLarge()
            return msg

        async def guarded(msg):
            # Once the stream is cut, whatever the app answers (FastAPI turns an error in its body reader
            # into its own 400) is replaced by the one 413 in the common shape (XE-0650).
            nonlocal answered
            if not tripped:
                return await send(msg)
            if not answered:
                answered = True
                await self._refuse(send)

        try:
            await self.app(scope, counted, guarded)
        except _TooLarge:
            pass
        if tripped and not answered:
            await self._refuse(send)

    @staticmethod
    async def _refuse(send):
        body = b'{"error":"request body too large","status":413}'
        await send({"type": "http.response.start", "status": 413, "headers": [
            (b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())]})
        await send({"type": "http.response.body", "body": body})


class _TooLarge(Exception):
    pass


app.add_middleware(BodyLimit)


@app.exception_handler(StarletteHTTPException)
async def http_error(request: Request, exc: StarletteHTTPException):
    headers = dict(exc.headers or {})
    if request.url.path.startswith("/v1"):
        return JSONResponse({"error": exc.detail, "status": exc.status_code}, status_code=exc.status_code, headers=headers)
    from .ui import render
    resp = render(request, "error.html", {"status": exc.status_code, "detail": exc.detail}, status_code=exc.status_code)
    resp.headers.update(headers)
    return resp


@app.exception_handler(RequestValidationError)
async def validation_error(request: Request, exc: RequestValidationError):
    """Same shape as every other error: one line naming the field, no echo of the input (XE-0080)."""
    first = (exc.errors() or [{}])[0]
    where = ".".join(str(x) for x in first.get("loc", []) if x not in ("body", "query", "path"))
    detail = f"{where}: {first.get('msg', 'invalid')}" if where else str(first.get("msg", "invalid request"))
    if request.url.path.startswith("/v1"):
        return JSONResponse({"error": detail, "status": 422}, status_code=422)
    from .ui import render
    return render(request, "error.html", {"status": 422, "detail": detail}, status_code=422)


@app.exception_handler(StatementError)
async def statement_error(request: Request, exc: StatementError):
    """A parameter the database cannot hold (U+0000 in text, an integer past int64) is the caller's error,
    whichever read or write path carried it (XE-0967). Anything else from the driver is still ours."""
    if isinstance(exc, DataError) or isinstance(exc.orig, (OverflowError, ValueError)):
        return await http_error(request, StarletteHTTPException(400, "a parameter is not representable"))
    return await unhandled_error(request, exc)


@app.exception_handler(IntegrityError)
async def integrity_error(request: Request, exc: IntegrityError):
    """Two requests wrote the same unique key and the database kept one: a fee block reused by two submits,
    a pause started twice. The loser's request conflicts with a write that has since landed; it is a 409 to
    retry or re-read, never a 500, on every table with a unique key (XE-1290, XE-1435). The transaction is
    already rolled back by the session's exit."""
    log.info("conflicting write on %s %s: %s", request.method, request.url.path, str(exc.orig)[:200])
    return await http_error(request, StarletteHTTPException(409, "conflicts with a write that has just landed; re-read and retry"))


@app.exception_handler(XeError)
async def node_error(request: Request, exc: XeError):
    """The node refused or failed a read the request needed: a 502 that says so, not a 500 that says nothing."""
    log.warning("node error on %s %s: %s", request.method, request.url.path, exc)
    return await http_error(request, StarletteHTTPException(502, "node error"))


@app.exception_handler(OverflowError)
async def overflow_error(request: Request, exc: OverflowError):
    """The driver raises this bare when an integer parameter does not fit int64; it is the caller's number."""
    return await http_error(request, StarletteHTTPException(400, "a parameter is not representable"))


@app.exception_handler(Exception)
async def unhandled_error(request: Request, exc: Exception):
    """Anything we did not expect: log it in full here, say nothing specific to the client (XE-0080)."""
    log.exception("unhandled error on %s %s", request.method, request.url.path)
    if request.url.path.startswith("/v1"):
        return JSONResponse({"error": "internal error", "status": 500}, status_code=500)
    from .ui import render
    return render(request, "error.html", {"status": 500, "detail": "internal error"}, status_code=500)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    resp = await call_next(request)
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    # Pages carry seat keys in the signer; everything they load is first-party except the fonts, and they
    # talk only to this origin. Inline scripts remain (the page scripts), so this bounds exfiltration and
    # injection surface rather than script execution (XE-0702).
    resp.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src https://fonts.gstatic.com; script-src 'self' 'unsafe-inline'; connect-src 'self'; "
        "frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'",
    )
    if request.url.path.startswith("/v1"):
        resp.headers.setdefault("Access-Control-Allow-Origin", "*")
        resp.headers.setdefault("Cache-Control", "no-store")
    return resp
