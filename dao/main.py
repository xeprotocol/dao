"""FastAPI application: JSON API under /v1, server-rendered pages elsewhere."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException

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


@app.exception_handler(StarletteHTTPException)
async def http_error(request: Request, exc: StarletteHTTPException):
    if request.url.path.startswith("/v1"):
        return JSONResponse({"error": exc.detail, "status": exc.status_code}, status_code=exc.status_code)
    from .ui import render
    return render(request, "error.html", {"status": exc.status_code, "detail": exc.detail}, status_code=exc.status_code)


@app.exception_handler(Exception)
async def unhandled_error(request: Request, exc: Exception):
    import logging
    logging.getLogger("dao").exception("unhandled error on %s: %s", request.url.path, exc)
    if request.url.path.startswith("/v1"):
        return JSONResponse({"error": "internal_error", "detail": str(exc), "status": 500}, status_code=500)
    from .ui import render
    return render(request, "error.html", {"status": 500, "detail": "Internal Server Error"}, status_code=500)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    resp = await call_next(request)
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    if request.url.path.startswith("/v1"):
        resp.headers.setdefault("Access-Control-Allow-Origin", "*")
        resp.headers.setdefault("Cache-Control", "no-store")
    return resp
