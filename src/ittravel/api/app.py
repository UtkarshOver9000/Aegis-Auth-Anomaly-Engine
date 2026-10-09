"""
FastAPI service for Alibi: login-risk scoring plus threat intelligence.
"""

from __future__ import annotations

import re
from pathlib import Path
from uuid import uuid4

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles

from .. import __version__
from ..intel import service
from .ratelimit import RateLimitMiddleware
from .routes import auth as auth_routes
from .routes import demo as demo_routes
from .routes import globe as globe_routes
from .routes import health as health_routes
from .routes import intel as intel_routes

app = FastAPI(
    title="Alibi: login security and threat intelligence",
    description=(
        "Scores each login attempt for account-takeover and attack-IP risk with gradient-boosting models trained "
        "on the RBA login dataset (31.3M logins), plus a physical impossible-travel check when coordinates are "
        "given. State is kept in memory, so the public demo is a sandbox. Metrics: /v1/model."
    ),
    version=__version__,
    license_info={"name": "MIT"},
)
# Public read API: any origin may read, but only these headers are accepted and no cookies are involved.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "X-API-Key"],
    expose_headers=["X-Data-As-Of", "X-Request-ID", "Retry-After"],
    allow_credentials=False,
)
app.add_middleware(GZipMiddleware, minimum_size=2048)
app.add_middleware(RateLimitMiddleware)


SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
}
# The dashboard loads only its own files, plus map tiles and YouTube thumbnails as images.
PAGE_CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data: blob: https://tile.openstreetmap.org https://i.ytimg.com; connect-src 'self'; "
    "font-src 'self'; worker-src 'self' blob:; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
)


REQUEST_ID = re.compile(r"[A-Za-z0-9-]{8,64}")


MAX_BODY = 256 * 1024  # a 30-event demo story is about 12 KB


@app.middleware("http")
async def body_limit(request, call_next):
    if int(request.headers.get("content-length") or 0) > MAX_BODY:
        return JSONResponse({"detail": "Request body too large"}, status_code=413)
    return await call_next(request)


@app.middleware("http")
async def request_id(request, call_next):
    """Echo a caller's X-Request-ID (or make one) so a request can be traced through logs."""
    rid = request.headers.get("x-request-id", "")
    rid = rid if REQUEST_ID.fullmatch(rid) else uuid4().hex
    response = await call_next(request)
    response.headers["X-Request-ID"] = rid
    return response


@app.middleware("http")
async def cache_headers(request, call_next):
    """Snapshot data changes at most every few hours: let browsers and the CDN cache reads briefly."""
    response = await call_next(request)
    path = request.url.path
    if request.method == "GET" and path.startswith("/v1/intel/") and "cache-control" not in response.headers:
        response.headers["Cache-Control"] = "public, max-age=300, s-maxage=1800, stale-while-revalidate=86400"
    elif path == "/v1/health":
        response.headers["Cache-Control"] = "no-store"
    return response


@app.middleware("http")
async def security_headers(request, call_next):
    response = await call_next(request)
    for name, value in SECURITY_HEADERS.items():
        response.headers.setdefault(name, value)
    if request.url.path == "/":
        response.headers["Content-Security-Policy"] = PAGE_CSP
    return response


@app.middleware("http")
async def data_age_header(request, call_next):
    """Every API response says which snapshot it was built from, including images and files."""
    response = await call_next(request)
    if request.url.path.startswith("/v1/"):
        response.headers["X-Data-As-Of"] = service.meta()["fetched_at"]
    return response


DASHBOARD_DIR = Path(__file__).resolve().parent.parent / "dashboard"
if DASHBOARD_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(DASHBOARD_DIR)), name="static")


SECURITY_TXT = """Contact: https://github.com/UtkarshOver9000/alibi/security/advisories/new
Expires: 2027-10-01T00:00:00.000Z
Preferred-Languages: en
Canonical: https://impossible-travel-auth-anomaly-engi.vercel.app/.well-known/security.txt
Policy: https://github.com/UtkarshOver9000/alibi/blob/main/docs/SECURITY.md#reporting-a-vulnerability
"""


@app.get("/.well-known/security.txt", include_in_schema=False)
async def security_txt():
    """RFC 9116: where to report a vulnerability."""
    return PlainTextResponse(SECURITY_TXT)


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
async def dashboard():
    index_file = DASHBOARD_DIR / "index.html"
    if index_file.exists():
        # always revalidate the page so a new deploy shows up at once (assets are versioned with ?v=)
        return FileResponse(str(index_file), media_type="text/html", headers={"Cache-Control": "no-cache"})
    return HTMLResponse("<h1>Alibi API</h1><p>See <a href='/docs'>/docs</a></p>")


for module in (auth_routes, demo_routes, intel_routes, globe_routes, health_routes):
    app.include_router(module.router)
