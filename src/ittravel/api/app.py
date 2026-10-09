"""
FastAPI service for Alibi: login-risk scoring plus threat intelligence.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import FileResponse, HTMLResponse
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
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["GET", "POST"], allow_headers=["*"])
app.add_middleware(GZipMiddleware, minimum_size=2048)
app.add_middleware(RateLimitMiddleware)


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


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
async def dashboard():
    index_file = DASHBOARD_DIR / "index.html"
    if index_file.exists():
        # always revalidate the page so a new deploy shows up at once (assets are versioned with ?v=)
        return FileResponse(str(index_file), media_type="text/html", headers={"Cache-Control": "no-cache"})
    return HTMLResponse("<h1>Alibi API</h1><p>See <a href='/docs'>/docs</a></p>")


for module in (auth_routes, demo_routes, intel_routes, globe_routes, health_routes):
    app.include_router(module.router)
