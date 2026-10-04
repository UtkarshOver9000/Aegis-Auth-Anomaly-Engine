"""
FastAPI service for Aegis login-risk scoring.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import Depends, FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles

from .. import __version__
from ..engine import get_engine
from ..schema import APIKeyCreate, APIKeyResponse, EvaluationResult, LoginEvent
from ..state import store
from .auth import verify_api_key, verify_master_key

app = FastAPI(
    title="Aegis: login risk scoring",
    description=(
        "Scores each login attempt for account-takeover and attack-IP risk with gradient-boosting models trained "
        "on the RBA login dataset (31.3M logins), plus a physical impossible-travel check when coordinates are "
        "given. State is kept in memory, so the public demo is a sandbox. Metrics: /v1/model."
    ),
    version=__version__,
    license_info={"name": "MIT"},
)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["GET", "POST"], allow_headers=["*"])

DASHBOARD_DIR = Path(__file__).resolve().parent.parent / "dashboard"
if DASHBOARD_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(DASHBOARD_DIR)), name="static")


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
async def dashboard():
    index_file = DASHBOARD_DIR / "index.html"
    if index_file.exists():
        return FileResponse(str(index_file), media_type="text/html")
    return HTMLResponse("<h1>Aegis API</h1><p>See <a href='/docs'>/docs</a></p>")


@app.post("/v1/auth/evaluate", response_model=EvaluationResult, tags=["Evaluation"])
async def evaluate_login(event: LoginEvent, _auth: str = Depends(verify_api_key)):
    """Score one login attempt and update that user's history. Requires `X-API-Key`."""
    return get_engine().evaluate_event(event)


@app.get("/v1/anomalies", tags=["Audit"])
async def get_anomalies(limit: int = Query(50, ge=1, le=200), _auth: str = Depends(verify_api_key)):
    """Recent HIGH and CRITICAL logins scored by this server instance."""
    return store.get_anomalies(limit)


@app.post("/v1/keys/generate", response_model=APIKeyResponse, tags=["Authentication"])
async def generate_key(req: APIKeyCreate, _admin: str = Depends(verify_master_key)):
    """Issue an extra API key. Requires the master key (set AEGIS_API_KEY in production)."""
    return store.create_api_key(req.name)


@app.get("/v1/model", tags=["Model"])
async def model_card():
    """Test-period metrics of the deployed models, from their model card."""
    card = get_engine().card
    return {k: card[k] for k in ("dataset", "alert_budget", "test_metrics", "thresholds", "scikit_learn")}


@app.get("/v1/stats", tags=["Telemetry"])
async def get_stats(_auth: str = Depends(verify_api_key)):
    anomalies = store.get_anomalies(200)
    return {
        "users_seen_by_this_instance": len(store.users),
        "high_or_critical_logins": len(anomalies),
        "critical": sum(1 for a in anomalies if a.get("risk_tier") == "CRITICAL"),
        "version": __version__,
    }


@app.get("/v1/health", include_in_schema=False)
async def health_check():
    return {"status": "ok"}
