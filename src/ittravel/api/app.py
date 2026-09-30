"""
FastAPI SaaS REST API for VigilGuard Identity Threat Detection & Response (ITDR) Platform.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import Depends, FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles

from ..ml_engine import engine
from ..schema import APIKeyCreate, APIKeyResponse, EvaluationResult, LoginEvent
from ..state import store
from .auth import verify_api_key

app = FastAPI(
    title="Aegis ITDR — Identity Threat Detection & Auth Anomaly Engine",
    description=(
        "Enterprise-grade AI-powered impossible travel and authentication anomaly detection. "
        "Evaluates real-time login events using an IsolationForest ensemble model with "
        "Haversine geo-velocity physics, device entropy, and IP subnet analysis."
    ),
    version="2.4.0",
    contact={"name": "Aegis Security by Utkarsh", "url": "https://github.com/UtkarshOver9000/Aegis-Auth-Anomaly-Engine"},
    license_info={"name": "MIT"},
)

# CORS — allow dashboard to call API from same origin on Vercel
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve dashboard static files
DASHBOARD_DIR = Path(__file__).resolve().parent.parent / "dashboard"
if DASHBOARD_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(DASHBOARD_DIR)), name="static")


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
async def serve_dashboard():
    """Serve the VigilGuard enterprise web dashboard."""
    index_file = DASHBOARD_DIR / "index.html"
    if index_file.exists():
        return FileResponse(str(index_file), media_type="text/html")
    return HTMLResponse(
        "<h1>VigilGuard ITDR API</h1><p>Visit <a href='/docs'>/docs</a></p>"
    )


@app.post(
    "/v1/auth/evaluate",
    response_model=EvaluationResult,
    summary="Evaluate Authentication Event",
    tags=["Evaluation"],
)
async def evaluate_login(
    event: LoginEvent,
    _auth: str = Depends(verify_api_key),
):
    """
    Real-time risk evaluation of a login attempt.

    Calculates Haversine distance and physical velocity between the user's
    previous and current location. Returns an ensemble risk score (0–100),
    risk tier (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`), and human-readable
    rationale explaining the AI model's decision.

    **Required header**: `X-API-Key: <your-api-key>`
    """
    return engine.evaluate_event(event)


@app.get("/v1/anomalies", summary="Retrieve Anomaly Audit Log", tags=["Audit"])
async def get_anomalies(
    limit: int = Query(50, ge=1, le=200, description="Max records to return"),
    _auth: str = Depends(verify_api_key),
):
    """Fetch recent high-risk anomaly events from the in-memory audit log."""
    return store.get_anomalies(limit)


@app.post(
    "/v1/keys/generate",
    response_model=APIKeyResponse,
    summary="Provision API Key",
    tags=["Authentication"],
)
async def generate_key(req: APIKeyCreate):
    """
    Generate a new tenant API key (`sk_live_...`) to authenticate API requests.
    Store keys securely in environment variables — they are not recoverable after creation.
    """
    return store.create_api_key(req.name)


@app.get("/v1/stats", summary="Platform Security Telemetry", tags=["Telemetry"])
async def get_telemetry(_auth: str = Depends(verify_api_key)):
    """Aggregate security telemetry: monitored identity count, threat tier breakdown, engine status."""
    anomalies = store.get_anomalies(200)
    return {
        "active_monitored_users": len(store.users),
        "total_anomalies_detected": len(anomalies),
        "critical_threats": sum(1 for a in anomalies if a.get("risk_tier") == "CRITICAL"),
        "high_threats": sum(1 for a in anomalies if a.get("risk_tier") == "HIGH"),
        "engine_status": "ONLINE",
        "model": "IsolationForest-GeoPhysics-Ensemble",
        "version": "2.4.0",
    }


@app.get("/v1/health", include_in_schema=False)
async def health_check():
    """Lightweight uptime health probe for load balancers."""
    return {"status": "ok"}
