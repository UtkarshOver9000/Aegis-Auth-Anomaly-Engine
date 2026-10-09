"""
Keyed endpoints: score one login, audit log, stats, and issuing keys (need ALIBI_API_KEY).
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from ... import __version__
from ...engine import get_engine
from ...schema import APIKeyCreate, APIKeyResponse, EvaluationResult, LoginEvent
from ...state import store
from ..auth import verify_api_key, verify_master_key

router = APIRouter()


@router.post("/v1/auth/evaluate", response_model=EvaluationResult, tags=["Evaluation"])
async def evaluate_login(event: LoginEvent, _auth: str = Depends(verify_api_key)):
    """Score one login attempt and update that user's history. Requires `X-API-Key`."""
    return get_engine().evaluate_event(event)


@router.get("/v1/anomalies", tags=["Audit"])
async def get_anomalies(limit: int = Query(50, ge=1, le=200), _auth: str = Depends(verify_api_key)):
    """Recent HIGH and CRITICAL logins scored by this server instance."""
    return store.get_anomalies(limit)


@router.post("/v1/keys/generate", response_model=APIKeyResponse, tags=["Authentication"])
async def generate_key(req: APIKeyCreate, _admin: str = Depends(verify_master_key)):
    """Issue an extra API key. Requires the master key (ALIBI_API_KEY on the server)."""
    return store.create_api_key(req.name)


@router.get("/v1/stats", tags=["Telemetry"])
async def get_stats(_auth: str = Depends(verify_api_key)):
    anomalies = store.get_anomalies(200)
    return {
        "users_seen_by_this_instance": len(store.users),
        "high_or_critical_logins": len(anomalies),
        "critical": sum(1 for a in anomalies if a.get("risk_tier") == "CRITICAL"),
        "version": __version__,
    }
