"""
Keyless demo scoring of a whole sign-in story, and the deployed models' metrics.
"""

from __future__ import annotations

from uuid import uuid4

from fastapi import APIRouter, HTTPException

from ...engine import get_engine
from ...schema import DemoStory

router = APIRouter()


@router.post("/v1/demo/check", tags=["Evaluation"])
async def demo_check(story: DemoStory):
    """Score a whole sign-in story in one call, no key needed: the account's usual sign-ins, then the one being
    tested. Runs under a fresh throwaway user id, so the public demo never touches other accounts."""
    uid = f"demo-{uuid4().hex[:12]}"
    engine = get_engine()
    results = [engine.evaluate_event(e.model_copy(update={"user_id": uid})) for e in story.events]
    timeline = [
        {
            "tier": r.risk_tier,
            "score": r.risk_score,
            "reasons": r.reasons[:3],
            "distance_km": r.distance_km,
            "velocity_kmph": r.velocity_kmph,
            "network": r.network,
        }
        for r in results
    ]
    return {"history_logins": len(results) - 1, "verdict": results[-1], "timeline": timeline}


@router.get("/v1/model", tags=["Model"])
async def model_card():
    """Test-period metrics of the deployed models, from their model card."""
    card = get_engine().card
    if not card:
        raise HTTPException(503, "Model files are not deployed here; verdicts use the network and travel rules only")
    return {k: card[k] for k in ("dataset", "alert_budget", "test_metrics", "thresholds", "scikit_learn")}
