"""
Overall and per-feed health for uptime monitors.
"""

from __future__ import annotations

from fastapi import APIRouter

from ...intel import service

router = APIRouter()


@router.get("/v1/health", tags=["Health"])
async def health_check():
    """Overall status plus every feed's last download, age and record count. "degraded" if any feed is stale."""
    return service.health()
