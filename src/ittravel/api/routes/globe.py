"""
Globe textures, the state pick map, places and legends, rendered from the snapshot.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, Response

from ...intel import globe, service

router = APIRouter()

# Globe images change only when the snapshot does: let browsers keep them an hour and the CDN a day.
GLOBE_CACHE = {"Cache-Control": "public, max-age=3600, s-maxage=86400, stale-while-revalidate=86400"}


@router.get("/v1/intel/globe/pick.png", tags=["Globe"])
async def globe_pick():
    """State lookup image: each state's pixels hold its index + 1 as red * 256 + green."""
    return Response(globe.pick_map(), media_type="image/png", headers=GLOBE_CACHE)


@router.get("/v1/intel/globe/places", tags=["Globe"])
async def globe_places():
    """Per state, in pick-image order: name, country, type, malware servers, DNS servers, IPv4 addresses."""
    return {
        "columns": ["name", "country", "type", "malware", "dns", "ipv4"],
        "rows": globe.places(),
        "as_of": service.meta()["fetched_at"],
    }


@router.get("/v1/intel/globe/state/{index}", tags=["Globe"])
async def globe_state(index: int):
    """One state's outline, for highlighting it."""
    if not 0 <= index < len(globe.places()):
        raise HTTPException(404, "No such state")
    return globe.state(index)


@router.get("/v1/intel/globe/{metric}.jpg", tags=["Globe"])
async def globe_texture(metric: str, w: int = Query(4096)):
    """Earth texture with every state coloured by this metric (2048 or 4096 pixels wide)."""
    if metric not in globe.METRICS or w not in globe.SIZES:
        raise HTTPException(404, f"metric must be one of {sorted(globe.METRICS)}, w one of {globe.SIZES}")
    return Response(globe.texture(metric, w), media_type="image/jpeg", headers=GLOBE_CACHE)


@router.get("/v1/intel/globe/{metric}/legend", tags=["Globe"])
async def globe_legend(metric: str):
    """Colour classes, units and the top 10 places for one globe metric."""
    if metric not in globe.METRICS:
        raise HTTPException(404, f"metric must be one of {sorted(globe.METRICS)}")
    return {
        **globe.legend(metric),
        "top": globe.top(metric),
        "ranks": globe.ranks(metric),
        "as_of": service.meta()["fetched_at"],
    }
