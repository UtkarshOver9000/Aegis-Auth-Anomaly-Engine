"""
FastAPI service for Alibi: login-risk scoring plus threat intelligence.
"""

from __future__ import annotations

from pathlib import Path
from uuid import uuid4

from fastapi import Depends, FastAPI, HTTPException, Query, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles

from .. import __version__
from ..engine import get_engine
from ..intel import globe, news, service
from ..intel.network import lookup, malware_ip, sample_ips, tor_exits
from ..schema import APIKeyCreate, APIKeyResponse, DemoStory, EvaluationResult, LoginEvent
from ..state import store
from .auth import verify_api_key, verify_master_key
from .ratelimit import RateLimitMiddleware

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


@app.post("/v1/auth/evaluate", response_model=EvaluationResult, tags=["Evaluation"])
async def evaluate_login(event: LoginEvent, _auth: str = Depends(verify_api_key)):
    """Score one login attempt and update that user's history. Requires `X-API-Key`."""
    return get_engine().evaluate_event(event)


@app.get("/v1/anomalies", tags=["Audit"])
async def get_anomalies(limit: int = Query(50, ge=1, le=200), _auth: str = Depends(verify_api_key)):
    """Recent HIGH and CRITICAL logins scored by this server instance."""
    return store.get_anomalies(limit)


@app.post("/v1/demo/check", tags=["Evaluation"])
async def demo_check(story: DemoStory):
    """Score a whole sign-in story in one call, no key needed: the account's usual sign-ins, then the one being
    tested. Runs under a fresh throwaway user id, so the public demo never touches other accounts."""
    uid = f"demo-{uuid4().hex[:12]}"
    engine = get_engine()
    results = [engine.evaluate_event(e.model_copy(update={"user_id": uid})) for e in story.events]
    timeline = [{"tier": r.risk_tier, "score": r.risk_score, "reasons": r.reasons[:3], "distance_km": r.distance_km,
                 "velocity_kmph": r.velocity_kmph, "network": r.network} for r in results]
    return {"history_logins": len(results) - 1, "verdict": results[-1], "timeline": timeline}


@app.post("/v1/keys/generate", response_model=APIKeyResponse, tags=["Authentication"])
async def generate_key(req: APIKeyCreate, _admin: str = Depends(verify_master_key)):
    """Issue an extra API key. Requires the master key (ALIBI_API_KEY on the server)."""
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


@app.get("/v1/intel/overview", tags=["Intel"])
async def intel_overview():
    """Headline numbers for the home page, all from the real data sources."""
    return service.overview(get_engine().card)


@app.get("/v1/intel/breaches", tags=["Intel"])
async def intel_breaches(full: bool = False):
    """Data breaches from Have I Been Pwned (CC BY 4.0). `full=true` returns every breach."""
    return {"breaches": service.all_breaches()} if full else service.breaches_summary()


@app.get("/v1/intel/flaws", tags=["Intel"])
async def intel_flaws():
    """Vulnerabilities known to be exploited in the wild (CISA KEV catalog)."""
    return service.flaws_summary()


@app.get("/v1/intel/countries", tags=["Intel"])
async def intel_countries():
    """Per-country Tor exits, public DNS resolvers, hosting IP space and OONI censorship measurements."""
    return service.countries()


@app.get("/v1/intel/threats", tags=["Intel"])
async def intel_threats():
    """Criminal infrastructure right now: malware and botnet servers (abuse.ch), criminal networks (Spamhaus),
    recent ransomware victims as aggregate counts (ransomware.live)."""
    return service.threats()


@app.get("/v1/intel/cables", tags=["Intel"])
async def intel_cables():
    """Submarine internet cables and landing stations (TeleGeography, CC BY-NC-SA 3.0)."""
    return service.cables()


@app.get("/v1/intel/sources", tags=["Intel"])
async def intel_sources():
    """Every data source behind the numbers, with its license."""
    return {**service.SOURCES, "news_feeds": news.NEWS_FEEDS, "video_feeds": news.VIDEO_FEEDS}


@app.get("/v1/intel/states", tags=["Intel"])
async def intel_states():
    """State and province borders (Natural Earth, public domain), simplified for the globe."""
    return FileResponse(str(service.DATA / "states.json"), media_type="application/json")


@app.get("/v1/intel/heat", tags=["Intel"])
async def intel_heat():
    """City-level hotspots of malware servers and public DNS servers (located with DB-IP, CC BY 4.0)."""
    return FileResponse(str(service.DATA / "heat.json"), media_type="application/json")


# Globe images change only when the snapshot does: let browsers keep them an hour and the CDN a day.
GLOBE_CACHE = {"Cache-Control": "public, max-age=3600, s-maxage=86400, stale-while-revalidate=86400"}


@app.get("/v1/intel/globe/pick.png", tags=["Globe"])
async def globe_pick():
    """State lookup image: each state's pixels hold its index + 1 as red * 256 + green."""
    return Response(globe.pick_map(), media_type="image/png", headers=GLOBE_CACHE)


@app.get("/v1/intel/globe/places", tags=["Globe"])
async def globe_places():
    """Per state, in pick-image order: name, country, type, malware servers, DNS servers, IPv4 addresses."""
    return {"columns": ["name", "country", "type", "malware", "dns", "ipv4"], "rows": globe.places()}


@app.get("/v1/intel/globe/state/{index}", tags=["Globe"])
async def globe_state(index: int):
    """One state's outline, for highlighting it."""
    if not 0 <= index < len(globe.places()):
        raise HTTPException(404, "No such state")
    return globe.state(index)


@app.get("/v1/intel/globe/{metric}.jpg", tags=["Globe"])
async def globe_texture(metric: str, w: int = Query(4096)):
    """Earth texture with every state coloured by this metric (2048 or 4096 pixels wide)."""
    if metric not in globe.METRICS or w not in globe.SIZES:
        raise HTTPException(404, f"metric must be one of {sorted(globe.METRICS)}, w one of {globe.SIZES}")
    return Response(globe.texture(metric, w), media_type="image/jpeg", headers=GLOBE_CACHE)


@app.get("/v1/intel/globe/{metric}/legend", tags=["Globe"])
async def globe_legend(metric: str):
    """Colour classes, units and the top 10 places for one globe metric."""
    if metric not in globe.METRICS:
        raise HTTPException(404, f"metric must be one of {sorted(globe.METRICS)}")
    return {**globe.legend(metric), "top": globe.top(metric), "as_of": service.meta()["fetched_at"]}


@app.get("/v1/intel/news", tags=["Intel"])
async def intel_news():
    """Latest security headlines and videos from public feeds (cached for 30 minutes)."""
    return {"news": news.latest(news.NEWS_FEEDS, "news")[:40], "videos": news.latest(news.VIDEO_FEEDS, "videos")[:12]}


@app.get("/v1/intel/ip/{ip}", tags=["Intel"])
async def intel_ip(ip: str):
    """Who owns an IP address, and whether it is a Tor exit or a hosting / VPN network."""
    net = lookup(ip)
    return {**net.__dict__, "type": net.label}


@app.get("/v1/intel/sample-ips", tags=["Intel"])
async def intel_sample_ips(country: str = Query(..., min_length=2, max_length=2)):
    """Real example IPs for a country: its biggest home ISPs and hosting / VPN networks, plus a live Tor exit."""
    cc = country.upper()
    hosting = sample_ips(cc, True, 1) or sample_ips("US", True, 1)
    tor = sorted(tor_exits())
    return {"home": sample_ips(cc, False, 2), "hosting": hosting, "tor": tor[len(tor) // 2] if tor else None,
            "malware": malware_ip(cc)}


@app.get("/v1/health", include_in_schema=False)
async def health_check():
    return {"status": "ok"}
