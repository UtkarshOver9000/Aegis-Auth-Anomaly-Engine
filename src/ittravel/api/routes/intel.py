"""
Read-only threat intelligence from the daily snapshot, plus live news and IP lookups.
"""

from __future__ import annotations

from fastapi import APIRouter, Query
from fastapi.responses import FileResponse

from ...engine import get_engine
from ...intel import news, service, stix
from ...intel.network import lookup, malware_ip, sample_ips, tor_exits

router = APIRouter()


@router.get("/v1/intel/overview", tags=["Intel"])
async def intel_overview():
    """Headline numbers for the home page, all from the real data sources."""
    return service.overview(get_engine().card)


@router.get("/v1/intel/breaches", tags=["Intel"])
async def intel_breaches(full: bool = False):
    """Data breaches from Have I Been Pwned (CC BY 4.0). `full=true` returns every breach."""
    return {"breaches": service.all_breaches()} if full else service.breaches_summary()


@router.get("/v1/intel/flaws", tags=["Intel"])
async def intel_flaws():
    """Vulnerabilities known to be exploited in the wild (CISA KEV catalog)."""
    return service.flaws_summary()


@router.get("/v1/intel/flaws/priority", tags=["Intel"])
async def intel_flaw_priority(vendors: str = Query("", max_length=300)):
    """Exploited flaws ranked for patching (EPSS, ransomware use, vendor reach, recency).
    `vendors` is a comma-separated filter, for example `Fortinet,Citrix,Microsoft`."""
    picked = [v for v in vendors.split(",") if v.strip()]
    return {
        "weights": service.PRIORITY_WEIGHTS,
        "vendors": picked,
        "flaws": service.prioritised_flaws(picked),
        "as_of": service.meta()["fetched_at"],
    }


@router.get("/v1/intel/countries", tags=["Intel"])
async def intel_countries():
    """Per-country Tor exits, public DNS resolvers, hosting IP space and OONI censorship measurements."""
    return service.countries()


@router.get("/v1/intel/threats", tags=["Intel"])
async def intel_threats():
    """Criminal infrastructure right now: malware and botnet servers (abuse.ch), criminal networks (Spamhaus),
    recent ransomware victims as aggregate counts (ransomware.live)."""
    return service.threats()


@router.get("/v1/intel/cables", tags=["Intel"])
async def intel_cables():
    """Submarine internet cables and landing stations (TeleGeography, CC BY-NC-SA 3.0)."""
    return {**service.cables(), "as_of": service.meta()["fetched_at"]}


@router.get("/v1/intel/search", tags=["Intel"])
async def intel_search(q: str = Query(..., min_length=2, max_length=100)):
    """Search an IP address, a CVE id, or a company / product name across breaches and exploited flaws."""
    return {**service.search(q), "as_of": service.meta()["fetched_at"]}


@router.get("/v1/intel/freshness", tags=["Intel"])
async def intel_freshness():
    """When each feed was last downloaded, its licence, and the period of the data behind each model."""
    return service.freshness()


@router.get("/v1/intel/sources", tags=["Intel"])
async def intel_sources():
    """Every data source behind the numbers, with its license."""
    return {**service.SOURCES, "news_feeds": news.NEWS_FEEDS, "video_feeds": news.VIDEO_FEEDS}


@router.get("/v1/intel/states", tags=["Intel"])
async def intel_states():
    """State and province borders (Natural Earth, public domain), simplified for the globe."""
    return FileResponse(str(service.DATA / "states.json"), media_type="application/json")


@router.get("/v1/intel/events", tags=["Intel"])
async def intel_events():
    """Typed points for the globe: malware servers with their report time (unix seconds), Tor exits and
    Spamhaus criminal ranges, each placed by DB-IP: [lat, lng, type, time]."""
    return FileResponse(str(service.DATA / "events.json"), media_type="application/json")


@router.get("/v1/intel/activity", tags=["Intel"])
async def intel_activity():
    """Malware servers reported today (UTC) and per hour over the 48 hours before the snapshot."""
    return service.activity()


@router.get("/v1/intel/heat", tags=["Intel"])
async def intel_heat():
    """City-level hotspots of malware servers and public DNS servers (located with DB-IP, CC BY 4.0)."""
    return FileResponse(str(service.DATA / "heat.json"), media_type="application/json")


@router.get("/v1/intel/news", tags=["Intel"])
async def intel_news():
    """Latest security headlines and videos from public feeds (cached for 30 minutes)."""
    items = {"news": news.latest(news.NEWS_FEEDS, "news")[:40], "videos": news.latest(news.VIDEO_FEEDS, "videos")[:12]}
    return {**items, "as_of": news.fetched_at("news")}


@router.get("/v1/intel/ip/{ip}", tags=["Intel"])
async def intel_ip(ip: str):
    """Who owns an IP address, and whether it is a Tor exit or a hosting / VPN network."""
    net = lookup(ip)
    return {**net.__dict__, "type": net.label, "as_of": service.meta()["fetched_at"]}


@router.get("/v1/intel/ip/{ip}/stix", tags=["Intel"])
async def intel_ip_stix(ip: str):
    """Everything Alibi knows about an IP as a STIX 2.1 bundle (observable, indicator, malware, sightings)."""
    net = lookup(ip)
    report = service.bad_ip(ip)
    objects = stix.malware_server(ip, report) if report else [stix.ipv4(ip, net.asn)]
    if net.asn and not report:
        objects.append(stix.autonomous_system(net.asn, net.network))
    return stix.bundle(objects)


@router.get("/v1/intel/sample-ips", tags=["Intel"])
async def intel_sample_ips(country: str = Query(..., min_length=2, max_length=2)):
    """Real example IPs for a country: its biggest home ISPs and hosting / VPN networks, plus a live Tor exit."""
    cc = country.upper()
    hosting = sample_ips(cc, True, 1) or sample_ips("US", True, 1)
    tor = sorted(tor_exits())
    return {
        "home": sample_ips(cc, False, 2),
        "hosting": hosting,
        "tor": tor[len(tor) // 2] if tor else None,
        "malware": malware_ip(cc),
    }
