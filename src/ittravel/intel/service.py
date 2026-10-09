"""
Summaries over the intel snapshot, shaped for the dashboard.
"""

from __future__ import annotations

import json
from collections import Counter
from datetime import date, datetime, timedelta
from functools import cache
from pathlib import Path

from .network import tor_exits

DATA = Path(__file__).resolve().parents[1] / "intel_data"
SOURCES = {
    "breaches": {"name": "Have I Been Pwned", "url": "https://haveibeenpwned.com", "license": "CC BY 4.0"},
    "flaws": {
        "name": "CISA Known Exploited Vulnerabilities catalog",
        "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        "license": "US government public data",
    },
    "network": {"name": "iptoasn.com", "url": "https://iptoasn.com", "license": "PDDL (public domain)"},
    "tor": {"name": "Tor Project Onionoo", "url": "https://metrics.torproject.org", "license": "Tor Metrics data"},
    "dns": {"name": "public-dns.info", "url": "https://public-dns.info", "license": "public list, counts only"},
    "censorship": {
        "name": "OONI (Open Observatory of Network Interference)",
        "url": "https://explorer.ooni.org",
        "license": "CC BY-NC-SA 4.0",
    },
    "malware": {"name": "abuse.ch Feodo Tracker, ThreatFox and URLhaus", "url": "https://abuse.ch", "license": "CC0"},
    "criminal_networks": {
        "name": "Spamhaus DROP and ASN-DROP",
        "url": "https://www.spamhaus.org/blocklists/do-not-route-or-peer/",
        "license": "free to use, per Spamhaus DROP terms",
    },
    "ransomware": {
        "name": "RansomLook",
        "url": "https://www.ransomlook.io",
        "license": "CC BY 4.0; totals only, no victim names or leak links",
    },
    "cables": {
        "name": "TeleGeography Submarine Cable Map",
        "url": "https://www.submarinecablemap.com",
        "license": "CC BY-NC-SA 3.0",
    },
    "geolocation": {
        "name": "IP Geolocation by DB-IP (IP to City Lite)",
        "url": "https://db-ip.com",
        "license": "CC BY 4.0",
    },
    "states": {
        "name": "Natural Earth admin-1 states and provinces",
        "url": "https://www.naturalearthdata.com",
        "license": "public domain",
    },
    "earth_imagery": {
        "name": "NASA Blue Marble (via three-globe)",
        "url": "https://visibleearth.nasa.gov/collection/1484/blue-marble",
        "license": "public domain (NASA)",
    },
}


@cache
def _load(name: str):
    return json.loads((DATA / name).read_text(encoding="utf-8"))


def meta() -> dict:
    return _load("meta.json")


def snapshot_date() -> date:
    return date.fromisoformat(meta()["fetched_at"][:10])


def breaches_summary() -> dict:
    rows = _load("breaches.json")
    today = snapshot_date()
    year_ago = (today - timedelta(days=365)).isoformat()
    recent = [r for r in rows if r["breach_date"] >= year_ago]
    by_year = Counter()
    for r in rows:
        by_year[r["breach_date"][:4]] += r["accounts"]
    data_types = Counter(d for r in rows for d in r["data"])
    companies = [r for r in rows if r["kind"] == "company"]
    return {
        "total_breaches": len(rows),
        "total_accounts": sum(r["accounts"] for r in rows),
        "last_12_months": {"breaches": len(recent), "accounts": sum(r["accounts"] for r in recent)},
        "accounts_by_year": {y: by_year[y] for y in sorted(by_year) if y >= "2010"},
        "most_exposed_data": data_types.most_common(10),
        "biggest": sorted(rows, key=lambda r: r["accounts"], reverse=True)[:10],
        "biggest_companies": sorted(companies, key=lambda r: r["accounts"], reverse=True)[:25],
        "how_stolen": Counter(r["how"] for r in companies).most_common(),
        "how_stolen_accounts": Counter(
            {h: sum(r["accounts"] for r in companies if r["how"] == h) for h in {r["how"] for r in companies}}
        ).most_common(),
        "lists": {
            "count": len(rows) - len(companies),
            "accounts": sum(r["accounts"] for r in rows if r["kind"] == "list"),
        },
        "latest": sorted(rows, key=lambda r: r["added"], reverse=True)[:15],
        "source": SOURCES["breaches"],
        "as_of": meta()["fetched_at"],
    }


def all_breaches() -> list[dict]:
    return _load("breaches.json")


def flaws_summary() -> dict:
    rows = _load("flaws.json")
    today = snapshot_date()
    in_days = lambda d: [r for r in rows if r["added"] >= (today - timedelta(days=d)).isoformat()]  # noqa: E731
    by_month = Counter(r["added"][:7] for r in rows)
    months = sorted(by_month)[-12:]
    return {
        "total": len(rows),
        "added_last_7_days": len(in_days(7)),
        "added_last_30_days": len(in_days(30)),
        "ransomware_linked": sum(r["ransomware"] for r in rows),
        "top_vendors": Counter(r["vendor"] for r in rows).most_common(12),
        "top_vendors_last_12_months": Counter(r["vendor"] for r in in_days(365)).most_common(10),
        "added_by_month": {m: by_month[m] for m in months},
        "latest": rows[:20],
        "most_likely_exploited": sorted((r for r in rows if r.get("epss") is not None), key=lambda r: -r["epss"])[:10],
        "epss_date": meta()["flaws"].get("epss_date"),
        "source": SOURCES["flaws"],
        "as_of": meta()["fetched_at"],
    }


def countries() -> dict:
    return {
        "countries": _load("countries.json"),
        "totals": meta()["countries"],
        "as_of": meta()["fetched_at"],
        "sources": {k: SOURCES[k] for k in ("tor", "dns", "censorship", "network", "malware", "ransomware", "cables")},
    }


def threats() -> dict:
    return {
        **_load("threats.json"),
        "as_of": meta()["threats_fetched_at"],
        "sources": {k: SOURCES[k] for k in ("malware", "criminal_networks", "ransomware", "network")},
    }


def cables() -> dict:
    return {**_load("cables.json"), "source": SOURCES["cables"]}


def overview(model_card: dict) -> dict:
    b, f, c = breaches_summary(), flaws_summary(), _load("countries.json")
    ato = model_card["test_metrics"]["ato"]
    return {
        "takeovers_caught": {
            "caught": ato["confusion_matrix"]["tp"],
            "of": ato["positives"],
            "challenge_rate": ato["alert_rate"],
            "roc_auc": ato["roc_auc"],
        },
        "accounts_exposed_last_12_months": b["last_12_months"]["accounts"],
        "breaches_last_12_months": b["last_12_months"]["breaches"],
        "exploited_flaws_last_30_days": f["added_last_30_days"],
        "ransomware_linked_flaws": f["ransomware_linked"],
        "malicious_ips": meta()["threats"]["malicious_ips"],
        "threat_indicators_48h": meta()["threats"]["threatfox_iocs_48h"],
        "criminal_networks": meta()["threats"]["spamhaus_asn_drop"],
        "ransomware_victims": _load("threats.json")["ransomware"],
        "submarine_cables": meta()["cables"]["cables"],
        "tor_exit_relays": meta()["countries"]["tor_exit_relays"],
        "tor_exit_ips_known": len(tor_exits()),
        "public_dns_resolvers": meta()["countries"]["dns_resolvers"],
        "censorship_tests_30d": meta()["countries"]["ooni_measurements"],
        "total_breaches": b["total_breaches"],
        "total_accounts_exposed": b["total_accounts"],
        "countries_with_confirmed_blocking": sum(1 for v in c.values() if v["confirmed_blocks"] > 0),
        "as_of": meta()["fetched_at"],
    }


def bad_ip(ip: str) -> dict | None:
    """The abuse.ch report behind a malware-server IP, if it is in the snapshot."""
    return _load("bad_ips.json").get(ip)


# The login models were trained once on the RBA dataset; these periods are the splits in rba/train.py.
MODELS = [
    {
        "name": "Account-takeover model",
        "data": "RBA login dataset (Wiefling et al., 2022)",
        "licence": "CC BY 4.0",
        "url": "https://zenodo.org/records/6782156",
        "data_period": "2020-02-03 to 2020-11-30",
        "train": "Feb to Jul 2020",
        "validate": "Aug to Sep 2020",
        "test": "Oct to Nov 2020",
        "note": "Values synthesized by the dataset's authors from real logins; city values are random.",
    },
    {
        "name": "Attack-IP model",
        "data": "RBA login dataset (Wiefling et al., 2022)",
        "licence": "CC BY 4.0",
        "url": "https://zenodo.org/records/6782156",
        "data_period": "2020-02-03 to 2021-02-28",
        "train": "first 70% by time",
        "validate": "next 15%",
        "test": "Jan to Feb 2021",
        "note": "Trained once; not retrained since.",
    },
]


def freshness() -> dict:
    """How current each number is: every feed's last download, and the models' data periods."""
    return {"snapshot": meta()["fetched_at"], "feeds": meta().get("feeds", []), "models": MODELS}


def search(q: str, limit: int = 10) -> dict:
    """One search box for everything: an IP, a CVE id, or text matched against breaches and flaws."""
    import ipaddress
    import re

    from .network import lookup

    q = q.strip()
    try:
        ipaddress.ip_address(q)
    except ValueError:
        pass
    else:
        net = lookup(q)
        return {"kind": "ip", "query": q, "ip": {**net.__dict__, "type": net.label}, "report": bad_ip(q)}
    if re.fullmatch(r"(?i)cve-\d{4}-\d{4,}", q):
        hits = [f for f in _load("flaws.json") if f["cve"].upper() == q.upper()]
        return {"kind": "cve", "query": q, "flaws": hits}
    needle = q.lower()
    breaches = [b for b in _load("breaches.json") if needle in b["name"].lower() or needle in b["domain"].lower()]
    flaws = [f for f in _load("flaws.json") if needle in f["vendor"].lower() or needle in f["product"].lower()]
    return {
        "kind": "text",
        "query": q,
        "breaches": sorted(breaches, key=lambda b: -b["accounts"])[:limit],
        "breach_matches": len(breaches),
        "flaws": flaws[:limit],
        "flaw_matches": len(flaws),
    }


def _records(feed_id: str) -> int | None:
    """How many records each feed contributed to the snapshot."""
    m, threats = meta(), _load("threats.json")
    by_source = dict(threats["by_source"])
    return {
        "hibp_breaches": m["breaches"]["breaches"],
        "cisa_kev": m["flaws"]["flaws"],
        "iptoasn": m["network"]["ranges"],
        "public_dns": m["countries"]["dns_resolvers"],
        "ooni": m["countries"]["ooni_measurements"],
        "feodo": by_source.get("Feodo Tracker", 0),
        "urlhaus": threats["urlhaus_urls_30d"],
        "threatfox": threats["threatfox_iocs_48h"],
        "spamhaus_drop": threats["spamhaus_drop_ranges"],
        "spamhaus_asndrop": threats["spamhaus_asn_drop"],
        "ransomlook": threats["ransomware"]["victims"],
        "cables": m["cables"]["cables"],
        "cable_landings": m["cables"]["landing_points"],
        "dbip_city": m.get("heat", {}).get("malware_located"),
        "natural_earth_admin1": m["states"]["states_provinces"],
        "tor_onionoo": m["countries"]["tor_exit_relays"],
    }.get(feed_id)


def health(now: datetime | None = None) -> dict:
    """Per-feed status: last successful download, age, record count, and whether it is past its max age."""
    from datetime import UTC

    now = now or datetime.now(UTC)
    units = {"h": 3600, "d": 86400}
    feeds = []
    for f in meta().get("feeds", []):
        age = (now - datetime.fromisoformat(f["updated"])).total_seconds() if f["updated"] else None
        limit = int(f["max_age"][:-1]) * units[f["max_age"][-1]]
        status = "missing" if not f["available"] else ("stale" if age is None or age > limit else "ok")
        if status != "ok" and f["optional"]:
            status = "optional, " + status
        feeds.append(
            {
                "id": f["id"],
                "status": status,
                "last_success": f["updated"],
                "age_hours": round(age / 3600, 1) if age is not None else None,
                "records": _records(f["id"]),
            }
        )
    degraded = any(x["status"] in ("stale", "missing") for x in feeds)
    return {"status": "degraded" if degraded else "ok", "snapshot": meta()["fetched_at"], "feeds": feeds}


# How much each signal counts towards a flaw's patch priority (0 to 100). Every flaw here is already being
# exploited (CISA KEV); the score orders them by what is likely to hit next and how widely.
PRIORITY_WEIGHTS = {"epss": 50, "ransomware": 20, "vendor_reach": 15, "recency": 15}


def prioritised_flaws(vendors: list[str] | None = None, limit: int = 20) -> list[dict]:
    """KEV flaws ranked by EPSS percentile, ransomware use, how often the vendor appears in KEV, and recency."""
    import math

    rows = _load("flaws.json")
    per_vendor = Counter(r["vendor"] for r in rows)
    top_vendor = max(per_vendor.values())
    today = snapshot_date()
    wanted = [v.lower() for v in vendors or [] if v.strip()]
    out = []
    for r in rows:
        if wanted and not any(w in r["vendor"].lower() or w in r["product"].lower() for w in wanted):
            continue
        days = (today - date.fromisoformat(r["added"])).days
        parts = {
            "epss": r.get("epss_pct") or 0.0,
            "ransomware": 1.0 if r["ransomware"] else 0.0,
            "vendor_reach": math.log1p(per_vendor[r["vendor"]]) / math.log1p(top_vendor),
            "recency": max(0.0, 1 - days / 365),
        }
        score = sum(PRIORITY_WEIGHTS[k] * v for k, v in parts.items())
        out.append({**r, "priority": round(score, 1), "priority_parts": {k: round(v, 3) for k, v in parts.items()}})
    return sorted(out, key=lambda r: -r["priority"])[:limit]
