"""
Summaries over the intel snapshot, shaped for the dashboard.
"""

from __future__ import annotations

import json
from collections import Counter
from datetime import date, timedelta
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
        "name": "ransomware.live",
        "url": "https://www.ransomware.live",
        "license": "public tracker; only aggregate counts shown, no victim names or leak links",
    },
    "cables": {
        "name": "TeleGeography Submarine Cable Map",
        "url": "https://www.submarinecablemap.com",
        "license": "CC BY-NC-SA 3.0",
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
