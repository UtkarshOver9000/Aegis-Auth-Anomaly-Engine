"""
Fill README.md's numbers and data-source table from the snapshot and sources.yaml, so they cannot drift.

    PYTHONPATH=src python scripts/readme_numbers.py          # rewrite README.md in place
    PYTHONPATH=src python scripts/readme_numbers.py --check  # exit 1 if README.md is out of date

Generated regions sit between <!-- name:start --> and <!-- name:end --> markers.
"""

from __future__ import annotations

import re
import sys
from datetime import date
from pathlib import Path

import yaml

from ittravel.intel import service

ROOT = Path(__file__).resolve().parents[1]


def _day(iso: str) -> str:
    d = date.fromisoformat(iso[:10])
    return f"{d.day} {d:%B %Y}"


def _b(n: float) -> str:
    return f"{n / 1e9:.2f} billion" if n >= 1e9 else f"{n / 1e6:.1f} million"


def numbers() -> str:
    m, b, f, t = service.meta(), service.breaches_summary(), service.flaws_summary(), service.threats()
    c = service.countries()["countries"]
    rw = t["ransomware"]
    blocking = sum(1 for v in c.values() if v["confirmed_blocks"] > 0)
    top_epss = f["most_likely_exploited"][0] if f.get("most_likely_exploited") else None
    rows = [
        (
            "Breaches",
            f"{b['total_breaches']:,} breaches, {_b(b['total_accounts'])} accounts; "
            f"{b['last_12_months']['breaches']} breaches and {_b(b['last_12_months']['accounts'])} accounts "
            "in the last 12 months",
        ),
        (
            "Attacks",
            f"{t['malicious_ips']:,} malware and botnet servers; {t['threatfox_iocs_48h']:,} threat indicators "
            f"in 48 hours; {t['spamhaus_asn_drop']} criminal networks; {rw['victims']} ransomware victims "
            f"({_day(rw['from'])} to {_day(rw['to'])})",
        ),
        (
            "Exploited flaws",
            f"{f['total']:,} flaws; {f['added_last_30_days']} added in the last 30 days; "
            f"{f['ransomware_linked']} used by ransomware"
            + (f"; highest exploit chance {top_epss['cve']} at {top_epss['epss']:.1%}" if top_epss else ""),
        ),
        (
            "Live globe",
            f"{m['states']['states_provinces']:,} states and provinces, {m['cables']['cables']} undersea cables, "
            f"websites confirmed blocked in {blocking} countries",
        ),
    ]
    head = f"Numbers from the snapshot of **{_day(m['fetched_at'])}** (the live app shows the current ones):\n\n"
    hosting = t["hosting_share_of_malicious_ips"]
    iot = t["iot_botnet_ips"] / max(t["malicious_ips"], 1)
    finding = (
        f"\n\n**A finding worth knowing:** only {hosting:.0%} of the malware servers sit on hosting or VPN "
        f"networks, about the same as those networks' {t['hosting_share_of_internet']:.0%} share of all "
        f"addresses; {iot:.0%} are home routers, cameras and other devices hijacked by botnets such as "
        "Mozi and Mirai. Blocking data centers alone misses most of them."
    )
    return head + "| Module | Today |\n|---|---|\n" + "\n".join(f"| {k} | {v} |" for k, v in rows) + finding


def sources() -> str:
    feeds = yaml.safe_load((ROOT / "sources.yaml").read_text(encoding="utf-8"))
    every = {"1d": "daily", "7d": "weekly", "30d": "monthly", "180d": "every 6 months"}
    rows = [
        f"| {f['name']} | {f['licence']} | {every.get(f['cadence'], 'every ' + f['cadence'])} | {f['description']} |"
        for f in feeds["feeds"]
    ]
    rows += [
        f"| {s['name']} | {s['licence']} | static ({s['period']}) | trains and tests the login models |"
        for s in feeds["static"]
    ]
    return (
        "| Source | Licence / terms | Refreshed | Used for |\n|---|---|---|---|\n"
        + "\n".join(rows)
        + "\n\nGenerated from [`sources.yaml`](sources.yaml) by `scripts/readme_numbers.py`."
    )


def render(text: str) -> str:
    for name, body in (("numbers", numbers()), ("sources", sources())):
        text = re.sub(
            rf"(<!-- {name}:start -->).*?(<!-- {name}:end -->)",
            lambda mt, body=body: f"{mt.group(1)}\n{body}\n{mt.group(2)}",
            text,
            flags=re.S,
        )
    return text


if __name__ == "__main__":
    readme = ROOT / "README.md"
    current = readme.read_text(encoding="utf-8")
    fresh = render(current)
    if "--check" in sys.argv:
        sys.exit(0 if fresh == current else "README.md is out of date: run scripts/readme_numbers.py")
    readme.write_text(fresh, encoding="utf-8")
