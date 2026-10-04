"""
Who owns an IP address, which country it is announced from, and whether it is a
Tor exit, a hosting/cloud/VPN network, a server reported for malware (abuse.ch)
or part of a network run by criminals (Spamhaus DROP). Data: the intel snapshot,
plus the Tor Project's live exit list.
"""

from __future__ import annotations

import ipaddress
import json
import os
import time
import urllib.request
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import numpy as np

DATA = Path(__file__).resolve().parents[1] / "intel_data"
TOR_LIVE_URL = "https://check.torproject.org/torbulkexitlist"
_tor_live: tuple[float, frozenset[str]] = (0.0, frozenset())


@dataclass(frozen=True)
class NetworkInfo:
    ip: str
    asn: int | None
    network: str | None
    country: str | None
    hosting: bool
    tor_exit: bool
    private: bool
    threat: str | None = None  # what abuse.ch saw this IP doing, e.g. "Botnet control server (Cobalt Strike)"
    criminal_network: bool = False  # on Spamhaus DROP / ASN-DROP

    @property
    def label(self) -> str:
        if self.private:
            return "private network"
        if self.threat:
            return "known malware server"
        if self.criminal_network:
            return "criminal network (Spamhaus DROP)"
        if self.tor_exit:
            return "Tor exit node"
        if self.hosting:
            return "hosting / VPN network"
        return "home or mobile network" if self.asn else "unknown network"


@lru_cache(maxsize=1)
def _tables():
    z = np.load(DATA / "network.npz")
    names = json.loads((DATA / "network_names.json").read_text())
    return z["start"], z["end"], z["asn"], z["cc"], z["hosting"], names["countries"], names["asn_names"]


@lru_cache(maxsize=1)
def _threat_tables():
    bad = json.loads((DATA / "bad_ips.json").read_text())
    drop = np.load(DATA / "drop.npz")
    return bad, drop["start"], drop["end"], set(drop["asn"].tolist())


def _threat(ip: str, n: int, asn: int | None) -> tuple[str | None, bool]:
    bad, d_start, d_end, d_asn = _threat_tables()
    hit = bad.get(ip)
    threat = f"{hit['what']} ({hit['malware']}), reported to {hit['source']} on {hit['seen']}" if hit else None
    i = int(np.searchsorted(d_start, n, side="right")) - 1
    return threat, (i >= 0 and n <= d_end[i]) or (asn in d_asn)


def tor_exits() -> frozenset[str]:
    """Tor exit IPs: the snapshot list, else the Tor Project's live bulk list (cached for an hour)."""
    global _tor_live
    path = DATA / "tor_exits.json"
    snapshot = frozenset(json.loads(path.read_text())) if path.exists() else frozenset()
    if snapshot or os.getenv("ALIBI_OFFLINE"):
        return snapshot
    if time.time() - _tor_live[0] > 3600:
        try:
            with urllib.request.urlopen(TOR_LIVE_URL, timeout=6) as resp:
                ips = frozenset(line.strip() for line in resp.read().decode().splitlines() if line.strip())
        except Exception:  # unreachable (blocked network, offline): Tor check is skipped, not faked
            ips = _tor_live[1]
        _tor_live = (time.time(), ips)
    return _tor_live[1]


def lookup(ip: str) -> NetworkInfo:
    start, end, asn, cc, hosting, countries, asn_names = _tables()
    tor = tor_exits()
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return NetworkInfo(ip, None, None, None, False, False, False)
    if addr.version != 4 or addr.is_private or addr.is_loopback or addr.is_reserved:
        return NetworkInfo(ip, None, None, None, False, ip in tor, bool(addr.is_private or addr.is_loopback))
    n = int(addr)
    i = int(np.searchsorted(start, n, side="right")) - 1
    if i < 0 or n > end[i]:
        threat, criminal = _threat(ip, n, None)
        return NetworkInfo(ip, None, None, None, False, ip in tor, False, threat, criminal)
    a = int(asn[i])
    threat, criminal = _threat(ip, n, a)
    return NetworkInfo(
        ip,
        a,
        asn_names.get(str(a)),
        countries[int(cc[i])] or None,
        bool(hosting[i]),
        ip in tor,
        False,
        threat,
        criminal,
    )


def sample_ips(country: str, hosting: bool, n: int = 2) -> list[dict]:
    """Real example IPs from the country's biggest networks (by prefixes announced): home ISPs or hosting / VPN."""
    start, end, asn, cc, host, countries, asn_names = _tables()
    if country not in countries:
        return []
    idx = np.flatnonzero((cc == countries.index(country)) & (host == hosting) & (asn != 0))
    if not idx.size:
        return []
    asns, counts = np.unique(asn[idx], return_counts=True)
    out = []
    for a in asns[np.argsort(-counts)][:n]:
        rows = idx[asn[idx] == a]
        i = rows[np.argmax((end[rows] - start[rows]).astype(np.int64))]
        out.append(
            {"ip": str(ipaddress.ip_address(int(start[i]) + 1)), "asn": int(a), "network": asn_names.get(str(int(a)))}
        )
    return out


def malware_ip(country: str) -> str | None:
    """A real IP reported for malware in this country (else anywhere), most recently seen first."""
    bad = _threat_tables()[0]
    ranked = sorted(bad.items(), key=lambda kv: kv[1]["seen"], reverse=True)
    return next((ip for ip, v in ranked if v.get("country") == country), ranked[0][0] if ranked else None)
