"""
Build the threat-intelligence snapshot that the app serves.

    python -m ittravel.intel.snapshot --raw data/intel

Sources (all public, credited in the app and README):
* Have I Been Pwned breach list (CC BY 4.0)            -> breaches.json
* CISA Known Exploited Vulnerabilities catalog          -> flaws.json
* iptoasn.com IP-to-network table (public domain)       -> network.npz (+ per-country hosting IPs)
* Tor Project Onionoo exit relays                       -> per-country Tor exits + exit IP list
* public-dns.info public DNS resolvers                  -> per-country counts
* OONI web-connectivity measurements (CC BY-NC-SA 4.0)  -> per-country censorship counts
* abuse.ch Feodo Tracker, ThreatFox, URLhaus (CC0)      -> threats.json + bad_ips.json
* Spamhaus DROP and ASN-DROP (free blocklists)          -> drop.npz + threats.json
* ransomware.live recent victims (aggregate counts only) -> threats.json
* TeleGeography Submarine Cable Map (CC BY-NC-SA 3.0)   -> cables.json (the globe's connections)
* Natural Earth admin-1 states and provinces (public domain) -> states.json (borders + click lookup)
* DB-IP IP to City Lite (CC BY 4.0)                     -> heat.json (city-level hotspots, per-state counts)
"""

from __future__ import annotations

import argparse
import csv
import gzip
import html
import ipaddress
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from urllib.parse import urlsplit

import numpy as np

OUT = Path(__file__).resolve().parents[1] / "intel_data"

# Network owners whose address space is rented servers, cloud or VPN infrastructure.
# Written for this project from well-known provider names (matched against iptoasn's AS descriptions).
HOSTING_KEYWORDS = (
    "AMAZON",
    "AWS",
    "GOOGLE-CLOUD",
    "MICROSOFT-CORP-MSN",
    "AZURE",
    "DIGITALOCEAN",
    "LINODE",
    "AKAMAI-LINODE",
    "OVH",
    "HETZNER",
    "VULTR",
    "CHOOPA",
    "M247",
    "DATACAMP",
    "CDN77",
    "CDNEXT",
    "LEASEWEB",
    "CONTABO",
    "SCALEWAY",
    "ONLINE S.A.S",
    "HOSTINGER",
    "IONOS",
    "ALIBABA",
    "TENCENT",
    "ORACLE",
    "CLOUDFLARE",
    "PACKETHUB",
    "ZENLAYER",
    "PSYCHZ",
    "COLOCROSSING",
    "QUADRANET",
    "NFORCE",
    "WORLDSTREAM",
    "FRANTECH",
    "G-CORE",
    "GCORE",
    "SERVERS-COM",
    "TZULO",
    "PERFORMIVE",
    "CLOUVIDER",
    "CONSTANT",
    "HOSTWINDS",
    "INTERSERVER",
    "KAMATERA",
    "CYBERZONE",
    "UPCLOUD",
    "IPXO",
    "HOSTROYALE",
    "STARK INDUSTRIES",
    "AEZA",
    "PROTON",
    "NORDVPN",
    "MULLVAD",
    "EXPRESSVPN",
    "PRIVATE INTERNET",
    "SURFSHARK",
    "WINDSCRIBE",
    "VPN",
)


def is_hosting(description: str) -> bool:
    d = description.upper()
    return any(k in d for k in HOSTING_KEYWORDS)


def build_network(raw: Path) -> tuple[dict, Counter]:
    starts, ends, asns, ccs, hosting = [], [], [], [], []
    names: dict[int, str] = {}
    hosting_ips: Counter = Counter()
    with gzip.open(raw / "ip2asn-v4.tsv.gz", "rt", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            start, end, asn, cc, desc = line.rstrip("\n").split("\t")
            asn = int(asn)
            if asn == 0:
                continue
            s, e = int(ipaddress.IPv4Address(start)), int(ipaddress.IPv4Address(end))
            h = is_hosting(desc)
            starts.append(s)
            ends.append(e)
            asns.append(asn)
            ccs.append(cc if cc != "None" else "")
            hosting.append(h)
            names.setdefault(asn, desc)
            if h and cc not in ("", "None"):
                hosting_ips[cc] += e - s + 1
    cc_list = sorted(set(ccs))
    cc_index = {c: i for i, c in enumerate(cc_list)}
    np.savez_compressed(
        OUT / "network.npz",
        start=np.array(starts, dtype=np.uint32),
        end=np.array(ends, dtype=np.uint32),
        asn=np.array(asns, dtype=np.uint32),
        cc=np.array([cc_index[c] for c in ccs], dtype=np.uint16),
        hosting=np.array(hosting, dtype=bool),
    )
    (OUT / "network_names.json").write_text(json.dumps({"countries": cc_list, "asn_names": names}))
    return {
        "ranges": len(starts),
        "networks": len(names),
        "hosting_networks": sum(is_hosting(n) for n in names.values()),
    }, hosting_ips


# How a breach happened, read from Have I Been Pwned's own write-up of it. Checked in order; first match wins.
HOW_RULES = [
    ("Credential-stuffing list", r"credential[- ]stuffing|combolist|combo list"),
    ("Info-stealer malware", r"stealer|malware"),
    (
        "Left open online",
        r"publicly (facing|accessible|exposed)|without (a |any )?password|unsecured|unprotected|"
        r"misconfigur|left (exposed|open)|exposed (elasticsearch|mongodb|database|server|kibana)|"
        r"open (elasticsearch|mongodb)|s3 bucket",
    ),
    ("Scraped", r"scrap"),
    ("Ransomware / extortion", r"ransom|extort"),
    ("Phishing / social engineering", r"phish|social engineering|vishing|sim[- ]swap"),
    ("Through a supplier", r"third[- ]party|supplier|vendor|service provider|contractor"),
    ("Insider", r"insider|rogue employee|former employee|disgruntled"),
    ("Software flaw exploited", r"sql injection|vulnerab|exploit"),
    ("Hacked, method not disclosed", r"hack|breach|attack|compromis|unauthori[sz]ed|intrusion"),
]


def plain(text: str) -> str:
    return re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]+>", " ", text or ""))).strip()


def how_stolen(b: dict, summary: str) -> str:
    if b.get("IsStealerLog"):
        return "Info-stealer malware"
    low = summary.lower()
    return next((label for label, pattern in HOW_RULES if re.search(pattern, low)), "Not disclosed")


def build_breaches(raw: Path) -> dict:
    data = json.loads((raw / "hibp_breaches.json").read_text(encoding="utf-8"))
    rows = []
    for b in data:
        if b.get("IsSpamList") or b.get("IsFabricated"):
            continue
        summary = plain(b["Description"])
        how = how_stolen(b, summary)
        rows.append(
            {
                "name": b["Title"],
                "domain": b.get("Domain") or "",
                "breach_date": b["BreachDate"],
                "added": b["AddedDate"][:10],
                "accounts": b["PwnCount"],
                "data": b["DataClasses"],
                "verified": b["IsVerified"],
                "sensitive": b["IsSensitive"],
                "how": how,
                "kind": "list"
                if how in ("Credential-stuffing list", "Info-stealer malware") or b.get("IsMalware")
                else "company",
                "summary": summary[:900],
            }
        )
    rows.sort(key=lambda r: r["breach_date"], reverse=True)
    (OUT / "breaches.json").write_text(json.dumps(rows, separators=(",", ":")))
    return {
        "breaches": len(rows),
        "accounts": sum(r["accounts"] for r in rows),
        "how": Counter(r["how"] for r in rows).most_common(),
    }


def build_flaws(raw: Path) -> dict:
    data = json.loads((raw / "cisa_kev.json").read_text(encoding="utf-8"))
    rows = [
        {
            "cve": v["cveID"],
            "vendor": v["vendorProject"],
            "product": v["product"],
            "name": v["vulnerabilityName"],
            "added": v["dateAdded"],
            "due": v["dueDate"],
            "ransomware": v.get("knownRansomwareCampaignUse") == "Known",
            "action": v.get("requiredAction", ""),
        }
        for v in data["vulnerabilities"]
    ]
    rows.sort(key=lambda r: r["added"], reverse=True)
    (OUT / "flaws.json").write_text(json.dumps(rows, separators=(",", ":")))
    return {"flaws": len(rows), "catalog_version": data.get("catalogVersion"), "released": data.get("dateReleased")}


def _ip_networks(ips: list[str]) -> dict[str, tuple[int, str, str, bool]]:
    """ip -> (asn, network name, country, is_hosting) from the snapshot's iptoasn table."""
    z = np.load(OUT / "network.npz")
    names = json.loads((OUT / "network_names.json").read_text())
    parsed = {}
    for ip in ips:
        try:
            parsed[ip] = int(ipaddress.IPv4Address(ip))
        except ValueError:
            continue
    keys = list(parsed)
    nums = np.array([parsed[k] for k in keys], dtype=np.int64)
    idx = np.searchsorted(z["start"].astype(np.int64), nums, side="right") - 1
    out = {}
    for ip, n, i in zip(keys, nums, idx, strict=True):
        if i >= 0 and n <= int(z["end"][i]):
            a = int(z["asn"][i])
            out[ip] = (
                a,
                names["asn_names"].get(str(a), ""),
                names["countries"][int(z["cc"][i])],
                bool(z["hosting"][i]),
            )
    return out


THREAT_TYPES = {
    "botnet_cc": "Botnet control server",
    "payload_delivery": "Malware download site",
    "cc_skimming": "Card-skimming site",
    "payload": "Malware file",
    "malware_download": "Malware download site",
}
GENERIC_TAGS = {
    "",
    "none",
    "32-bit",
    "64-bit",
    "elf",
    "arm",
    "arm7",
    "mips",
    "mipsel",
    "sh4",
    "x86",
    "x86_64",
    "i686",
    "powerpc",
    "m68k",
    "sparc",
    "ascii",
    "bash",
    "sh",
    "exe",
    "dll",
    "zip",
    "opendir",
    "ua-wget",
    "botnetdomain",
}
IOT_BOTNETS = {
    "mirai",
    "mozi",
    "gafgyt",
    "bashlite",
    "hajime",
    "moobot",
    "kaiten",
    "tsunami",
    "xorddos",
    "32-bit",
    "elf",
}


def _jsonl(path: Path, prefix: str) -> list[dict]:
    return [json.loads(ln) for ln in path.read_text(encoding="utf-8").splitlines() if ln.startswith(prefix)]


def build_threats(raw: Path) -> tuple[dict, Counter, Counter]:
    """Criminal infrastructure seen right now: botnet control servers, malware sites, criminal networks, ransomware."""
    bad: dict[str, dict] = {}  # ip -> what it was reported for

    for r in json.loads((raw / "feodo_c2.json").read_text(encoding="utf-8")):
        bad[r["ip_address"]] = {
            "what": "Botnet control server",
            "malware": r["malware"],
            "source": "Feodo Tracker",
            "seen": (r.get("last_online") or r["first_seen"])[:10],
            "online": r["status"] == "online",
        }

    tf = json.loads((raw / "threatfox_recent.json").read_text(encoding="utf-8"))
    tf_rows = [r for group in tf.values() for r in group]
    for r in tf_rows:
        if r["ioc_type"] == "ip:port":
            ip = r["ioc_value"].rsplit(":", 1)[0]
            bad.setdefault(
                ip,
                {
                    "what": THREAT_TYPES.get(r["threat_type"], r["threat_type"]),
                    "malware": r["malware_printable"],
                    "source": "ThreatFox",
                    "seen": r["first_seen_utc"][:10],
                    "online": True,
                },
            )

    with open(raw / "urlhaus_recent.csv", encoding="utf-8", errors="replace") as fh:
        uh_rows = [row for row in csv.reader(ln for ln in fh if not ln.startswith("#")) if len(row) >= 8]
    uh_online = 0
    for _id, added, url, status, _last, threat, tags, *_ in uh_rows:
        uh_online += status == "online"
        host = urlsplit(url).hostname or ""
        if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", host):
            family = next((t for t in tags.split(",") if t.strip().lower() not in GENERIC_TAGS), "unnamed")
            bad.setdefault(
                host,
                {
                    "what": THREAT_TYPES.get(threat, threat),
                    "malware": family.strip(),
                    "source": "URLhaus",
                    "seen": added[:10],
                    "online": status == "online",
                },
            )

    nets = _ip_networks(list(bad))
    by_network: Counter = Counter()
    by_country: Counter = Counter()
    on_hosting = iot = 0
    for ip, info in bad.items():
        n = nets.get(ip)
        if n:
            info["asn"], info["network"], info["country"], info["hosting"] = n
            by_network[n[0]] += 1
            by_country[n[2]] += 1
            on_hosting += n[3]
        iot += info["malware"].lower() in IOT_BOTNETS
    (OUT / "bad_ips.json").write_text(json.dumps(bad, separators=(",", ":")))

    z = np.load(OUT / "network.npz")
    sizes = z["end"].astype(np.int64) - z["start"].astype(np.int64) + 1
    names = json.loads((OUT / "network_names.json").read_text())["asn_names"]
    hosting_asns = set(np.unique(z["asn"][z["hosting"]]).tolist())

    drop = _jsonl(raw / "spamhaus_drop_v4.json", '{"cidr"')
    asn_drop = _jsonl(raw / "spamhaus_asndrop.json", '{"asn"')
    drop_asns = {d["asn"] for d in asn_drop}
    drop_nets = sorted((ipaddress.IPv4Network(d["cidr"]) for d in drop), key=lambda n: int(n.network_address))
    np.savez_compressed(
        OUT / "drop.npz",
        start=np.array([int(n.network_address) for n in drop_nets], dtype=np.uint32),
        end=np.array([int(n.broadcast_address) for n in drop_nets], dtype=np.uint32),
        asn=np.array(sorted(drop_asns), dtype=np.uint32),
    )

    rw = json.loads((raw / "ransomware_recent.json").read_text(encoding="utf-8"))
    rw_country = Counter((r.get("country") or "").upper() for r in rw if r.get("country"))
    malware = Counter(info["malware"] for info in bad.values())
    threats = {
        "malicious_ips": len(bad),
        "malicious_ips_on_hosting": on_hosting,
        "hosting_share_of_malicious_ips": round(on_hosting / max(len(nets), 1), 4),
        "hosting_share_of_internet": round(float(sizes[z["hosting"]].sum() / sizes.sum()), 4),
        "iot_botnet_ips": iot,
        "by_source": Counter(i["source"] for i in bad.values()).most_common(),
        "what": Counter(i["what"] for i in bad.values()).most_common(),
        "top_malware": malware.most_common(15),
        "top_networks": [
            {
                "asn": a,
                "network": names.get(str(a), ""),
                "count": n,
                "hosting": a in hosting_asns,
                "criminal_network": a in drop_asns,
            }
            for a, n in by_network.most_common(15)
        ],
        "top_countries": by_country.most_common(15),
        "threatfox_iocs_48h": len(tf_rows),
        "threatfox_types": Counter(THREAT_TYPES.get(r["threat_type"], r["threat_type"]) for r in tf_rows).most_common(),
        "threatfox_malware": Counter(r["malware_printable"] for r in tf_rows).most_common(15),
        "urlhaus_urls_30d": len(uh_rows),
        "urlhaus_online": uh_online,
        "spamhaus_drop_ranges": len(drop_nets),
        "spamhaus_drop_addresses": sum(n.num_addresses for n in drop_nets),
        "spamhaus_asn_drop": len(asn_drop),
        "spamhaus_asn_drop_countries": Counter(d.get("cc") or "?" for d in asn_drop).most_common(10),
        "ransomware": {
            "victims": len(rw),
            "from": min(r["discovered"] for r in rw)[:10],
            "to": max(r["discovered"] for r in rw)[:10],
            "by_country": rw_country.most_common(12),
            "by_sector": Counter(r.get("activity") or "Not stated" for r in rw).most_common(12),
            "by_group": Counter(r["group"] for r in rw).most_common(12),
        },
    }
    (OUT / "threats.json").write_text(json.dumps(threats, indent=1))
    return threats, by_country, rw_country


def build_cables(raw: Path) -> tuple[dict, Counter]:
    """Submarine internet cables and their landing stations: the physical links between countries."""
    import pycountry

    cables = json.loads((raw / "cable_geo.json").read_text(encoding="utf-8"))
    out = []
    for f in cables["features"]:
        g = f["geometry"]
        lines = g["coordinates"] if g["type"] == "MultiLineString" else [g["coordinates"]]
        out.append(
            {
                "name": f["properties"]["name"],
                "color": f["properties"].get("color") or "#888888",
                "paths": [[[round(lat, 2), round(lon, 2)] for lon, lat in line] for line in lines],
            }
        )
    landings = json.loads((raw / "landing_points.json").read_text(encoding="utf-8"))
    by_name = {c.name: c.alpha_2 for c in pycountry.countries}
    by_name.update({getattr(c, "common_name", c.name): c.alpha_2 for c in pycountry.countries})
    by_name.update(
        {
            "United States": "US",
            "Russia": "RU",
            "South Korea": "KR",
            "Taiwan": "TW",
            "Vietnam": "VN",
            "Iran": "IR",
            "Tanzania": "TZ",
            "Congo, Dem. Rep.": "CD",
            "Congo, Rep.": "CG",
            "Turkey": "TR",
            "Venezuela": "VE",
            "Bolivia": "BO",
            "Syria": "SY",
            "Brunei": "BN",
            "Laos": "LA",
            "Micronesia": "FM",
            "Cape Verde": "CV",
            "Côte d'Ivoire": "CI",
            "Moldova": "MD",
        }
    )
    points, per_country = [], Counter()
    for f in landings["features"]:
        name = f["properties"]["name"]
        cc = by_name.get(name.rsplit(",", 1)[-1].strip(), "")
        lon, lat = f["geometry"]["coordinates"]
        points.append({"name": name, "lat": round(lat, 3), "lng": round(lon, 3), "cc": cc})
        per_country[cc] += 1
    (OUT / "cables.json").write_text(json.dumps({"cables": out, "landings": points}, separators=(",", ":")))
    return {
        "cables": len(out),
        "landing_points": len(points),
        "landings_without_country": per_country.get("", 0),
    }, per_country


def build_states(raw: Path) -> dict:
    """State / province borders, simplified for the globe (needs shapely at build time only)."""
    from shapely.geometry import shape

    data = json.loads((raw / "ne_10m_admin1.geojson").read_text(encoding="utf-8"))
    out = []
    for f in data["features"]:
        p = f["properties"]
        g = shape(f["geometry"]).simplify(0.06, preserve_topology=True)
        polys = [g] if g.geom_type == "Polygon" else list(getattr(g, "geoms", []))
        rings = [
            [[round(lat, 2), round(lon, 2)] for lon, lat in poly.exterior.coords] for poly in polys if not poly.is_empty
        ]
        rings = [r for r in rings if len(r) >= 4]
        if not rings:
            continue
        minx, miny, maxx, maxy = g.bounds
        out.append(
            {
                "n": p.get("name_en") or p["name"],
                "c": p.get("iso_a2") or "",
                "t": p.get("type_en") or "Region",
                "b": [round(miny, 2), round(minx, 2), round(maxy, 2), round(maxx, 2)],
                "r": rings,
            }
        )
    (OUT / "states.json").write_text(json.dumps(out, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
    return {"states_provinces": len(out)}


def _geolocate(raw: Path, ips: set[str]) -> dict[str, tuple[float, float, str, str]]:
    """ip -> (lat, lon, city, state) from DB-IP City Lite, in one pass over its sorted ranges."""
    wanted = []
    for ip in ips:
        try:
            wanted.append((int(ipaddress.IPv4Address(ip)), ip))
        except ValueError:
            continue
    wanted.sort()
    out, k = {}, 0
    with gzip.open(raw / "dbip-city-lite.csv.gz", "rt", encoding="utf-8", errors="replace") as fh:
        for row in csv.reader(fh):
            if k >= len(wanted):
                break
            if ":" in row[0]:
                continue
            start, end = int(ipaddress.IPv4Address(row[0])), int(ipaddress.IPv4Address(row[1]))
            while k < len(wanted) and wanted[k][0] < start:
                k += 1
            while k < len(wanted) and wanted[k][0] <= end:
                out[wanted[k][1]] = (float(row[6]), float(row[7]), row[5], row[4])
                k += 1
    return out


def build_heat(raw: Path) -> dict:
    """City-level hotspots for malware servers and public DNS servers, plus counts per state and per city."""
    import shapely
    from shapely.geometry import Polygon

    bad = json.loads((OUT / "bad_ips.json").read_text())
    with open(raw / "public_dns_nameservers.csv", encoding="utf-8", errors="replace") as fh:
        dns = {
            r["ip_address"]: r["country_code"].upper()
            for r in csv.DictReader(fh)
            if not r.get("error") and "." in r["ip_address"]
        }
    geo = _geolocate(raw, set(bad) | set(dns))

    states = json.loads((OUT / "states.json").read_text(encoding="utf-8"))
    owner, polys = [], []  # one polygon per ring, each mapped back to its state
    for i, st in enumerate(states):
        for r in st["r"]:
            owner.append(i)
            polys.append(shapely.make_valid(Polygon([(lng, lat) for lat, lng in r])))
    tree = shapely.STRtree(polys)

    heat, places = {}, defaultdict(dict)
    for layer, ips, cc_of in (
        ("malware", list(bad), lambda ip: bad[ip].get("country", "")),
        ("dns", list(dns), lambda ip: dns[ip]),
    ):
        located = [ip for ip in ips if ip in geo]
        pts = shapely.points([geo[ip][1] for ip in located], [geo[ip][0] for ip in located])
        hit_pt, hit_state = tree.query(pts, predicate="intersects")
        first: dict[int, int] = {}  # a point on a shared border counts once
        for p_i, s_i in zip(hit_pt.tolist(), hit_state.tolist(), strict=True):
            first.setdefault(p_i, owner[s_i])
        per_state = Counter(first.values())
        for i, s in enumerate(states):
            s[layer[0]] = per_state.get(i, 0)
        spots = Counter((round(geo[ip][0], 1), round(geo[ip][1], 1)) for ip in located)
        heat[layer] = [[lat, lng, n] for (lat, lng), n in spots.items()]
        cities: dict[str, Counter] = defaultdict(Counter)
        for ip in located:
            if geo[ip][2]:
                cities[cc_of(ip)][f"{geo[ip][2]}, {geo[ip][3]}" if geo[ip][3] else geo[ip][2]] += 1
        for cc, counter in cities.items():
            places[cc][layer] = counter.most_common(8)
        heat[f"{layer}_located"] = len(located)
        heat[f"{layer}_total"] = len(ips)

    landings = json.loads((OUT / "cables.json").read_text())["landings"]
    heat["landings"] = [[p["lat"], p["lng"], 1] for p in landings]
    heat["places"] = places
    (OUT / "heat.json").write_text(json.dumps(heat, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
    (OUT / "states.json").write_text(json.dumps(states, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
    return {k: heat[k] for k in ("malware_located", "malware_total", "dns_located", "dns_total")}


def build_countries(
    raw: Path, hosting_ips: Counter, bad_by_country: Counter, rw_by_country: Counter, landings: Counter
) -> dict:
    import pycountry

    tor_exits: Counter = Counter()
    exit_ips: set[str] = set()
    tor_file = raw / "onionoo_exits.json"
    if tor_file.exists():  # torproject.org is blocked on some networks; the API then fetches the list live
        for relay in json.loads(tor_file.read_text(encoding="utf-8"))["relays"]:
            tor_exits[(relay.get("country") or "").upper()] += 1
            exit_ips.update(relay.get("exit_addresses") or [])
    (OUT / "tor_exits.json").write_text(json.dumps(sorted(exit_ips)))

    dns: Counter = Counter()
    with open(raw / "public_dns_nameservers.csv", encoding="utf-8", errors="replace") as fh:
        for row in csv.DictReader(fh):
            if not row.get("error") and row.get("country_code"):
                dns[row["country_code"].upper()] += 1

    ooni = json.loads((raw / "ooni_by_country.json").read_text(encoding="utf-8"))
    censorship = {
        r["probe_cc"]: {
            "measurements": r["measurement_count"],
            "anomalies": r["anomaly_count"],
            "confirmed_blocks": r["confirmed_count"],
        }
        for r in ooni["result"]
        if r.get("probe_cc") and r["probe_cc"] != "ZZ"
    }

    countries = {}
    for c in pycountry.countries:
        a2 = c.alpha_2
        o = censorship.get(a2, {})
        countries[a2] = {
            "name": getattr(c, "common_name", None) or c.name,
            "numeric": c.numeric,
            "tor_exits": tor_exits.get(a2, 0),
            "dns_resolvers": dns.get(a2, 0),
            "hosting_ipv4": hosting_ips.get(a2, 0),
            "censorship_measurements": o.get("measurements", 0),
            "censorship_anomalies": o.get("anomalies", 0),
            "confirmed_blocks": o.get("confirmed_blocks", 0),
            "malicious_ips": bad_by_country.get(a2, 0),
            "ransomware_victims": rw_by_country.get(a2, 0),
            "cable_landings": landings.get(a2, 0),
        }
    (OUT / "countries.json").write_text(json.dumps(countries, separators=(",", ":")))
    return {
        "tor_in_snapshot": tor_file.exists(),
        "tor_exit_relays": sum(tor_exits.values()),
        "tor_exit_ips": len(exit_ips),
        "dns_resolvers": sum(dns.values()),
        "ooni_countries": len(censorship),
        "ooni_measurements": sum(o["measurements"] for o in censorship.values()),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Build the intel snapshot from raw downloads")
    parser.add_argument("--raw", type=Path, default=Path("data/intel"))
    args = parser.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)
    meta = {"fetched_at": (args.raw / "fetched_at.txt").read_text().strip()}
    net, hosting_ips = build_network(args.raw)
    meta["network"] = net
    meta["breaches"] = build_breaches(args.raw)
    meta["flaws"] = build_flaws(args.raw)
    threats, bad_by_country, rw_by_country = build_threats(args.raw)
    meta["threats"] = {
        k: threats[k]
        for k in (
            "malicious_ips",
            "threatfox_iocs_48h",
            "urlhaus_urls_30d",
            "spamhaus_drop_ranges",
            "spamhaus_asn_drop",
        )
    }
    meta["threats_fetched_at"] = (args.raw / "fetched_at_threats.txt").read_text().strip()
    meta["cables"], landings = build_cables(args.raw)
    meta["states"] = build_states(args.raw)
    meta["heat"] = build_heat(args.raw)
    meta["countries"] = build_countries(args.raw, hosting_ips, bad_by_country, rw_by_country, landings)
    meta["window_ooni"] = "last 30 days to fetch date"
    (OUT / "meta.json").write_text(json.dumps(meta, indent=2))
    print(json.dumps(meta, indent=2))


if __name__ == "__main__":
    main()
