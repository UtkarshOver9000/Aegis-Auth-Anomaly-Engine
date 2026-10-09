"""
Alibi's internal data model, aligned with STIX 2.1 (OASIS).

Every finding maps to a STIX object so it can be exported, shared or loaded into tools such as
OpenCTI and MISP:

| Alibi thing                          | STIX 2.1 object                                    |
|--------------------------------------|----------------------------------------------------|
| an IP, domain or URL                 | ipv4-addr / domain-name / url (observable, SCO)    |
| a network (ASN)                      | autonomous-system (SCO)                            |
| "this IP is a malware server"        | indicator, with a STIX pattern                     |
| a malware family (Mozi, Cobalt ...)  | malware (is_family = true)                         |
| a ransomware gang                    | threat-actor                                       |
| a named wave of activity             | campaign                                           |
| an exploited flaw (CVE)              | vulnerability                                      |
| "indicates", "uses", "targets"       | relationship                                       |
| "a feed reported it again"           | sighting                                           |

Each domain object carries first_seen / last_seen where STIX defines them, a confidence (0-100)
and the source it came from (created_by_ref + external_references). IDs are deterministic
(UUIDv5), so the same IP or CVE always gets the same id.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

SPEC = "2.1"
# STIX 2.1 namespace for deterministic observable ids (spec section 2.9)
SCO_NAMESPACE = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")
ALIBI_NAMESPACE = uuid.uuid5(uuid.NAMESPACE_URL, "https://github.com/UtkarshOver9000/alibi")
ALIBI_IDENTITY = f"identity--{uuid.uuid5(ALIBI_NAMESPACE, 'alibi')}"
TYPES = (
    "indicator",
    "ipv4-addr",
    "domain-name",
    "url",
    "autonomous-system",
    "malware",
    "threat-actor",
    "campaign",
    "vulnerability",
    "relationship",
    "sighting",
    "identity",
)


def _ts(value: str | datetime | None = None) -> str:
    if value is None:
        value = datetime.now(UTC)
    if isinstance(value, str):
        value = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if value.tzinfo is None:
            value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _id(kind: str, *key: object) -> str:
    ns = SCO_NAMESPACE if kind in ("ipv4-addr", "domain-name", "url", "autonomous-system") else ALIBI_NAMESPACE
    return f"{kind}--{uuid.uuid5(ns, '|'.join(map(str, key)))}"


def _sdo(kind: str, key: tuple, *, created: str | None, confidence: int, source: dict | None, **props) -> dict:
    stamp = _ts(created)
    obj = {
        "type": kind,
        "spec_version": SPEC,
        "id": _id(kind, *key),
        "created": stamp,
        "modified": stamp,
        "created_by_ref": ALIBI_IDENTITY,
        "confidence": confidence,
        **{k: v for k, v in props.items() if v is not None},
    }
    if source:
        obj["external_references"] = [source]
    return obj


def identity() -> dict:
    return {
        "type": "identity",
        "spec_version": SPEC,
        "id": ALIBI_IDENTITY,
        "created": "2026-10-04T00:00:00.000Z",
        "modified": "2026-10-04T00:00:00.000Z",
        "name": "Alibi",
        "identity_class": "system",
    }


def source_ref(name: str, url: str | None = None, external_id: str | None = None) -> dict:
    return {k: v for k, v in {"source_name": name, "url": url, "external_id": external_id}.items() if v}


# observables (SCOs) ---------------------------------------------------------------------------
def autonomous_system(asn: int, name: str | None = None) -> dict:
    obj = {"type": "autonomous-system", "spec_version": SPEC, "id": _id("autonomous-system", asn), "number": asn}
    return {**obj, "name": name} if name else obj


def ipv4(value: str, asn: int | None = None) -> dict:
    obj = {"type": "ipv4-addr", "spec_version": SPEC, "id": _id("ipv4-addr", value), "value": value}
    return {**obj, "belongs_to_refs": [_id("autonomous-system", asn)]} if asn else obj


# domain objects (SDOs) -------------------------------------------------------------------------
def indicator(
    pattern: str,
    name: str,
    *,
    first_seen: str,
    last_seen: str | None = None,
    confidence: int = 50,
    source: dict | None = None,
    indicator_types: list[str] | None = None,
) -> dict:
    return _sdo(
        "indicator",
        (pattern,),
        created=first_seen,
        confidence=confidence,
        source=source,
        name=name,
        pattern=pattern,
        pattern_type="stix",
        valid_from=_ts(first_seen),
        valid_until=None,
        indicator_types=indicator_types or ["malicious-activity"],
        x_alibi_last_seen=_ts(last_seen) if last_seen else None,
    )


def malware(name: str, *, first_seen: str | None = None, confidence: int = 70, source: dict | None = None) -> dict:
    return _sdo(
        "malware",
        (name.lower(),),
        created=first_seen,
        confidence=confidence,
        source=source,
        name=name,
        is_family=True,
        first_seen=_ts(first_seen) if first_seen else None,
    )


def threat_actor(name: str, *, first_seen: str | None = None, confidence: int = 70, source: dict | None = None) -> dict:
    return _sdo(
        "threat-actor",
        (name.lower(),),
        created=first_seen,
        confidence=confidence,
        source=source,
        name=name,
        threat_actor_types=["crime-syndicate"],
        first_seen=_ts(first_seen) if first_seen else None,
    )


def campaign(
    name: str, *, first_seen: str, last_seen: str | None = None, confidence: int = 50, source: dict | None = None
) -> dict:
    return _sdo(
        "campaign",
        (name.lower(),),
        created=first_seen,
        confidence=confidence,
        source=source,
        name=name,
        first_seen=_ts(first_seen),
        last_seen=_ts(last_seen) if last_seen else None,
    )


def vulnerability(cve: str, name: str, *, added: str, confidence: int = 100) -> dict:
    ref = source_ref("cve", f"https://nvd.nist.gov/vuln/detail/{cve}", cve)
    return _sdo("vulnerability", (cve,), created=added, confidence=confidence, source=ref, name=cve, description=name)


def relationship(
    source_id: str, kind: str, target_id: str, *, created: str | None = None, confidence: int = 50
) -> dict:
    return _sdo(
        "relationship",
        (source_id, kind, target_id),
        created=created,
        confidence=confidence,
        source=None,
        relationship_type=kind,
        source_ref=source_id,
        target_ref=target_id,
    )


def sighting(
    of_id: str,
    *,
    first_seen: str,
    last_seen: str | None = None,
    count: int = 1,
    where: str | None = None,
    confidence: int = 50,
) -> dict:
    return _sdo(
        "sighting",
        (of_id, first_seen, where or ""),
        created=first_seen,
        confidence=confidence,
        source=source_ref(where) if where else None,
        sighting_of_ref=of_id,
        first_seen=_ts(first_seen),
        last_seen=_ts(last_seen or first_seen),
        count=count,
    )


def bundle(objects: list[dict]) -> dict:
    seen, unique = set(), []
    for o in [identity(), *objects]:
        if o["id"] not in seen:
            seen.add(o["id"])
            unique.append(o)
    return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": unique}


# Alibi findings -> STIX -------------------------------------------------------------------------
FEED_URLS = {
    "Feodo Tracker": "https://feodotracker.abuse.ch",
    "ThreatFox": "https://threatfox.abuse.ch",
    "URLhaus": "https://urlhaus.abuse.ch",
}
# how much a single report from each feed is trusted (0-100)
FEED_CONFIDENCE = {"Feodo Tracker": 85, "ThreatFox": 70, "URLhaus": 75}


def malware_server(ip: str, report: dict) -> list[dict]:
    """A snapshot bad_ips.json entry -> observable, indicator, malware family, sighting and relationships."""
    src = source_ref(f"abuse.ch {report['source']}", FEED_URLS.get(report["source"]))
    conf = FEED_CONFIDENCE.get(report["source"], 50)
    objs = [ipv4(ip, report.get("asn"))]
    if report.get("asn"):
        objs.append(autonomous_system(report["asn"], report.get("network")))
    ind = indicator(
        f"[ipv4-addr:value = '{ip}']", f"{report['what']}: {ip}", first_seen=report["seen"], confidence=conf, source=src
    )
    objs += [
        ind,
        relationship(ind["id"], "based-on", objs[0]["id"], created=report["seen"], confidence=conf),
        sighting(ind["id"], first_seen=report["seen"], where=f"abuse.ch {report['source']}", confidence=conf),
    ]
    family = report.get("malware")
    if family and family.lower() not in ("unnamed", "unknown", "unknown malware", "none"):
        mal = malware(family, source=src)
        objs += [mal, relationship(ind["id"], "indicates", mal["id"], created=report["seen"], confidence=conf)]
    return objs


def exploited_flaw(flaw: dict) -> list[dict]:
    """A snapshot flaws.json entry (CISA KEV) -> vulnerability."""
    return [vulnerability(flaw["cve"], flaw["name"], added=flaw["added"])]


def ransomware_gang(name: str, victims_this_week: int, first: str, last: str) -> list[dict]:
    """Aggregate only: the gang and a campaign for this week's activity, never victim names."""
    src = source_ref("ransomware.live", "https://www.ransomware.live")
    actor = threat_actor(name, source=src)
    camp = campaign(f"{name} leak-site posts {first} to {last}", first_seen=first, last_seen=last, source=src)
    camp["x_alibi_victims"] = victims_this_week
    return [actor, camp, relationship(camp["id"], "attributed-to", actor["id"], created=first, confidence=60)]
