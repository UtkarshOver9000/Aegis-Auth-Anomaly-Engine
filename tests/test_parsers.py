"""Snapshot parsers run on small excerpts saved from the real feeds (tests/fixtures/raw)."""

import json
import shutil
from pathlib import Path

import pytest

from ittravel.intel import snapshot

RAW = Path(__file__).parent / "fixtures" / "raw"
DATA = Path(__file__).resolve().parents[1] / "src" / "ittravel" / "intel_data"


@pytest.fixture
def out(tmp_path, monkeypatch):
    for name in ("network.npz", "network_names.json"):  # build_threats looks IPs up in the network table
        shutil.copy(DATA / name, tmp_path / name)
    monkeypatch.setattr(snapshot, "OUT", tmp_path)
    return tmp_path


def test_breaches_parse_and_get_a_method(out):
    meta = snapshot.build_breaches(RAW)
    rows = json.loads((out / "breaches.json").read_text(encoding="utf-8"))
    source = json.loads((RAW / "hibp_breaches.json").read_text(encoding="utf-8"))
    kept = [b for b in source if not b.get("IsSpamList") and not b.get("IsFabricated")]
    assert meta["breaches"] == len(rows) == len(kept)
    assert meta["accounts"] == sum(b["PwnCount"] for b in kept)
    assert all(r["how"] and r["kind"] in ("company", "list") and "<" not in r["summary"] for r in rows)


def test_flaws_parse_newest_first_without_epss(out):
    meta = snapshot.build_flaws(RAW)
    rows = json.loads((out / "flaws.json").read_text())
    assert meta["flaws"] == len(rows) == 40 and meta["epss_scored"] == 0
    assert [r["added"] for r in rows] == sorted((r["added"] for r in rows), reverse=True)
    assert all(r["cve"].startswith("CVE-") for r in rows)


def test_threats_parse_every_source(out):
    threats, by_country = snapshot.build_threats(RAW)
    assert threats["malicious_ips"] == sum(n for _, n in threats["by_source"])
    assert {s for s, _ in threats["by_source"]} <= {"Feodo Tracker", "ThreatFox", "URLhaus"}
    assert threats["spamhaus_drop_ranges"] == 30 and threats["spamhaus_asn_drop"] == 30
    rw = threats["ransomware"]
    assert rw["victims"] == 40 and sum(n for _, n in rw["by_group"]) <= 40 and len(rw["by_group"]) <= 12  # top 12 gangs
    assert [d for d, _ in rw["by_day"]] == sorted(d for d, _ in rw["by_day"])
    assert sum(by_country.values()) <= threats["malicious_ips"]
    saved = json.loads((out / "bad_ips.json").read_text())
    assert len(saved) == threats["malicious_ips"] and all("what" in v and "seen" in v for v in saved.values())
