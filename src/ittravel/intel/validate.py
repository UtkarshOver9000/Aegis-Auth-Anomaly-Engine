"""
Format and sanity checks for every downloaded feed, run before a download may replace the last good copy.

Each check reads the new file, confirms the fields the snapshot builder relies on are there, and that the
record count is plausible (a feed that suddenly shrinks to a handful of rows is broken, not quiet).
"""

from __future__ import annotations

import csv
import gzip
import io
import json
from pathlib import Path


class InvalidFeed(ValueError):
    """The file downloaded completely but is not what the parser expects."""


def _need(cond: bool, why: str) -> None:
    if not cond:
        raise InvalidFeed(why)


def _json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise InvalidFeed(f"not valid JSON: {e}") from e


def _rows_of(items: list, key: str, minimum: int, what: str) -> None:
    _need(isinstance(items, list), f"{what}: expected a list")
    _need(len(items) >= minimum, f"{what}: only {len(items)} records, expected at least {minimum}")
    _need(all(isinstance(i, dict) and key in i for i in items[:50]), f"{what}: records lack '{key}'")


def _features(path: Path, minimum: int) -> None:
    data = _json(path)
    _need(data.get("type") == "FeatureCollection", "not a GeoJSON FeatureCollection")
    _rows_of(data.get("features"), "geometry", minimum, "features")


def _jsonl(path: Path, key: str, minimum: int) -> None:
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.startswith("{")]
    _rows_of([r for r in rows if key in r], key, minimum, "lines")


def _csv_header(path: Path, needed: set[str], minimum: int) -> None:
    with open(path, encoding="utf-8", errors="replace", newline="") as fh:
        reader = csv.DictReader(fh)
        _need(needed <= set(reader.fieldnames or []), f"CSV header lacks {needed - set(reader.fieldnames or [])}")
        count = sum(1 for _ in reader)
    _need(count >= minimum, f"only {count} rows, expected at least {minimum}")


def _gz_lines(path: Path, sep: str, fields: int, sample: int = 1000) -> None:
    with gzip.open(path, "rt", encoding="utf-8", errors="replace") as fh:
        head = [line for _, line in zip(range(sample), fh, strict=False)]
    _need(len(head) == sample, "file has too few lines")
    rows = list(csv.reader(io.StringIO("".join(head)), delimiter=sep))
    _need(all(len(r) >= fields for r in rows), f"rows should have {fields} fields")


def _urlhaus(path: Path) -> None:
    lines = [
        ln for ln in path.read_text(encoding="utf-8", errors="replace").splitlines() if ln and not ln.startswith("#")
    ]
    rows = list(csv.reader(lines))
    _need(len(rows) >= 100, f"only {len(rows)} URLs")
    _need(all(len(r) >= 8 and r[2].startswith("http") for r in rows[:50]), "rows do not look like URLhaus entries")


def _epss(path: Path) -> None:
    with gzip.open(path, "rt", encoding="utf-8") as fh:
        head = [next(fh, "") for _ in range(3)]
    _need(head[0].startswith("#model_version"), "missing the EPSS model line")
    _need(head[1].strip() == "cve,epss,percentile", "unexpected EPSS header")
    _need(head[2].startswith("CVE-"), "no scores")


CHECKS = {
    "epss": _epss,
    "hibp_breaches": lambda p: _rows_of(_json(p), "PwnCount", 500, "breaches"),
    "cisa_kev": lambda p: _rows_of(_json(p).get("vulnerabilities"), "cveID", 1000, "vulnerabilities"),
    "iptoasn": lambda p: _gz_lines(p, "\t", 5),
    "public_dns": lambda p: _csv_header(p, {"ip_address", "country_code", "error"}, 10_000),
    "ooni": lambda p: _rows_of(_json(p).get("result"), "probe_cc", 50, "countries"),
    "feodo": lambda p: _rows_of(_json(p), "ip_address", 0, "C2 servers"),
    "urlhaus": _urlhaus,
    "threatfox": lambda p: _rows_of([r for g in _json(p).values() for r in g], "ioc_value", 100, "indicators"),
    "spamhaus_drop": lambda p: _jsonl(p, "cidr", 100),
    "spamhaus_asndrop": lambda p: _jsonl(p, "asn", 50),
    "ransomlook": lambda p: _rows_of(_json(p), "group_name", 10, "posts"),
    "cables": lambda p: _features(p, 300),
    "cable_landings": lambda p: _features(p, 1000),
    "dbip_city": lambda p: _gz_lines(p, ",", 8),
    "natural_earth_admin1": lambda p: _features(p, 4000),
    "tor_onionoo": lambda p: _rows_of(_json(p).get("relays"), "exit_addresses", 100, "relays"),
}


def check(feed_id: str, path: Path) -> None:
    """Raise InvalidFeed if the file at `path` is not a usable copy of this feed."""
    if feed_id in CHECKS:
        CHECKS[feed_id](path)
