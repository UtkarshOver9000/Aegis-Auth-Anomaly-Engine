"""
Live security news and videos from public RSS/Atom feeds (no API keys).
Only headlines, dates and links are shown; every item links to its source.
"""

from __future__ import annotations

import time
import urllib.request
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from email.utils import parsedate_to_datetime

NEWS_FEEDS = {
    "The Hacker News": "https://feeds.feedburner.com/TheHackersNews",
    "BleepingComputer": "https://www.bleepingcomputer.com/feed/",
    "Krebs on Security": "https://krebsonsecurity.com/feed/",
    "CISA advisories": "https://www.cisa.gov/cybersecurity-advisories/all.xml",
}
YT = "https://www.youtube.com/feeds/videos.xml?channel_id="
VIDEO_FEEDS = {
    "John Hammond": YT + "UCVeW9qkBjo3zosnqUbG7CFw",
    "NetworkChuck": YT + "UC9x0AN7BWHpCDHSm9NiJFJQ",
    "Marcus Hutchins": YT + "UCLDnEn-TxejaDB8qm2AUhHQ",
    "Hak5": YT + "UC3s0BtrBJpwNDaflRSoiieQ",
}
CACHE_SECONDS = 1800
_cache: dict[str, tuple[float, list]] = {}
ATOM = "{http://www.w3.org/2005/Atom}"


def _date(text: str | None) -> str | None:
    if not text:
        return None
    try:
        return parsedate_to_datetime(text).isoformat()
    except (TypeError, ValueError):
        try:
            return datetime.fromisoformat(text.replace("Z", "+00:00")).isoformat()
        except ValueError:
            return None


def parse_feed(xml_bytes: bytes, source: str, limit: int = 12) -> list[dict]:
    root = ET.fromstring(xml_bytes)
    items = []
    for item in root.iter("item"):  # RSS 2.0
        items.append(
            {
                "source": source,
                "title": (item.findtext("title") or "").strip(),
                "url": (item.findtext("link") or "").strip(),
                "published": _date(item.findtext("pubDate")),
            }
        )
    for entry in root.iter(f"{ATOM}entry"):  # Atom (YouTube, some blogs)
        link = entry.find(f"{ATOM}link")
        items.append(
            {
                "source": source,
                "title": (entry.findtext(f"{ATOM}title") or "").strip(),
                "url": link.get("href") if link is not None else "",
                "published": _date(entry.findtext(f"{ATOM}published") or entry.findtext(f"{ATOM}updated")),
            }
        )
    return [i for i in items if i["title"] and i["url"].startswith("http")][:limit]


_last_good: dict[str, list[dict]] = {}  # feed url -> its last non-empty result


def _fetch(source: str, url: str) -> list[dict]:
    req = urllib.request.Request(url, headers={"User-Agent": "Alibi-security-dashboard/1.0 (+github.com)"})
    try:
        with urllib.request.urlopen(req, timeout=12) as resp:
            items = parse_feed(resp.read(), source)
    except Exception:  # one broken feed must not take the page down
        items = []
    if items:
        _last_good[url] = items
    return items or _last_good.get(url, [])  # a failed refresh serves the previous copy


def latest(feeds: dict[str, str], key: str) -> list[dict]:
    now = time.time()
    hit = _cache.get(key)
    if hit and now - hit[0] < CACHE_SECONDS:
        return hit[1]
    with ThreadPoolExecutor(max_workers=len(feeds) or 1) as pool:
        results = pool.map(lambda kv: _fetch(*kv), feeds.items())
    items = [i for group in results for i in group]
    items.sort(key=lambda i: i["published"] or "", reverse=True)
    _cache[key] = (now, items)
    return items
