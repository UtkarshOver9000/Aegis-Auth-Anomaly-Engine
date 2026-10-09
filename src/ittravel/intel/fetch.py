"""
Download every feed listed in sources.yaml into a raw folder.

    python -m ittravel.intel.fetch --raw data/intel [--force] [--only hibp_breaches,cisa_kev]

Per feed: a timeout, retries with exponential backoff, a descriptive User-Agent, and a
conditional GET (ETag / If-Modified-Since) so unchanged files aren't downloaded again.
A feed is skipped while its last success is younger than its cadence (unless --force).
Each download goes to a temporary file and replaces the old copy only when it is complete
and non-empty, so a failed fetch never destroys the last good file.
"""

from __future__ import annotations

import argparse
import gzip
import json
import shutil
import sys
import time
import urllib.error
import urllib.request
from datetime import UTC, datetime, timedelta
from pathlib import Path

import yaml

SOURCES = Path(__file__).resolve().parents[3] / "sources.yaml"
USER_AGENT = "Alibi-threat-intel/4.0 (+https://github.com/UtkarshOver9000/alibi)"
UNITS = {"m": 60, "h": 3600, "d": 86400}
NO_RETRY = {400, 401, 403, 404, 410}


def seconds(span: str) -> int:
    return int(span[:-1]) * UNITS[span[-1]]


def expand(url: str, now: datetime) -> str:
    prev_month = now.replace(day=1) - timedelta(days=1)
    return url.format(
        yyyy_mm=now.strftime("%Y-%m"),
        prev_yyyy_mm=prev_month.strftime("%Y-%m"),
        since=(now - timedelta(days=30)).strftime("%Y-%m-%d"),
        until=now.strftime("%Y-%m-%d"),
    )


def _check_gzip(path: Path) -> None:
    """Read a .gz file to the end; a cut-off archive raises before it can replace a good copy."""
    with gzip.open(path, "rb") as fh:
        while fh.read(1 << 20):
            pass


def download(url: str, dest: Path, state: dict, retries: int = 4, timeout: int = 120, sleep=time.sleep) -> tuple:
    """Return ("updated" | "not modified", new validators). Raises the last error after all retries."""
    headers = {"User-Agent": USER_AGENT}
    if dest.exists():
        if state.get("etag"):
            headers["If-None-Match"] = state["etag"]
        if state.get("last_modified"):
            headers["If-Modified-Since"] = state["last_modified"]
    error: Exception | None = None
    for attempt in range(retries):
        tmp = dest.with_name(dest.name + ".part")
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=timeout) as resp:
                with open(tmp, "wb") as fh:
                    shutil.copyfileobj(resp, fh, 1 << 20)
                size, expected = tmp.stat().st_size, resp.headers.get("Content-Length")
                if size == 0:
                    raise ValueError("empty response")
                if expected and size != int(expected):  # the server closed the connection early
                    raise ValueError(f"truncated download: {size} of {expected} bytes")
                if dest.suffix == ".gz":
                    _check_gzip(tmp)
                tmp.replace(dest)
                return "updated", {"etag": resp.headers.get("ETag"), "last_modified": resp.headers.get("Last-Modified")}
        except urllib.error.HTTPError as e:
            if e.code == 304:
                return "not modified", {}
            error = e
            if e.code in NO_RETRY:
                break
        except Exception as e:  # network errors, resets, timeouts, empty bodies
            error = e
        finally:
            tmp.unlink(missing_ok=True)
        if attempt < retries - 1:
            sleep(min(60, 3 * 2**attempt))
    raise error  # type: ignore[misc]


def run(raw: Path, force: bool = False, only: set[str] | None = None, now: datetime | None = None, **kw) -> dict:
    now = now or datetime.now(UTC)
    raw.mkdir(parents=True, exist_ok=True)
    state_file = raw / "_fetch_state.json"
    states = json.loads(state_file.read_text()) if state_file.exists() else {}
    feeds = yaml.safe_load(SOURCES.read_text(encoding="utf-8"))["feeds"]
    for feed in feeds:
        if only and feed["id"] not in only:
            continue
        st = states.setdefault(feed["id"], {})
        dest = raw / feed["file"]
        last = st.get("last_success")
        if not force and dest.exists() and last:
            if now - datetime.fromisoformat(last) < timedelta(seconds=seconds(feed["cadence"])):
                st["status"] = "fresh, skipped"
                continue
        st["last_attempt"] = now.isoformat()
        urls = [expand(feed["url"], now)] + ([expand(feed["fallback_url"], now)] if feed.get("fallback_url") else [])
        for url in urls:
            try:
                status, validators = download(url, dest, st, **kw)
            except Exception as e:
                st["status"], st["error"] = "failed", f"{type(e).__name__}: {e}"[:300]
                continue
            st.update({k: v for k, v in validators.items() if v})
            st.update(status=status, url=url, last_success=now.isoformat(), bytes=dest.stat().st_size)
            st.pop("error", None)
            break
        if st["status"] == "failed" and feed.get("optional"):
            st["status"] = "unavailable (optional)"
    for feed in feeds:  # how old is each file now?
        st = states.get(feed["id"], {})
        if st.get("last_success"):
            age = now - datetime.fromisoformat(st["last_success"])
            st["age_hours"] = round(age.total_seconds() / 3600, 1)
            st["stale"] = age > timedelta(seconds=seconds(feed["max_age"]))
    state_file.write_text(json.dumps(states, indent=1))
    stamp = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    (raw / "fetched_at.txt").write_text(stamp)
    (raw / "fetched_at_threats.txt").write_text(stamp)
    return states


def main() -> None:
    parser = argparse.ArgumentParser(description="Download every feed in sources.yaml")
    parser.add_argument("--raw", type=Path, default=Path("data/intel"))
    parser.add_argument("--force", action="store_true", help="ignore each feed's cadence")
    parser.add_argument("--only", help="comma-separated feed ids")
    args = parser.parse_args()
    states = run(args.raw, args.force, set(args.only.split(",")) if args.only else None)
    feeds = yaml.safe_load(SOURCES.read_text(encoding="utf-8"))["feeds"]
    missing = []
    for feed in feeds:
        st = states.get(feed["id"], {})
        flag = " STALE" if st.get("stale") else ""
        print(f"{feed['id']:22} {st.get('status', '-'):24} {st.get('age_hours', '-'):>7} h{flag} {st.get('error', '')}")
        if not (args.raw / feed["file"]).exists() and not feed.get("optional"):
            missing.append(feed["id"])
    if missing:  # the snapshot cannot be built without these
        sys.exit(f"missing required feeds: {', '.join(missing)}")


if __name__ == "__main__":
    main()
