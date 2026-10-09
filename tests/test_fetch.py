import io
import urllib.error
from datetime import UTC, datetime
from pathlib import Path

import pytest

from ittravel.intel import fetch

DBIP_HEAD = (Path(__file__).parent / "fixtures" / "dbip-city-lite-head.csv.gz").read_bytes()


class Resp(io.BytesIO):
    def __init__(self, body: bytes, headers: dict | None = None):
        super().__init__(body)
        self.headers = headers or {}


def http_error(code: int) -> urllib.error.HTTPError:
    return urllib.error.HTTPError("https://example.org", code, "x", {}, None)


def test_url_templates_use_utc_months_and_a_30_day_window():
    url = "a/{yyyy_mm}/{prev_yyyy_mm}/{since}/{until}"
    assert fetch.expand(url, datetime(2026, 3, 15, tzinfo=UTC)) == "a/2026-03/2026-02/2026-02-13/2026-03-15"
    assert fetch.expand(url, datetime(2026, 1, 5, tzinfo=UTC)).startswith("a/2026-01/2025-12/")


def test_download_retries_with_backoff_then_succeeds(tmp_path, monkeypatch):
    calls, sleeps = [], []

    def urlopen(req, timeout):
        calls.append(req.get_header("User-agent"))
        if len(calls) < 3:
            raise ConnectionResetError("reset")
        return Resp(b"data", {"ETag": '"v1"'})

    monkeypatch.setattr(fetch.urllib.request, "urlopen", urlopen)
    status, validators = fetch.download("https://x", tmp_path / "f", {}, sleep=sleeps.append)
    assert status == "updated" and validators["etag"] == '"v1"'
    assert sleeps == [3, 6] and calls[0].startswith("Alibi-threat-intel")
    assert (tmp_path / "f").read_bytes() == b"data"


def test_not_modified_keeps_the_file_and_sends_validators(tmp_path, monkeypatch):
    dest = tmp_path / "f"
    dest.write_bytes(b"old")
    seen = {}

    def urlopen(req, timeout):
        seen.update(req.headers)
        raise http_error(304)

    monkeypatch.setattr(fetch.urllib.request, "urlopen", urlopen)
    assert fetch.download("https://x", dest, {"etag": '"v1"'})[0] == "not modified"
    assert seen["If-none-match"] == '"v1"' and dest.read_bytes() == b"old"


def test_a_failed_or_empty_download_never_replaces_the_last_good_file(tmp_path, monkeypatch):
    dest = tmp_path / "f"
    dest.write_bytes(b"good")
    monkeypatch.setattr(fetch.urllib.request, "urlopen", lambda req, timeout: Resp(b""))
    with pytest.raises(ValueError):
        fetch.download("https://x", dest, {}, retries=2, sleep=lambda s: None)
    monkeypatch.setattr(fetch.urllib.request, "urlopen", lambda req, timeout: (_ for _ in ()).throw(http_error(404)))
    with pytest.raises(urllib.error.HTTPError):
        fetch.download("https://x", dest, {}, sleep=lambda s: None)
    assert dest.read_bytes() == b"good" and not (tmp_path / "f.part").exists()


def test_run_falls_back_to_last_month_and_then_respects_the_cadence(tmp_path, monkeypatch):
    def urlopen(req, timeout):
        if "2026-03" in req.full_url:
            raise http_error(404)  # this month's file isn't published yet
        return Resp(DBIP_HEAD)  # 1,000 real DB-IP rows

    monkeypatch.setattr(fetch.urllib.request, "urlopen", urlopen)
    now = datetime(2026, 3, 2, tzinfo=UTC)
    st = fetch.run(tmp_path, only={"dbip_city"}, now=now, sleep=lambda s: None)["dbip_city"]
    assert st["status"] == "updated" and st["url"].endswith("dbip-city-lite-2026-02.csv.gz")
    again = fetch.run(tmp_path, only={"dbip_city"}, now=now.replace(day=10))["dbip_city"]
    assert again["status"] == "fresh, skipped" and not again["stale"]
    assert (tmp_path / "fetched_at.txt").read_text() == "2026-03-10T00:00:00Z"


def test_a_cut_off_download_is_rejected(tmp_path, monkeypatch):
    import gzip as gz

    dest = tmp_path / "table.tsv.gz"
    dest.write_bytes(gz.compress(b"good"))
    whole = gz.compress(b"x" * 100000)
    monkeypatch.setattr(
        fetch.urllib.request, "urlopen", lambda req, timeout: Resp(whole[:50], {"Content-Length": str(len(whole))})
    )
    with pytest.raises(ValueError, match="truncated"):
        fetch.download("https://x", dest, {}, retries=1)
    monkeypatch.setattr(fetch.urllib.request, "urlopen", lambda req, timeout: Resp(whole[:50]))  # no length header
    with pytest.raises(EOFError):
        fetch.download("https://x", dest, {}, retries=1)
    assert gz.decompress(dest.read_bytes()) == b"good"


def test_every_saved_feed_passes_its_check_and_bad_files_fail(tmp_path):
    from pathlib import Path

    from ittravel.intel import validate

    raw = Path(__file__).resolve().parents[2] / "_data" / "intel"
    checked = 0
    for feed_id, name in (
        ("hibp_breaches", "hibp_breaches.json"),
        ("cisa_kev", "cisa_kev.json"),
        ("threatfox", "threatfox_recent.json"),
        ("urlhaus", "urlhaus_recent.csv"),
        ("spamhaus_asndrop", "spamhaus_asndrop.json"),
        ("cables", "cable_geo.json"),
    ):
        if (raw / name).exists():  # real downloads, when present on this machine
            validate.check(feed_id, raw / name)
            checked += 1
    bad = tmp_path / "x.json"
    bad.write_text('{"vulnerabilities": []}')
    with pytest.raises(validate.InvalidFeed, match="expected at least 1000"):
        validate.check("cisa_kev", bad)
    bad.write_text("<html>maintenance</html>")
    with pytest.raises(validate.InvalidFeed, match="not valid JSON"):
        validate.check("hibp_breaches", bad)


def test_an_invalid_file_is_not_retried_and_keeps_the_old_copy(tmp_path, monkeypatch):
    from ittravel.intel.validate import InvalidFeed

    dest = tmp_path / "cisa_kev.json"
    dest.write_text("good")
    calls = []
    monkeypatch.setattr(fetch.urllib.request, "urlopen", lambda req, timeout: calls.append(1) or Resp(b"<html>"))

    def strict(path):
        raise InvalidFeed("bad")

    with pytest.raises(InvalidFeed):
        fetch.download("https://x", dest, {}, validate=strict)
    assert calls == [1] and dest.read_text() == "good"
