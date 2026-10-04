from fastapi.testclient import TestClient

from ittravel.api.app import app
from ittravel.intel import news, service
from ittravel.intel.network import lookup, malware_ip, sample_ips
from ittravel.intel.snapshot import how_stolen

client = TestClient(app)


def test_network_lookup_knows_owners_and_hosting():
    google = lookup("8.8.8.8")
    assert google.asn == 15169 and google.country == "US"
    droplet = lookup("159.89.1.1")
    assert droplet.network.startswith("DIGITALOCEAN") and droplet.hosting
    assert droplet.label == "hosting / VPN network"
    assert lookup("192.168.1.10").private
    assert lookup("not-an-ip").asn is None


def test_reported_malware_server_is_flagged():
    ip = malware_ip("IN")
    info = lookup(ip)
    assert info.threat and info.label == "known malware server"


def test_sample_ips_come_from_the_right_country():
    for home in sample_ips("IN", hosting=False):
        info = lookup(home["ip"])
        assert info.country == "IN" and not info.hosting
    assert lookup(sample_ips("DE", hosting=True, n=1)[0]["ip"]).hosting


def test_breach_method_is_read_from_the_write_up():
    assert (
        how_stolen({}, "the data was in a MongoDB instance left publicly facing without a password")
        == "Left open online"
    )
    assert how_stolen({}, "a credential stuffing list of email addresses and passwords") == "Credential-stuffing list"
    assert how_stolen({"IsStealerLog": True}, "") == "Info-stealer malware"
    assert how_stolen({}, "In 2020, the company suffered a data breach") == "Hacked, method not disclosed"
    assert how_stolen({}, "") == "Not disclosed"


def test_summaries_add_up():
    b = service.breaches_summary()
    assert b["total_breaches"] > 900 and b["total_accounts"] > 10**10
    assert sum(n for _, n in b["how_stolen"]) + b["lists"]["count"] == b["total_breaches"]
    f = service.flaws_summary()
    assert f["total"] > 1000 and f["added_last_7_days"] <= f["added_last_30_days"] <= f["total"]
    t = service.threats()
    assert t["malicious_ips"] == sum(n for _, n in t["by_source"])
    assert 0 < t["hosting_share_of_malicious_ips"] < 1
    c = service.countries()["countries"]
    assert c["IN"]["name"] == "India" and c["IN"]["cable_landings"] > 0


def test_feed_parser_reads_rss_and_atom():
    rss = b"""<rss><channel><item><title>Patch now</title><link>https://example.org/a</link>
        <pubDate>Fri, 02 Oct 2026 10:00:00 GMT</pubDate></item></channel></rss>"""
    atom = b"""<feed xmlns="http://www.w3.org/2005/Atom"><entry><title>New video</title>
        <link href="https://www.youtube.com/watch?v=abc"/><published>2026-10-03T08:00:00+00:00</published></entry></feed>"""
    (r,) = news.parse_feed(rss, "Blog")
    (a,) = news.parse_feed(atom, "Channel")
    assert r["title"] == "Patch now" and r["published"].startswith("2026-10-02")
    assert a["url"].endswith("v=abc") and a["source"] == "Channel"


def test_intel_endpoints():
    for path in (
        "/v1/intel/overview",
        "/v1/intel/breaches",
        "/v1/intel/flaws",
        "/v1/intel/threats",
        "/v1/intel/countries",
        "/v1/intel/cables",
        "/v1/intel/states",
        "/v1/intel/sources",
    ):
        assert client.get(path).status_code == 200, path
    ips = client.get("/v1/intel/sample-ips", params={"country": "IN"}).json()
    assert len(ips["home"]) == 2 and ips["malware"]
    assert client.get("/v1/intel/ip/8.8.8.8").json()["asn"] == 15169


def _story(final_ip, final_country="IN", minutes=600, lat=19.08, lon=72.88):
    base = {
        "device_id": "laptop",
        "browser": "Chrome 128.0",
        "os": "Windows 10",
        "device_type": "desktop",
        "success": True,
    }
    home = sample_ips("IN", hosting=False, n=1)[0]["ip"]
    events = [
        {
            **base,
            "user_id": "x",
            "login_ts": f"2026-09-{d:02d}T09:00:00Z",
            "ip": home,
            "country": "IN",
            "lat": 19.08,
            "lon": 72.88,
        }
        for d in range(10, 24, 2)
    ]
    hour, minute = divmod(9 * 60 + minutes, 60)
    events.append(
        {
            **base,
            "user_id": "x",
            "login_ts": f"2026-09-22T{hour % 24:02d}:{minute:02d}:00Z",
            "ip": final_ip,
            "country": final_country,
            "lat": lat,
            "lon": lon,
        }
    )
    return client.post("/v1/demo/check", json={"events": events}).json()


def test_demo_story_verdicts():
    assert _story(malware_ip("IN"))["verdict"]["risk_tier"] == "CRITICAL"
    vpn = _story(sample_ips("IN", hosting=True, n=1)[0]["ip"])["verdict"]
    assert vpn["risk_tier"] == "HIGH" and vpn["network"]["hosting"]
    travel = _story(sample_ips("GB", hosting=False, n=1)[0]["ip"], "GB", minutes=10, lat=51.51, lon=-0.13)
    assert travel["verdict"]["risk_tier"] in ("HIGH", "CRITICAL") and travel["verdict"]["velocity_kmph"] > 900
    assert len(travel["timeline"]) == 8
