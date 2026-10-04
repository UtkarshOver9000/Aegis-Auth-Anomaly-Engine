"""Engine tests against the committed model artifacts (trained on the RBA dataset)."""

from datetime import datetime, timedelta, timezone

import pytest

from ittravel.engine import RiskEngine, tier_for
from ittravel.rba.features import FEATURE_COLUMNS
from ittravel.schema import LoginEvent
from ittravel.state import StateStore

T0 = datetime(2026, 8, 3, 9, 0, tzinfo=timezone.utc)
HOME = dict(
    ip="84.208.20.10",
    device_id="dev-laptop",
    country="NO",
    asn=29695,
    browser="Chrome 120.0",
    os="Windows 10",
    device_type="desktop",
    rtt_ms=420,
)


def login(user="u1", minutes=0.0, **overrides) -> LoginEvent:
    fields = {**HOME, **overrides}
    return LoginEvent(user_id=user, login_ts=(T0 + timedelta(minutes=minutes)).isoformat(), **fields)


@pytest.fixture()
def engine():
    return RiskEngine(state_store=StateStore())


def history(engine, user="u1", days=5):
    for d in range(days, 0, -1):
        engine.evaluate_event(login(user, minutes=-d * 1440))


def test_features_match_training_columns(engine):
    feats = engine.features(engine.store.get_user("x"), login("x"), T0)
    assert list(feats) == FEATURE_COLUMNS


def test_first_login_has_no_novelty_flags(engine):
    r = engine.evaluate_event(login())
    assert all(r.features[k] == 0 for k in ("new_country", "new_asn", "new_ip", "new_ua", "country_hop_1h"))
    assert r.features["log_prior_logins"] == 0
    assert r.previous_location is None


def test_novelty_features_track_user_history(engine):
    history(engine)
    usual = engine.evaluate_event(login(minutes=0))
    assert usual.features["new_country"] == 0 and usual.features["new_asn"] == 0
    hop = engine.evaluate_event(login(minutes=10, country="RU", asn=9009, ip="185.220.101.7", device_id="dev-x"))
    assert hop.features["new_country"] == 1 and hop.features["new_asn"] == 1 and hop.features["new_ua"] == 1
    assert hop.features["country_hop_1h"] == 1
    assert any("Country changed within an hour" in r for r in hop.reasons)


def test_risky_login_outranks_usual_login(engine):
    history(engine, "a")
    history(engine, "b")
    usual = engine.evaluate_event(login("a", minutes=0))
    risky = engine.evaluate_event(
        login(
            "b",
            minutes=0,
            country="RU",
            asn=9009,
            ip="185.220.101.7",
            device_id="dev-x",
            browser="Chrome Mobile 96.0",
            os="Android 10",
            device_type="mobile",
        )
    )
    assert risky.ato_probability > usual.ato_probability
    assert risky.risk_score >= usual.risk_score


def test_failed_attempts_and_ip_bursts_are_counted(engine):
    history(engine)
    for i in range(4):
        engine.evaluate_event(login(minutes=i, success=False))
    for i in range(12):
        engine.evaluate_event(login(f"other{i}", minutes=5 + i * 0.1, ip="203.0.113.9", success=False))
    r = engine.evaluate_event(login(minutes=10, ip="203.0.113.9"))
    assert r.features["fails_prev10"] == 4
    assert r.features["prev_failed"] == 1
    assert r.features["ip_attempts_1h"] == 12 and r.features["ip_failures_1h"] == 12


def test_impossible_travel_forces_at_least_high(engine):
    engine.evaluate_event(login(minutes=0, lat=40.7128, lon=-74.0060, country="US"))
    r = engine.evaluate_event(login(minutes=5, lat=35.6762, lon=139.6503, country="JP"))
    assert r.velocity_kmph > 100_000
    assert r.risk_tier in {"HIGH", "CRITICAL"} and r.is_anomaly
    assert r.reasons[0].startswith("Impossible travel")


def test_weekday_matches_duckdb_convention(engine):
    sunday = datetime(2026, 8, 2, 12, tzinfo=timezone.utc)
    feats = engine.features(engine.store.get_user("w"), login("w"), sunday)
    assert feats["weekday"] == 0


@pytest.mark.parametrize("pct, tier", [(10, "LOW"), (90, "MEDIUM"), (99.2, "HIGH"), (99.95, "CRITICAL")])
def test_tiers(pct, tier):
    assert tier_for(pct) == tier


def test_percentiles_are_monotonic(engine):
    lo = engine._percentile("ato", 1e-9)
    hi = engine._percentile("ato", 0.5)
    assert 0 <= lo <= hi <= 100
