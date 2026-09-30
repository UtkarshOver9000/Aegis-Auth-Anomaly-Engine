import pytest
from ittravel.schema import LoginEvent
from ittravel.ml_engine import AIAnomalyEngine
from ittravel.state import StateStore
from datetime import datetime, timezone

def test_engine_initialization():
    engine = AIAnomalyEngine(contamination=0.1)
    assert engine._is_trained is True

def test_first_login_score():
    store = StateStore()
    engine = AIAnomalyEngine(state_store=store)
    event = LoginEvent(
        user_id="user1",
        login_ts="2026-08-01T10:00:00Z",
        lat=40.7128,
        lon=-74.0060,
        city="New York",
        country="US",
        device_id="device1",
        ip="192.168.1.1"
    )
    result = engine.evaluate_event(event)
    assert result.is_anomaly is False
    assert result.risk_score == 5.0
    assert result.risk_tier == "LOW"

@pytest.mark.parametrize("i", range(15))
def test_impossible_travel_bulk(i):
    store = StateStore()
    engine = AIAnomalyEngine(state_store=store)
    # Event 1
    ev1 = LoginEvent(
        user_id=f"usr_{i}",
        login_ts="2026-08-01T10:00:00Z",
        lat=40.7128,
        lon=-74.0060,
        city="New York",
        country="US",
        device_id="device1",
        ip="192.168.1.1"
    )
    engine.evaluate_event(ev1)
    
    # Event 2: 10 minutes later in Tokyo (impossible)
    ev2 = LoginEvent(
        user_id=f"usr_{i}",
        login_ts="2026-08-01T10:10:00Z",
        lat=35.6762,
        lon=139.6503,
        city="Tokyo",
        country="JP",
        device_id="device2",
        ip="10.0.0.1"
    )
    result = engine.evaluate_event(ev2)
    assert result.is_anomaly is True
    assert result.risk_tier in ["HIGH", "CRITICAL"]

