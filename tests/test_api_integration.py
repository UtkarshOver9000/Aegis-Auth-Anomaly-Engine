"""
Integration tests for Aegis ITDR API endpoints.

Tests cover:
- Health endpoint availability
- API key authentication enforcement
- Full evaluation lifecycle (first login, impossible travel, normal commute)
- Audit log retrieval
- Telemetry stats endpoint
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from ittravel.api.app import app

client = TestClient(app)
VALID_KEY = "demo-master-key-9000"
INVALID_KEY = "sk_invalid_badkey"

BASE_EVENT = {
    "user_id": "integration_test_user",
    "login_ts": "2026-09-30T10:00:00Z",
    "lat": 40.7128,
    "lon": -74.0060,
    "city": "New York",
    "country": "US",
    "device_id": "dev-macbook-test",
    "ip": "192.168.1.100"
}

TOKYO_EVENT = {
    "user_id": "integration_test_user",
    "login_ts": "2026-09-30T10:05:00Z",
    "lat": 35.6762,
    "lon": 139.6503,
    "city": "Tokyo",
    "country": "JP",
    "device_id": "dev-ios-unknown",
    "ip": "203.0.113.15"
}


def test_health_endpoint_no_auth():
    res = client.get("/v1/health")
    assert res.status_code == 200
    assert res.json()["status"] == "ok"


def test_evaluate_unauthorized():
    res = client.post("/v1/auth/evaluate", json=BASE_EVENT)
    assert res.status_code == 401


def test_evaluate_invalid_key():
    res = client.post("/v1/auth/evaluate", headers={"X-API-Key": INVALID_KEY}, json=BASE_EVENT)
    assert res.status_code == 403


def test_evaluate_first_login():
    event = {**BASE_EVENT, "user_id": "it_first_login_test"}
    res = client.post("/v1/auth/evaluate", headers={"X-API-Key": VALID_KEY}, json=event)
    assert res.status_code == 200
    data = res.json()
    assert data["is_anomaly"] is False
    assert data["risk_score"] == 5.0
    assert data["risk_tier"] == "LOW"


def test_evaluate_impossible_travel():
    # Set baseline in New York
    event1 = {**BASE_EVENT, "user_id": "it_impossible_test"}
    client.post("/v1/auth/evaluate", headers={"X-API-Key": VALID_KEY}, json=event1)

    # Immediate jump to Tokyo (should be CRITICAL)
    event2 = {**TOKYO_EVENT, "user_id": "it_impossible_test"}
    res = client.post("/v1/auth/evaluate", headers={"X-API-Key": VALID_KEY}, json=event2)
    assert res.status_code == 200
    data = res.json()
    assert data["is_anomaly"] is True
    assert data["risk_tier"] in ["HIGH", "CRITICAL"]
    assert data["velocity_kmph"] > 900


def test_evaluate_response_schema():
    event = {**BASE_EVENT, "user_id": "it_schema_test"}
    res = client.post("/v1/auth/evaluate", headers={"X-API-Key": VALID_KEY}, json=event)
    assert res.status_code == 200
    data = res.json()
    required_fields = [
        "user_id", "is_anomaly", "risk_score", "risk_tier",
        "reasons", "velocity_kmph", "distance_km", "time_delta_hours",
        "current_location", "timestamp"
    ]
    for field in required_fields:
        assert field in data, f"Missing required field: {field}"


def test_anomaly_log_endpoint():
    # Generate some anomaly data first
    event1 = {**BASE_EVENT, "user_id": "it_log_test"}
    client.post("/v1/auth/evaluate", headers={"X-API-Key": VALID_KEY}, json=event1)
    event2 = {**TOKYO_EVENT, "user_id": "it_log_test"}
    client.post("/v1/auth/evaluate", headers={"X-API-Key": VALID_KEY}, json=event2)

    res = client.get("/v1/anomalies", headers={"X-API-Key": VALID_KEY})
    assert res.status_code == 200
    assert isinstance(res.json(), list)


def test_stats_endpoint():
    res = client.get("/v1/stats", headers={"X-API-Key": VALID_KEY})
    assert res.status_code == 200
    stats = res.json()
    assert "active_monitored_users" in stats
    assert "engine_status" in stats
    assert stats["engine_status"] == "ONLINE"


@pytest.mark.parametrize("i", range(5))
def test_evaluate_sequential_normal_sessions(i):
    uid = f"it_normal_session_{i}"
    event1 = {**BASE_EVENT, "user_id": uid}
    res1 = client.post("/v1/auth/evaluate", headers={"X-API-Key": VALID_KEY}, json=event1)
    assert res1.status_code == 200

    # Normal follow-up login nearby (Brooklyn)
    event2 = {
        **event1,
        "login_ts": "2026-09-30T11:00:00Z",
        "lat": 40.6782,
        "lon": -73.9442,
        "city": "Brooklyn",
        "ip": "192.168.1.101"
    }
    res2 = client.post("/v1/auth/evaluate", headers={"X-API-Key": VALID_KEY}, json=event2)
    assert res2.status_code == 200
    assert res2.json()["risk_tier"] in ["LOW", "MEDIUM"]
