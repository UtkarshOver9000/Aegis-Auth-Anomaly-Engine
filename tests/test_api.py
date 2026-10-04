from fastapi.testclient import TestClient

from ittravel.api.app import app
from ittravel.state import DEMO_MASTER_KEY

client = TestClient(app)
KEY = {"X-API-Key": DEMO_MASTER_KEY}
EVENT = {
    "user_id": "api-user",
    "login_ts": "2026-08-03T09:00:00Z",
    "ip": "84.208.20.10",
    "device_id": "dev-laptop",
    "country": "NO",
    "asn": 29695,
}


def test_health_and_dashboard():
    assert client.get("/v1/health").json() == {"status": "ok"}
    assert "Alibi" in client.get("/").text


def test_evaluate_requires_a_key():
    assert client.post("/v1/auth/evaluate", json=EVENT).status_code == 401
    assert client.post("/v1/auth/evaluate", json=EVENT, headers={"X-API-Key": "nope"}).status_code == 403


def test_evaluate_returns_model_scores():
    res = client.post("/v1/auth/evaluate", json=EVENT, headers=KEY)
    assert res.status_code == 200
    data = res.json()
    assert data["risk_tier"] in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
    assert 0 <= data["risk_score"] <= 100
    assert 0 <= data["ato_probability"] <= 1 and 0 <= data["attack_ip_probability"] <= 1
    assert data["recommended_action"]


def test_validation_rejects_bad_input():
    bad = {**EVENT, "rtt_ms": -5}
    assert client.post("/v1/auth/evaluate", json=bad, headers=KEY).status_code == 422


def test_issuing_keys_requires_the_master_key():
    res = client.post("/v1/keys/generate", json={"name": "svc"}, headers=KEY)
    assert res.status_code == 200
    issued = res.json()["api_key"]
    assert issued.startswith("demo_")
    # an issued key can evaluate, but cannot mint more keys
    assert (
        client.post("/v1/auth/evaluate", json={**EVENT, "user_id": "k"}, headers={"X-API-Key": issued}).status_code
        == 200
    )
    assert client.post("/v1/keys/generate", json={"name": "x"}, headers={"X-API-Key": issued}).status_code == 403
    assert client.post("/v1/keys/generate", json={"name": "x"}).status_code == 401


def test_model_card_endpoint():
    card = client.get("/v1/model").json()
    assert set(card["test_metrics"]) == {"ato", "attack_ip"}
    for metrics in card["test_metrics"].values():
        for key in ("roc_auc", "pr_auc", "precision", "recall", "log_loss", "confusion_matrix"):
            assert key in metrics
    assert card["dataset"]["logins"] > 30_000_000


def test_anomaly_log_and_stats():
    client.post("/v1/auth/evaluate", json={**EVENT, "user_id": "t", "lat": 40.71, "lon": -74.0}, headers=KEY)
    client.post(
        "/v1/auth/evaluate",
        json={
            **EVENT,
            "user_id": "t",
            "login_ts": "2026-08-03T09:05:00Z",
            "lat": 35.67,
            "lon": 139.65,
            "country": "JP",
        },
        headers=KEY,
    )
    logs = client.get("/v1/anomalies", headers=KEY).json()
    assert any(a["user_id"] == "t" for a in logs)
    assert client.get("/v1/stats", headers=KEY).json()["users_seen_by_this_instance"] >= 1
