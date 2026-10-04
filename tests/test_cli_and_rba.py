import json

import duckdb
import pandas as pd
import pytest

from ittravel.cli import score_file
from ittravel.rba.features import FEATURE_COLUMNS, build_features
from ittravel.rba.train import evaluate, score_quantiles, threshold_for_budget


def test_cli_scores_events_in_order(tmp_path):
    events = [
        {"user_id": "c", "login_ts": "2026-08-01T09:00:00Z", "ip": "84.208.20.10", "device_id": "d1", "country": "NO"},
        {"user_id": "c", "login_ts": "2026-08-01T09:10:00Z", "ip": "185.220.101.7", "device_id": "d2", "country": "RU"},
    ]
    path = tmp_path / "events.jsonl"
    path.write_text("\n".join(json.dumps(e) for e in events))
    out = score_file(path)
    assert len(out) == 2
    assert out[1]["features"]["country_hop_1h"] == 1


def test_feature_sql_uses_only_earlier_logins():
    con = duckdb.connect()
    rows = pd.DataFrame(
        {
            "ts": pd.to_datetime(["2020-03-01 10:00", "2020-03-01 10:20", "2020-03-02 09:00", "2020-03-01 10:30"]),
            "user_id": [1, 1, 1, 2],
            "rtt_ms": [500.0, None, 600.0, 300.0],
            "ip": ["a", "b", "b", "b"],
            "country": ["NO", "SE", "SE", "NO"],
            "asn": [1, 2, 2, 2],
            "ua": ["x", "y", "y", "z"],
            "browser": ["c", "c", "c", "c"],
            "os": ["w", "w", "w", "w"],
            "device": ["desktop", "desktop", "desktop", "mobile"],
            "success": [True, False, True, True],
            "attack_ip": [False, False, False, False],
            "ato": [False, True, False, False],
        }
    )
    con.register("rows", rows)
    con.execute("CREATE TABLE logins AS SELECT * FROM rows")
    assert build_features(con) == 4
    f = con.execute("SELECT * FROM features ORDER BY user_id, ts").fetchdf()
    first, hop, later = f.iloc[0], f.iloc[1], f.iloc[2]
    assert first["new_country"] == 0 and first["log_prior_logins"] == 0
    assert hop["new_country"] == 1 and hop["country_hop_1h"] == 1 and hop["new_asn"] == 1 and hop["success"] == 0
    assert later["new_country"] == 0 and later["prev_failed"] == 1 and later["fails_prev10"] == 1
    other = f.iloc[3]
    assert other["ip_attempts_1h"] == 1 and other["ip_failures_1h"] == 1  # user 1's failed 10:20 attempt from IP "b"
    assert set(FEATURE_COLUMNS) <= set(f.columns)


def test_threshold_for_budget_and_quantiles():
    proba = pd.Series([0.9, 0.5, 0.1, 0.05, 0.01]).to_numpy()
    weights = pd.Series([1, 1, 1, 1, 1], dtype=float).to_numpy()
    assert threshold_for_budget(proba, weights, 0.2) == 0.9  # flags exactly the top 20%
    q = score_quantiles(proba, weights, levels=4)
    assert q["levels"][0] == 0 and q["levels"][-1] == 1
    assert q["values"] == sorted(q["values"])


def test_evaluate_reports_alert_metrics():
    y = pd.Series([1, 0, 0, 0, 1]).to_numpy()
    p = pd.Series([0.9, 0.8, 0.1, 0.1, 0.2]).to_numpy()
    m = evaluate(y, p, threshold=0.5)
    assert m["confusion_matrix"] == {"tn": 2, "fp": 1, "fn": 1, "tp": 1}
    assert m["alert_rate"] == 0.4 and m["alerts_per_10k_logins"] == 4000.0
    assert m["recall"] == 0.5 and m["precision"] == 0.5
    assert m["roc_auc"] == pytest.approx(5 / 6, abs=1e-4)
