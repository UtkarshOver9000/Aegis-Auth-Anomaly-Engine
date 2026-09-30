import subprocess
import json
import pytest
import sys
import os

def run_cli(*args):
    cmd = [sys.executable, "-m", "ittravel.cli"] + list(args)
    env = os.environ.copy()
    env["PYTHONPATH"] = "src"
    result = subprocess.run(cmd, capture_output=True, text=True, env=env)
    return result

def test_cli_help():
    res = run_cli("--help")
    assert res.returncode == 0
    assert "Impossible-Travel Auth Anomaly Engine CLI" in res.stdout

def test_cli_missing_args():
    res = run_cli("--user", "u1")
    assert res.returncode != 0
    assert "the following arguments are required" in res.stderr

@pytest.mark.parametrize("i", range(20))
def test_cli_valid_scoring_bulk(i):
    res = run_cli(
        "--user", f"u_bulk_{i}",
        "--lat", str(35.0 + i * 0.1),
        "--lon", str(-120.0 + i * 0.1),
        "--device", f"dev_{i}",
        "--ip", f"192.168.1.{i}"
    )
    assert res.returncode == 0
    data = json.loads(res.stdout)
    assert data["user_id"] == f"u_bulk_{i}"
    assert "risk_score" in data

@pytest.mark.parametrize("i", range(25))
def test_cli_anomaly_bulk(i):
    # First login
    run_cli(
        "--user", f"u_anom_{i}",
        "--lat", "40.7128",
        "--lon", "-74.0060",
        "--device", "dev_1",
        "--ip", "10.0.0.1"
    )
    # Immediate second login from far away
    res = run_cli(
        "--user", f"u_anom_{i}",
        "--lat", "35.6762",
        "--lon", "139.6503",
        "--device", "dev_2",
        "--ip", "172.16.0.1"
    )
    assert res.returncode == 0
    data = json.loads(res.stdout)
    assert data["is_anomaly"] is True
    assert data["risk_tier"] in ["HIGH", "CRITICAL"]

def test_cli_reset():
    res = run_cli(
        "--user", "u_reset",
        "--lat", "10.0",
        "--lon", "20.0",
        "--device", "dev_reset",
        "--ip", "1.1.1.1",
        "--reset"
    )
    assert res.returncode == 0
