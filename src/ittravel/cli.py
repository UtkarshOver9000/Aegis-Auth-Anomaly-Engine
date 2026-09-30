"""
CLI interface for Aegis Impossible-Travel Auth Anomaly Engine.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
import tempfile

from ittravel.ml_engine import engine
from ittravel.schema import LoginEvent
from ittravel.state import store

STATE_FILE = Path(tempfile.gettempdir()) / "aegis_cli_state.json"


def load_persistent_cli_state():
    if not STATE_FILE.exists():
        return
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        for user_id, udata in data.items():
            user = store.get_user(user_id)
            if udata.get("last_ts"):
                user.last_ts = datetime.fromisoformat(udata["last_ts"])
            user.last_lat = udata.get("last_lat")
            user.last_lon = udata.get("last_lon")
            user.last_city = udata.get("last_city")
            user.last_country = udata.get("last_country")
            user.last_device_id = udata.get("last_device_id")
            user.last_ip = udata.get("last_ip")
            user.known_devices = set(udata.get("known_devices", []))
    except Exception:
        pass


def save_persistent_cli_state():
    try:
        data = {}
        for user_id, user in store.users.items():
            data[user_id] = {
                "last_ts": user.last_ts.isoformat() if user.last_ts else None,
                "last_lat": user.last_lat,
                "last_lon": user.last_lon,
                "last_city": user.last_city,
                "last_country": user.last_country,
                "last_device_id": user.last_device_id,
                "last_ip": user.last_ip,
                "known_devices": list(user.known_devices),
            }
        with open(STATE_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f)
    except Exception:
        pass


def main():
    parser = argparse.ArgumentParser(description="Aegis Impossible-Travel Auth Anomaly Engine CLI")
    parser.add_argument("--user", type=str, required=True, help="User ID")
    parser.add_argument("--lat", type=float, required=True, help="Latitude")
    parser.add_argument("--lon", type=float, required=True, help="Longitude")
    parser.add_argument("--city", type=str, default="Unknown", help="City name")
    parser.add_argument("--country", type=str, default="US", help="Country code")
    parser.add_argument("--device", type=str, required=True, help="Device ID")
    parser.add_argument("--ip", type=str, required=True, help="IP Address")
    parser.add_argument("--reset", action="store_true", help="Reset internal state before scoring")

    args = parser.parse_args()

    if args.reset:
        store.users.clear()
        if STATE_FILE.exists():
            STATE_FILE.unlink(missing_ok=True)
    else:
        load_persistent_cli_state()

    event = LoginEvent(
        user_id=args.user,
        login_ts=datetime.now(timezone.utc).isoformat(),
        lat=args.lat,
        lon=args.lon,
        city=args.city,
        country=args.country,
        device_id=args.device,
        ip=args.ip,
    )

    result = engine.evaluate_event(event)
    save_persistent_cli_state()

    print(json.dumps(result.model_dump(), indent=2, default=str))


if __name__ == "__main__":
    main()
