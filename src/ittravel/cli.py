import argparse
import json
import sys
from datetime import datetime, timezone
from ittravel.schema import AuthEvent
from ittravel.api.auth import get_engine
from ittravel.state import reset_state

def main():
    parser = argparse.ArgumentParser(description="Impossible-Travel Auth Anomaly Engine CLI")
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
        reset_state()

    event = AuthEvent(
        user_id=args.user,
        login_ts=datetime.now(timezone.utc),
        lat=args.lat,
        lon=args.lon,
        city=args.city,
        country=args.country,
        device_id=args.device,
        ip=args.ip
    )

    engine = get_engine()
    result = engine.score(event)
    print(json.dumps(result.model_dump(), indent=2, default=str))

if __name__ == "__main__":
    main()
