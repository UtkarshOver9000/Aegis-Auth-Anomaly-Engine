"""
Score a sequence of login events from a JSON Lines file, in order.

    python -m ittravel.cli events.jsonl

Each line is one LoginEvent (see schema.py). Events are scored in file order,
so earlier lines become each user's history for later ones.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .engine import RiskEngine
from .schema import LoginEvent
from .state import StateStore


def score_file(path: Path) -> list[dict]:
    engine = RiskEngine(state_store=StateStore())
    out = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        if line.strip():
            out.append(engine.evaluate_event(LoginEvent.model_validate_json(line)).model_dump())
    return out


def main() -> None:
    parser = argparse.ArgumentParser(description="Score login events from a JSON Lines file")
    parser.add_argument("events", type=Path)
    args = parser.parse_args()
    for result in score_file(args.events):
        print(json.dumps({k: result[k] for k in ("user_id", "timestamp", "risk_tier", "risk_score", "reasons")}))


if __name__ == "__main__":
    main()
