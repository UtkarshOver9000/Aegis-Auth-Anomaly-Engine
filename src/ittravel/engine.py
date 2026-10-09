"""
Live login-risk engine.

For each login it updates the user's history, computes exactly the features the
models were trained on (see ``rba/features.py``), and scores them with the two
gradient-boosting models trained on the RBA login dataset:

* account-takeover model (``ato``)
* attack-IP model (``attack_ip``)

Each score is turned into a percentile of real validation-period logins, so
"99.5" means the login looks riskier than 99.5% of logins the model was
validated on. When coordinates are supplied, the physical impossible-travel
check (great-circle distance / time > 900 km/h) is applied on top.
"""

from __future__ import annotations

import json
import math
from collections import deque
from datetime import UTC, datetime
from pathlib import Path

import joblib
import numpy as np

from . import settings
from .geo import haversine_km
from .intel.network import lookup
from .rba.features import FEATURE_COLUMNS
from .schema import EvaluationResult, LoginEvent
from .state import StateStore, UserState, store

ARTIFACT_DIR = Path(__file__).resolve().parent / "artifacts"
TIERS = ((99.9, "CRITICAL"), (99.0, "HIGH"), (90.0, "MEDIUM"))
ACTIONS = {
    "LOW": "let them in",
    "MEDIUM": "let them in and log it for review",
    "HIGH": "ask for a one-time code",
    "CRITICAL": "block and alert the owner",
}
GUESSING_FAILS = 5  # wrong passwords in the user's last 10 attempts that count as someone guessing
TIER_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


def _velocity_threshold() -> float:
    return settings.velocity_threshold_kmh()


def tier_for(percentile: float) -> str:
    for cutoff, tier in TIERS:
        if percentile >= cutoff:
            return tier
    return "LOW"


class RiskEngine:
    def __init__(self, state_store: StateStore | None = None, artifact_dir: Path = ARTIFACT_DIR):
        self.store = state_store if state_store is not None else store
        models, card = artifact_dir / "rba_models.joblib", artifact_dir / "rba_model_card.json"
        # Without the model files the engine still answers, from the network and travel rules alone.
        self.models = joblib.load(models) if models.exists() else None
        self.card = json.loads(card.read_text()) if card.exists() and self.models is not None else {}
        self.ip_history: dict[str, deque] = {}

    # --- features -------------------------------------------------------
    def _ip_window(self, ip: str, now: datetime) -> tuple[int, int]:
        window = self.ip_history.setdefault(ip, deque())
        while window and (now - window[0][0]).total_seconds() > 3600:
            window.popleft()
        return len(window), sum(1 for _, ok in window if not ok)

    def features(self, user: UserState, event: LoginEvent, now: datetime) -> dict:
        n_prior = user.login_count
        secs = (now - user.last_ts).total_seconds() if user.last_ts else None
        ua = event.user_agent or event.device_id

        def is_new(value, seen: set) -> int:
            return int(n_prior > 0 and value not in seen)

        ip_attempts, ip_failures = self._ip_window(event.ip, now)
        return {
            "log_prior_logins": math.log1p(n_prior),
            "log_secs_since_prev": math.log1p(max(secs, 0.0) if secs is not None else 1e8),
            "new_country": is_new(event.country, user.seen["country"]),
            "new_asn": is_new(event.asn, user.seen["asn"]),
            "new_ip": is_new(event.ip, user.seen["ip"]),
            "new_ua": is_new(ua, user.seen["ua"]),
            "new_browser": is_new(event.browser, user.seen["browser"]),
            "new_os": is_new(event.os, user.seen["os"]),
            "new_device": is_new(event.device_type, user.seen["device"]),
            "country_hop_1h": int(
                user.last_country is not None
                and event.country != user.last_country
                and secs is not None
                and secs < 3600
            ),
            "prev_failed": int(user.last_success is False),
            "fails_prev10": sum(1 for ok in user.recent_outcomes if not ok),
            "success": int(event.success),
            "log_rtt_ms": math.log1p(event.rtt_ms or 0.0),
            "rtt_missing": int(event.rtt_ms is None),
            "hour": now.hour,
            "weekday": (now.weekday() + 1) % 7,  # DuckDB dayofweek(): Sunday = 0
            "ip_attempts_1h": ip_attempts,
            "ip_failures_1h": ip_failures,
        }

    def _percentile(self, target: str, proba: float) -> float:
        q = self.card["score_quantiles"][target]
        return float(np.interp(proba, q["values"], q["levels"])) * 100

    # --- scoring --------------------------------------------------------
    def evaluate_event(self, event: LoginEvent) -> EvaluationResult:
        now = datetime.fromisoformat(event.login_ts.replace("Z", "+00:00"))
        if now.tzinfo is None:
            now = now.replace(tzinfo=UTC)
        user = self.store.get_user(event.user_id)
        net = lookup(event.ip)
        if event.asn is None and net.asn:  # fill the network from public IP data when the caller doesn't know it
            event = event.model_copy(update={"asn": net.asn})
        if event.country is None and net.country:
            event = event.model_copy(update={"country": net.country})
        feats = self.features(user, event, now)
        x = np.array([[feats[c] for c in FEATURE_COLUMNS]], dtype=np.float32)
        if self.models is None:
            proba, pct = {"ato": 0.0, "attack_ip": 0.0}, {"ato": 0.0, "attack_ip": 0.0}
        else:
            proba = {t: float(m.predict_proba(x)[0, 1]) for t, m in self.models.items()}
            pct = {t: round(self._percentile(t, p), 2) for t, p in proba.items()}

        tier = max((tier_for(p) for p in pct.values()), key=TIER_RANK.__getitem__)
        reasons = self._reasons(feats, event, user)

        distance_km = velocity = hours = 0.0
        if None not in (event.lat, event.lon, user.last_lat, user.last_lon) and user.last_ts:
            distance_km = float(
                haversine_km(
                    np.array([user.last_lat]), np.array([user.last_lon]), np.array([event.lat]), np.array([event.lon])
                )[0]
            )
            hours = max((now - user.last_ts).total_seconds() / 3600, 1e-4)
            velocity = distance_km / hours
            if velocity > _velocity_threshold() and distance_km > 100:
                reasons.insert(
                    0,
                    f"Impossible travel: {distance_km:,.0f} km in {hours * 60:.0f} min "
                    f"= {velocity:,.0f} km/h (> {_velocity_threshold():.0f} km/h)",
                )
                tier = max(tier, "HIGH", key=TIER_RANK.__getitem__)
        if net.threat:
            reasons.insert(0, f"This IP is a known malware server: {net.threat}")
            tier = "CRITICAL"
        elif net.criminal_network:
            owner = net.network or "unknown"
            reasons.insert(0, f"The IP belongs to a network Spamhaus lists as run by criminals ({owner})")
            tier = max(tier, "HIGH", key=TIER_RANK.__getitem__)
        if net.tor_exit:
            reasons.insert(0, "Signed in through Tor, a network built to hide where people really are")
            tier = max(tier, "HIGH", key=TIER_RANK.__getitem__)
        elif net.hosting:
            reasons.insert(0, f"Came from a hosting / VPN network ({net.network}), where VPNs, proxies and bots run")
            # a VPN the owner always uses is fine; a data-center network new to this account gets a code
            tier = max(tier, "HIGH" if feats["new_asn"] else "MEDIUM", key=TIER_RANK.__getitem__)
        if feats["fails_prev10"] >= GUESSING_FAILS:
            reasons.insert(0, f"{feats['fails_prev10']} wrong passwords just before this: someone may be guessing")
            tier = max(tier, "HIGH", key=TIER_RANK.__getitem__)
        if net.country and event.country and net.country != event.country:
            reasons.append(f"The IP is registered in {net.country}, but the login claims {event.country}")
        if self.models is None:
            reasons.append("Model unavailable on this server: verdict from network and travel rules only")
        if not reasons:
            reasons.append("Nothing unusual for this user")

        previous = None
        if user.last_ts:
            previous = {
                "country": user.last_country,
                "city": user.last_city,
                "lat": user.last_lat,
                "lon": user.last_lon,
            }
        result = EvaluationResult(
            user_id=event.user_id,
            is_anomaly=TIER_RANK[tier] >= TIER_RANK["HIGH"],
            risk_score=max(pct.values()),
            risk_tier=tier,
            recommended_action=ACTIONS[tier],
            ato_probability=round(proba["ato"], 8),
            attack_ip_probability=round(proba["attack_ip"], 6),
            ato_percentile=pct["ato"],
            attack_ip_percentile=pct["attack_ip"],
            reasons=reasons,
            network={
                "asn": net.asn,
                "network": net.network,
                "country": net.country,
                "type": net.label,
                "tor_exit": net.tor_exit,
                "hosting": net.hosting,
                "threat": net.threat,
                "criminal_network": net.criminal_network,
            },
            features={k: round(float(v), 4) for k, v in feats.items()},
            velocity_kmph=round(velocity, 1),
            distance_km=round(distance_km, 1),
            time_delta_hours=round(hours, 3),
            previous_location=previous,
            current_location={"country": event.country, "city": event.city, "lat": event.lat, "lon": event.lon},
            timestamp=event.login_ts,
        )

        user.record(event, now)
        self.ip_history.setdefault(event.ip, deque()).append((now, event.success))
        if result.is_anomaly:
            self.store.log_anomaly(result.model_dump())
        return result

    @staticmethod
    def _reasons(f: dict, event: LoginEvent, user: UserState) -> list[str]:
        out = []
        if f["country_hop_1h"]:
            out.append(f"Country changed within an hour ({user.last_country} -> {event.country})")
        elif f["new_country"]:
            out.append(f"First login from {event.country} for this user")
        if f["new_asn"]:
            out.append(f"New network for this user (ASN {event.asn})")
        if f["new_ua"] or f["new_device"]:
            out.append("New device or browser for this user")
        if 3 <= f["fails_prev10"] < GUESSING_FAILS:
            out.append(f"{f['fails_prev10']} failed attempts in this user's last 10")
        if f["ip_attempts_1h"] >= 10:
            out.append(f"This IP made {f['ip_attempts_1h']} attempts in the past hour ({f['ip_failures_1h']} failed)")
        if not event.success:
            out.append("This attempt failed")
        return out


_engine: RiskEngine | None = None


def get_engine() -> RiskEngine:
    global _engine
    if _engine is None:
        _engine = RiskEngine()
    return _engine
