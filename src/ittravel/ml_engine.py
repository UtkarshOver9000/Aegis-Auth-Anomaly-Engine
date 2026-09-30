"""
Ensemble AI/ML Anomaly Detection Engine combining IsolationForest and Physics-based Geo-heuristics.
"""

from __future__ import annotations

from datetime import datetime, timezone

import numpy as np
from sklearn.ensemble import IsolationForest

from .geo import haversine_km
from .schema import EvaluationResult, LoginEvent
from .state import StateStore, UserState, store


class AIAnomalyEngine:
    """
    Core AI/ML Anomaly Detection Engine.
    
    This engine uses an ensemble approach, combining a scikit-learn IsolationForest
    for unsupervised anomaly detection with deterministic heuristics (like Haversine
    distance calculation) to detect impossible physical travel and anomalous login behavior.
    
    Attributes:
        model (IsolationForest): The scikit-learn ML model.
        store (StateStore): The in-memory or database-backed state store for user history.
    """
    def __init__(self, contamination: float = 0.05, state_store: StateStore | None = None):
        """
        Initialize the Anomaly Engine.

        Args:
            contamination (float): The proportion of outliers in the data set for IsolationForest.
            state_store (StateStore | None): The state store instance. Uses default if None.
        """
        self.model = IsolationForest(
            n_estimators=100,
            contamination=contamination,
            random_state=42,
        )
        self.store = state_store if state_store is not None else store
        self._is_trained = False
        self._bootstrap_model()

    def _bootstrap_model(self):
        """Train IsolationForest on initial synthetic feature distribution."""
        np.random.seed(42)
        normal_samples = np.column_stack([
            np.random.uniform(0, 50, 1000),      # speed km/h (normal travel)
            np.random.uniform(0, 100, 1000),     # distance km
            np.random.uniform(0.1, 24, 1000),    # time delta hours
            np.zeros(1000),                      # device_is_new
            np.random.choice([0, 1], 1000, p=[0.8, 0.2]), # ip subnet change
        ])
        anomaly_samples = np.column_stack([
            np.random.uniform(900, 3000, 100),   # impossible speed
            np.random.uniform(2000, 12000, 100), # distance km
            np.random.uniform(0.01, 1.0, 100),   # time delta hours
            np.ones(100),                        # new device
            np.ones(100),                        # ip subnet change
        ])
        data = np.vstack([normal_samples, anomaly_samples])
        self.model.fit(data)
        self._is_trained = True

    def evaluate_event(self, event: LoginEvent) -> EvaluationResult:
        user_state: UserState = self.store.get_user(event.user_id)
        
        # Parse timestamp
        curr_ts = datetime.fromisoformat(event.login_ts.replace("Z", "+00:00"))
        if curr_ts.tzinfo is None:
            curr_ts = curr_ts.replace(tzinfo=timezone.utc)

        reasons = []

        if user_state.last_ts is None:
            # First login for this user
            user_state.update(
                ts=curr_ts,
                lat=event.lat,
                lon=event.lon,
                city=event.city,
                country=event.country,
                device_id=event.device_id,
                ip=event.ip,
            )
            return EvaluationResult(
                user_id=event.user_id,
                is_anomaly=False,
                risk_score=5.0,
                risk_tier="LOW",
                reasons=["First observed login for user"],
                velocity_kmph=0.0,
                distance_km=0.0,
                time_delta_hours=0.0,
                previous_location=None,
                current_location={"city": event.city, "country": event.country, "lat": event.lat, "lon": event.lon},
                timestamp=event.login_ts,
            )

        # Calculate time delta & distance
        time_delta_sec = max(0.0, (curr_ts - user_state.last_ts).total_seconds())
        time_delta_hours = time_delta_sec / 3600.0

        distance_km = float(
            haversine_km(
                np.array([user_state.last_lat]),
                np.array([user_state.last_lon]),
                np.array([event.lat]),
                np.array([event.lon]),
            )[0]
        )

        velocity_kmph = distance_km / max(time_delta_hours, 1e-4)

        # Feature Flags
        device_is_new = 1.0 if event.device_id not in user_state.known_devices else 0.0
        
        last_ip_prefix = ".".join(user_state.last_ip.split(".")[:2]) if user_state.last_ip else ""
        curr_ip_prefix = ".".join(event.ip.split(".")[:2])
        ip_subnet_changed = 1.0 if last_ip_prefix != curr_ip_prefix else 0.0

        # Heuristic Risk Calculation
        heuristic_score = 0.0
        if velocity_kmph > 900.0 and distance_km > 100.0:
            reasons.append(f"Impossible physical travel velocity ({velocity_kmph:.1f} km/h > 900 km/h)")
            heuristic_score += 65.0

        if device_is_new:
            reasons.append(f"Unrecognized device fingerprint ({event.device_id})")
            heuristic_score += 20.0

        if ip_subnet_changed:
            reasons.append("Login from new IP subnet")
            heuristic_score += 10.0

        # ML Model Scoring (IsolationForest decision function)
        features = np.array([[velocity_kmph, distance_km, time_delta_hours, device_is_new, ip_subnet_changed]])
        raw_ml_score = self.model.score_samples(features)[0] # negative values are anomalous
        ml_risk_score = float(np.clip((0.2 - raw_ml_score) * 100.0, 0.0, 100.0))

        # Ensemble Score (Weighted sum)
        final_risk_score = min(100.0, max(0.0, 0.6 * heuristic_score + 0.4 * ml_risk_score))

        if not reasons and final_risk_score < 30.0:
            reasons.append("Normal login behavior pattern")

        is_anomaly = final_risk_score >= 50.0

        # Risk Tier categorization
        if final_risk_score >= 80.0:
            risk_tier = "CRITICAL"
        elif final_risk_score >= 60.0:
            risk_tier = "HIGH"
        elif final_risk_score >= 35.0:
            risk_tier = "MEDIUM"
        else:
            risk_tier = "LOW"

        prev_loc = {
            "city": user_state.last_city,
            "country": user_state.last_country,
            "lat": user_state.last_lat,
            "lon": user_state.last_lon,
        }
        curr_loc = {
            "city": event.city,
            "country": event.country,
            "lat": event.lat,
            "lon": event.lon,
        }

        # Update state for next evaluation
        user_state.update(
            ts=curr_ts,
            lat=event.lat,
            lon=event.lon,
            city=event.city,
            country=event.country,
            device_id=event.device_id,
            ip=event.ip,
        )

        res = EvaluationResult(
            user_id=event.user_id,
            is_anomaly=is_anomaly,
            risk_score=round(final_risk_score, 1),
            risk_tier=risk_tier,
            reasons=reasons,
            velocity_kmph=round(velocity_kmph, 1),
            distance_km=round(distance_km, 1),
            time_delta_hours=round(time_delta_hours, 3),
            previous_location=prev_loc,
            current_location=curr_loc,
            timestamp=event.login_ts,
        )

        if is_anomaly:
            self.store.log_anomaly(res.model_dump())

        return res


# Global instance
engine = AIAnomalyEngine()
