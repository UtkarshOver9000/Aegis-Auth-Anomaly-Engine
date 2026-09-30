# Aegis ITDR — System Architecture

Aegis is designed for high-throughput, inline, low-latency authentication evaluation at enterprise scale.

## Core Components

1. **API Gateway (FastAPI)**: Handles incoming `POST /v1/auth/evaluate` requests. Authenticates microservice callers via `X-API-Key` header verification.
2. **Tenant State Engine (StateStore)**: Maintains an in-memory per-user ring buffer of the last known location, IP octets, device fingerprint, and timestamp. Redis-backed in production.
3. **Ensemble ML Engine (IsolationForest)**: A pre-trained unsupervised IsolationForest model trained on synthetic feature distributions (velocity, device novelty, subnet entropy). Scores each login event as an outlier probability.
4. **Geodesic Physics Engine (Haversine)**: Calculates the great-circle distance between consecutive coordinate pairs using the Haversine formula, then divides by the time delta to produce an implied physical velocity in km/h.
5. **Composite Risk Scorer**: Weighted ensemble combining ML outlier score (40%) + heuristic velocity physics (60%). Outputs a canonical 0–100 risk score with tier classification and human-readable rationale tags.
6. **Web Dashboard (Leaflet + Chart.js)**: Real-time browser-based interface with interactive geodesic radar map, attack simulator sandbox, global edge POP status, and SOC audit trail.

## Scoring Signal Pipeline

```
Login Event (user_id, lat, lon, device_id, ip, timestamp)
        │
        ▼
┌──────────────────────────────────────────────────────┐
│          Aegis Composite Risk Scoring Engine          │
│  ┌─────────────────────────────────────────────────┐ │
│  │ Haversine(prev_coord, curr_coord) / Δt → km/h   │ │
│  │ IsolationForest.score_samples(features)          │ │
│  │ device_id ∈ known_devices? (entropy novelty)     │ │
│  │ ip_prefix_changed? (subnet jump detection)       │ │
│  └─────────────────────────────────────────────────┘ │
│  Final Score = 0.6 × heuristic + 0.4 × ML score     │
└──────────────────────────────────────────────────────┘
        │
        ▼
  Risk Tier Decision:
  0–35   → LOW    (Frictionless allow)
  36–79  → HIGH   (Step-up Passkey / WebAuthn challenge)
  80–100 → CRITICAL (Immediate block + PagerDuty SOC alert)
```

## Future Scalability

- Replace in-memory StateStore with **Redis Streams** for distributed state across Kubernetes replicas.
- Add **Apache Kafka** ingestion layer for high-volume auth telemetry (> 1M events/day).
- Integrate **HashiCorp Vault** for production API key management.
- Add **PostgreSQL** persistent audit log for GDPR/SOC2 compliance.
