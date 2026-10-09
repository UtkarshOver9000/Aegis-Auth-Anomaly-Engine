# Alibi architecture (one page)

Alibi is one FastAPI app (`src/ittravel`) that serves a static dashboard, a public threat-intel API built on a
daily data snapshot, and login-risk scoring with two models trained on the RBA dataset.
`ittravel` is the original package name; it stays for import compatibility.

## Modules

| Path | What it does |
|---|---|
| `api/app.py` | All HTTP routes: `/` (dashboard), `/v1/intel/*`, `/v1/demo/check`, `/v1/auth/evaluate`, `/v1/keys/generate`, `/v1/model`, `/v1/stats`, `/v1/health` |
| `api/auth.py` | `X-API-Key` checks for the keyed routes (key from `ALIBI_API_KEY` only) |
| `api/ratelimit.py` | Per-IP token-bucket limits on `/v1/*` |
| `engine.py` | `RiskEngine`: builds the 19 live features, scores both models, maps percentiles to tiers, then applies the rule layer: malware IP → CRITICAL; criminal network, Tor, new hosting / VPN network, 5+ failed passwords, or > 900 km/h travel → at least HIGH |
| `state.py` | In-memory per-user history and issued API keys (lost on restart) |
| `schema.py` | Pydantic request and response models |
| `geo.py` | Haversine distance |
| `intel/snapshot.py` | Offline builder: raw downloads → `intel_data/` |
| `intel/service.py` | Reads `intel_data/*.json` and shapes summaries; holds the `SOURCES` licence table |
| `intel/network.py` | IP lookup: owner (iptoasn), hosting flag, Tor (snapshot or live list), abuse.ch malware hit, Spamhaus DROP |
| `intel/news.py` | Live RSS / Atom fetch with a 30-minute in-memory cache |
| `rba/load.py`, `rba/features.py`, `rba/train.py` | Offline training: zip → DuckDB → window-function features → gradient boosting |
| `dashboard/` | `index.html`, `dashboard.css`, `dashboard.js` (plain JS; d3, Leaflet, globe.gl, fonts and textures self-hosted in `dashboard/vendor/`) |
| `api/index.py` (repo root) | Vercel entry point that imports the app |

## Data flow

```
Public sources ──(scripts/fetch_intel.sh)──> data/intel/ (raw, not committed)
                 └─(python -m ittravel.intel.snapshot)──> src/ittravel/intel_data/ (committed, ~13 MB)
                      breaches.json  flaws.json  threats.json  bad_ips.json  countries.json
                      states.json  heat.json  cables.json  network.npz  drop.npz  meta.json
GitHub Action refresh-intel.yml (daily 03:17 UTC) runs both steps and commits intel_data/
Vercel redeploys on each push → API reads intel_data/ from the deployed bundle

RBA zip (Zenodo, 1.1 GB) ──rba/load.py──> data/rba.duckdb ──rba/train.py──> src/ittravel/artifacts/
      rba_models.joblib (two HistGradientBoosting models)   rba_model_card.json (metrics, thresholds, score quantiles)
      reports/rba_metrics.json, reports/figures/*.png

Browser ──GET /──> dashboard ──fetch /v1/intel/*──> service.py ──> intel_data/
        ──POST /v1/demo/check──> engine.py ──> artifacts/ + network.py
```

## Where things live

- **Snapshot:** `src/ittravel/intel_data/`, rebuilt daily. Its date is in `meta.json` (`fetched_at`).
- **Models:** `src/ittravel/artifacts/`, trained once on RBA (2020-02 to 2021-02). They are not retrained
  automatically.
- **Live, not snapshotted:** news and video feeds (cached 30 minutes per instance), and the Tor exit list
  when the snapshot has none (cached 1 hour).
- **State:** in memory per serverless instance, so the hosted demo is a sandbox.

## Known limits

- A single `app.py` holds every route.
- Login history is in memory only.
- The snapshot ships inside the deploy bundle, not in shared storage.
- The models are trained on 2020–2021 data.
- Rate limits are per serverless instance, not global.
