# Aegis ITDR — Deployment & Operations Runbook

## Local Development

```bash
git clone https://github.com/UtkarshOver9000/Aegis-Auth-Anomaly-Engine.git
cd Aegis-Auth-Anomaly-Engine
pip install -e .
python -m uvicorn ittravel.api.app:app --reload --port 8000
```

## Docker

```bash
docker build -t aegis-itdr:latest .
docker run -p 8000:8000 aegis-itdr:latest
```

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `AEGIS_API_KEY` | `demo-master-key-9000` | Override default demo API key |
| `AEGIS_VELOCITY_THRESHOLD` | `900` | Max allowed km/h before CRITICAL flag |
| `AEGIS_CONTAMINATION` | `0.05` | IsolationForest contamination rate |

## Health Check

```bash
curl http://localhost:8000/v1/health
# {"status": "ok"}
```

## Telemetry Stats

```bash
curl -H "X-API-Key: demo-master-key-9000" http://localhost:8000/v1/stats
```
