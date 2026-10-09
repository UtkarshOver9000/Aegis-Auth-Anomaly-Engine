# Security notes

## API keys

- The dashboard and `POST /v1/demo/check` need no key. No key is ever shown in the UI or the README.
- `POST /v1/auth/evaluate`, `/v1/anomalies` and `/v1/stats` need an `X-API-Key` header. The master key
  comes only from the `ALIBI_API_KEY` environment variable on the server. If it is not set, those
  endpoints return 503: there is no built-in default key.
- `POST /v1/keys/generate` issues extra keys (`alibi_...`) and requires the master key. Issued keys
  can evaluate logins but cannot issue keys. Keys are compared in constant time and held in memory only.

## Rate limits

Per client IP (first `X-Forwarded-For` hop), token bucket, in memory per server instance:

| Path | Limit |
|---|---|
| `/v1/demo/*` | 20 requests a minute |
| `/v1/auth/*` | 60 a minute |
| other `/v1/*` | 120 a minute |

Over the limit returns 429 with `Retry-After`. Each serverless instance counts on its own, so add a
gateway or CDN limit for a hard global cap.

## Not provided by this project

- Persistent or shared state: history is per process (see ARCHITECTURE.md).
- CORS is open (`*`) for the demo page; restrict it for real deployments.

## Data handling

Login events sent to the demo are kept only in that server instance's memory (the last 50
per user and the last 200 HIGH/CRITICAL results) and are lost when the instance stops.
Do not send real user data to the public demo.

## Reporting a problem

Open a GitHub issue using the bug template; don't include real credentials or personal data.
