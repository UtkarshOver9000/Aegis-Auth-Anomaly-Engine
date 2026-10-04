# Security notes

## API keys

- `POST /v1/auth/evaluate`, `/v1/anomalies` and `/v1/stats` need an `X-API-Key` header.
- The master key comes from the `AEGIS_API_KEY` environment variable. If it is not set,
  the public demo key `demo-master-key-9000` is used. **Always set `AEGIS_API_KEY` outside
  the demo.**
- `POST /v1/keys/generate` issues extra keys and requires the master key. Issued keys
  (`demo_...`) can evaluate logins but cannot issue keys.
- Keys are compared in constant time and held in memory only; they do not survive a restart.

## Not provided by this project

- Rate limiting: enforce it at the gateway or CDN.
- Persistent or shared state: history is per process (see ARCHITECTURE.md).
- CORS is open (`*`) for the demo page; restrict it for real deployments.

## Data handling

Login events sent to the demo are kept only in that server instance's memory (the last 50
per user and the last 200 HIGH/CRITICAL results) and are lost when the instance stops.
Do not send real user data to the public demo.

## Reporting a problem

Open a GitHub issue using the bug template; don't include real credentials or personal data.
