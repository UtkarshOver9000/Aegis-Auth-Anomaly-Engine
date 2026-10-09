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

## Reporting a vulnerability

Please report security issues privately through GitHub's "Report a vulnerability" form
(https://github.com/UtkarshOver9000/alibi/security/advisories/new), not in a public issue. Include the steps
to reproduce and what an attacker could do. You can expect a first reply within 7 days and a fix or a plan
within 30 days. Good-faith research that avoids privacy violations, data destruction and service disruption
is welcome; please give a reasonable time to fix before disclosing. The same contact is published at
`/.well-known/security.txt` (RFC 9116).

For ordinary bugs, open an issue with the bug template; don't include real credentials or personal data.

## Secret scan of the git history (9 October 2026)

All 35 commits on every branch were scanned for AWS, GitHub, Google, Slack, Stripe, OpenAI and Anthropic
key formats, private keys, JWTs and quoted assignments to `secret`, `password`, `api_key` or `token`
(snapshot data and vendored files excluded). The only hit is the old public demo key
`demo-master-key-9000`, which was published on purpose. Since the key-handling change (#13) it no longer
works anywhere, because there is no built-in default key. Nothing needed rotating. New commits are
checked by the gitleaks pre-commit hook.
