# Aegis ITDR Security Model

## API Authentication

All endpoints (except `/v1/health`) require an `X-API-Key` HTTP header. Keys are issued via `POST /v1/keys/generate` and stored in the in-memory StateStore ring.

In production, keys should be:
- Stored in **HashiCorp Vault** or **AWS Secrets Manager**
- Rotated every 90 days
- Issued per-microservice (least privilege)

## Threat Model

| Threat Actor | Attack Vector | Aegis Response |
|---|---|---|
| Account Takeover | Stolen session cookie replayed from different continent | CRITICAL block via velocity physics |
| Credential Stuffing | Bulk credential replay across many accounts | Per-user IsolationForest outlier detection |
| SIM-Swap + 2FA Bypass | New device login post-SIM swap | Device entropy novelty flag → Step-up challenge |
| Tor / VPN Pivoting | IP subnet jump via anonymizing proxies | Subnet ASN jump detection |

## Rate Limiting

Aegis does not enforce rate limiting internally — this should be enforced at the edge CDN/API Gateway layer (e.g., Cloudflare, AWS API Gateway throttling).

## Data Privacy

- No PII is logged in plain text in the audit ring buffer.
- Login telemetry (coordinates, IP, device) is stored **in-memory only** and purged on process restart.
- For GDPR compliance, implement Redis with TTL-based expiry (e.g., `EXPIRE user:{id} 86400`).
