# Aegis architecture

## Offline: training on the RBA dataset

```
rba-dataset.zip (Zenodo, 9 GB CSV inside)
   └─ rba/load.py       stream the CSV out of the zip in 1M-row chunks into DuckDB (31,269,264 rows)
      └─ rba/features.py  SQL window functions over each user's (and each IP's) earlier logins
         └─ rba/train.py    time split → gradient boosting per target → artifacts/ + reports/
```

Features per login, all from **earlier** activity only:

| Feature | Meaning |
|---|---|
| `log_prior_logins`, `log_secs_since_prev` | how established the account is, time since last attempt |
| `new_country`, `new_asn`, `new_ip`, `new_ua`, `new_browser`, `new_os`, `new_device` | first time this user is seen with that value |
| `country_hop_1h` | country differs from the previous attempt less than an hour ago |
| `prev_failed`, `fails_prev10`, `success` | recent failed password attempts, this attempt's outcome |
| `log_rtt_ms`, `rtt_missing` | server-measured round-trip time |
| `hour`, `weekday` | time of day and week |
| `ip_attempts_1h`, `ip_failures_1h` | how busy this IP has been across all users in the last hour |

Two binary targets, both labelled by the original online service: `ato` (account
takeover confirmed by its incident team) and `attack_ip` (IP found in an attacker data set).

## Online: the API

```
POST /v1/auth/evaluate
   └─ engine.RiskEngine
        ├─ state.UserState     per-user history (seen countries/networks/devices, recent outcomes)
        ├─ per-IP 1-hour window
        ├─ same 19 features as training → both models → probabilities
        ├─ probability → percentile of validation-period logins → tier
        └─ optional: great-circle distance / time > 900 km/h → at least HIGH
```

Tiers: percentile ≥ 99.9 → CRITICAL (block and alert), ≥ 99 → HIGH (step-up
authentication), ≥ 90 → MEDIUM (allow and log), otherwise LOW.

State is in process memory. On Vercel each instance has its own memory and is recycled,
so the hosted demo is a sandbox; a production deployment would keep user history in a
shared store.
