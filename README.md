# Aegis: login risk scoring

![CI](https://github.com/UtkarshOver9000/Aegis-Auth-Anomaly-Engine/actions/workflows/ci.yml/badge.svg)

Scores every login attempt for **account takeover** and **attack-IP** risk. Two
gradient-boosting models are trained on the full **RBA login dataset**: 31,269,264 logins
from 4,304,857 users. They are evaluated on months of logins they never saw. When a login
includes coordinates, a physical **impossible-travel** check runs on top.

**Live demo:** https://impossible-travel-auth-anomaly-engi.vercel.app
**API docs:** https://impossible-travel-auth-anomaly-engi.vercel.app/docs

## Results

### Account takeover: test period 2020-10-01 → 2020-11-30

5,403,650 logins, 22 of them confirmed account takeovers.

| Method | Takeovers caught | Logins challenged | ROC-AUC |
|---|---|---|---|
| **Model, 1% alert budget** | **14 of 22 (63.64%)** | 0.77% (76.5 per 10,000) | **0.978** |
| Model, 0.1% alert budget | 8 of 22 (36.36%) | 0.07% (6.8 per 10,000) | 0.978 |
| Rule: new country *or* new network for the user | 15 of 22 (68.18%) | 3.52% (351.6 per 10,000) | 0.823 |
| Rule: new device *and* new country | 4 of 22 (18.18%) | 0.05% (5.3 per 10,000) | 0.591 |
| Rule: country changed within 1 hour | 1 of 22 (4.55%) | 34.53% (3,452.7 per 10,000) | 0.350 |

**In business terms:** sending 0.77% of logins to a step-up check (e.g. a one-time code)
stops 14 of the 22 takeovers. The best simple rule needs 4.6× as many challenges to catch
one more takeover.

With only 22 takeovers in the test window, the uncertainty is wide: the 95% confidence
interval for the 63.64% recall is 42.95% to 80.27%.

Full model metrics at the 1% budget:

| Metric | Value |
|---|---|
| ROC-AUC | 0.978 |
| PR-AUC | 0.0038 (933× the 0.0004% base rate) |
| Precision | 0.03% (14 true alerts among 41,321) |
| Recall | 63.64% |
| Accuracy | 99.24% |
| Log loss | 0.00004 |
| Brier score | 0.000004 |

The confusion matrix: 5,362,321 TN, 41,307 FP, 8 FN, 14 TP. Takeovers are so rare that
precision is tiny for any method. That's normal for this problem, and it's why the action
is a step-up challenge, not a block.

### Attack-IP logins: test period 2021-01-01 → 2021-02-28

5,279,379 logins; 604,413 (11.45%) came from IPs on a known-attacker list.

| Method | ROC-AUC | PR-AUC | Precision | Recall | Logins flagged |
|---|---|---|---|---|---|
| **Model** | **0.7487** | **0.2358** | 28.76% | 3.84% | 1.53% |
| Rule: new country or new network | 0.4925 | n/a | 6.36% | 1.65% | 2.98% |
| Rule: country changed within 1 hour | 0.4902 | n/a | 10.88% | 33.48% | 35.22% |

The attack-IP model ranks logins better than chance (ROC-AUC 0.7487, PR-AUC about twice the
base rate), but at a 1-2% alert rate it catches only 3.84% of attack-IP logins. These
features describe user behaviour. Attack IPs are labelled from an external blocklist,
which those behaviours only partly reveal. Treat this model as a weak supporting signal.

![Training curves](reports/figures/rba_training_curves.png)
![Precision-recall](reports/figures/rba_precision_recall.png)

## Data

| | |
|---|---|
| Dataset | *Login Data Set for Risk-Based Authentication*, Wiefling, Jørgensen, Thunem and Lo Iacono (2022), [Zenodo record 6782156](https://zenodo.org/records/6782156), CC BY 4.0 |
| File | `rba-dataset.zip`, 1.1 GB (9.05 GB CSV inside), MD5 `cc1b1078b3929650e6c08678caffcc57` (verified) |
| Contents | 31,269,264 login attempts, 4,304,857 users, 2020-02-03 → 2021-02-28: IP, country, ASN, user agent, browser, OS, device type, round-trip time, success, attack-IP and account-takeover labels |
| Labels | 141 account takeovers (confirmed by the service's incident team; all fall between February and November 2020), 3,096,977 attack-IP logins |

**Read this before quoting the numbers.** Per-user and per-population statistics come
from 33M+ real logins at a large Norwegian single-sign-on service. The individual values
were then synthesized by the dataset's authors to protect privacy, and they call the
values artificial. Two consequences:
- **Cities in this dataset are random**, so geographic travel speed can't be computed
  from it. The impossible-travel check therefore isn't evaluated here.
- Country changes are unusually common: 34.53% of takeover-period test logins come from
  a different country than the same user's attempt less than an hour earlier. That's why
  the "country changed within 1 hour" rule performs badly in the tables above.

## How it works

**Features.** 19 per login, all from the user's and the IP's *earlier* activity only:
- Account age and time since the last attempt.
- First time seen with this country, network (ASN), IP, user agent, browser, OS or device
  type.
- Country hop within an hour.
- Failed attempts among the user's last 10.
- The round-trip time and this attempt's success.
- Hour and weekday.
- How many attempts (and failures) the IP made in the last hour, across all users.

They're computed in DuckDB with window functions over all 31M rows
(`src/ittravel/rba/features.py`). The live engine (`src/ittravel/engine.py`) computes the
same 19 values from in-memory history; a test checks the column order matches.

**Training** (`src/ittravel/rba/train.py`):
- Takeover labels stop in November 2020, so that model uses train 2020-02 → 07,
  validation 08-09 and test 10-11.
- The attack-IP model uses the full period: first 70% train, next 15% validation, last
  15% test.
- Training keeps every positive plus a random 3,000,000 negatives, re-weighted to the
  true class balance.
- Gradient boosting records weighted log loss every round. Validation picks the round
  (takeover model: 39; attack-IP model: 37) and the alert threshold.
- The whole run (DuckDB feature build included) took 36 minutes on a laptop.

**Scoring.**
- Each probability becomes a percentile of validation-period logins.
- Tiers: ≥ 99.9 is CRITICAL (block and alert), ≥ 99 is HIGH (step-up authentication),
  ≥ 90 is MEDIUM (allow and log), anything lower is LOW.
- If coordinates are sent and the implied speed exceeds 900 km/h over more than 100 km,
  the login is raised to at least HIGH.

## API

```bash
curl -X POST https://impossible-travel-auth-anomaly-engi.vercel.app/v1/auth/evaluate \
  -H "Content-Type: application/json" -H "X-API-Key: demo-master-key-9000" \
  -d '{"user_id":"u1","login_ts":"2026-10-04T10:00:00Z","ip":"203.0.113.15","device_id":"dev-1","country":"NO","asn":29695}'
```

| Endpoint | Purpose |
|---|---|
| `POST /v1/auth/evaluate` | score a login and update that user's history (needs `X-API-Key`) |
| `GET /v1/model` | test metrics of the deployed models |
| `GET /v1/anomalies`, `GET /v1/stats` | recent HIGH/CRITICAL results of this server instance |
| `POST /v1/keys/generate` | issue an extra key (needs the master key) |

- The demo key is public. Set `AEGIS_API_KEY` for any real deployment.
- History lives in memory, and on Vercel each instance has its own, so the hosted demo is
  a sandbox.
- More detail: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and
  [docs/SECURITY.md](docs/SECURITY.md).

## Run it

```bash
pip install -r requirements-dev.txt
PYTHONPATH=src uvicorn ittravel.api.app:app --reload --port 8000     # dashboard at http://localhost:8000
PYTHONPATH=src python -m ittravel.cli events.jsonl                    # score a JSON Lines file in order
docker compose up                                                     # same API in Docker
```

Retrain from scratch (downloads 1.1 GB; needs about 3 GB of disk for DuckDB):

```bash
curl -L -o data/rba-dataset.zip "https://zenodo.org/records/6782156/files/rba-dataset.zip?download=1"
PYTHONPATH=src python -m ittravel.rba.load --zip data/rba-dataset.zip --db data/rba.duckdb
PYTHONPATH=src python -m ittravel.rba.train --db data/rba.duckdb
```

## Tests

`pytest --cov=src`: 29 tests, 70% line coverage. CI runs lint and tests on Python 3.11 to
3.13. The tests check:
- The DuckDB feature SQL on hand-checked rows (no look-ahead).
- That the live engine's features match the training columns.
- Novelty, failure and IP-burst counting.
- Impossible travel and the tier mapping.
- API authentication and key issuing.
- The CLI, and the alert-budget and metric maths.

## License

MIT for the code. The RBA dataset is CC BY 4.0 (Wiefling et al., 2022).
