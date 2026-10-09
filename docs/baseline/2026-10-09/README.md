# Baseline, 9 October 2026 (before the master-plan changes)

Measured on the live site https://impossible-travel-auth-anomaly-engi.vercel.app (commit `e4424b4`) from a home
connection in India. Lighthouse 12 runs in headless Chrome with default throttling.

## Lighthouse

| | Performance | Accessibility | Best practices | SEO | FCP | LCP | TBT | CLS | Page weight |
|---|---|---|---|---|---|---|---|---|---|
| Mobile | 53 | 86 | 96 | 100 | 6.0 s | 6.0 s | 420 ms | 0.003 | 790 KB |
| Desktop | 85 | 86 | 96 | 100 | 1.6 s | 1.6 s | 50 ms | 0.064 | 790 KB |

Page weight counts the home tab only. The globe tab adds the Earth textures and the state data when opened.

## API latency

Total time with `curl`, gzip on. Two runs about 15 minutes apart; the first hit cold serverless instances.
Sizes are the compressed bytes from the first run.

| Endpoint | Run 1 | Run 2 | Size |
|---|---|---|---|
| `/` | 0.39 s | 1.09 s | 4.5 KB |
| `/v1/health` | 0.54 s | 0.35 s | 15 B |
| `/v1/intel/overview` | 2.56 s | 0.33 s | 0.7 KB |
| `/v1/intel/countries` | 0.33 s | 1.08 s | 7.5 KB |
| `/v1/intel/heat` | 0.89 s | 0.37 s | 83 KB |
| `/v1/intel/states` | 1.66 s | 3.53 s | 591 KB |
| `/v1/intel/news` | 0.34 s | 0.33 s | 3.4 KB |
| `/v1/intel/sample-ips?country=IN` | 1.00 s | 0.65 s | 0.3 KB |
| `/v1/model` | 0.34 s | 0.36 s | 0.7 KB |

`/v1/intel/states` (591 KB) is the slowest and heaviest call.

## Tests

`pytest`: 37 passed at `e4424b4`.

## Screenshots

`screens/`: every tab at 1440×1000 (desktop) and 390×844 (mobile), taken with headless Chrome.
