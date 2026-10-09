# Pitch and demo script

## 60-second pitch (for anyone, technical or not)

"Every day, companies lose their customers' data, attackers rent or hijack servers, and ransomware gangs post
new victims. All of that is published somewhere, but it is scattered across a dozen sites. Alibi pulls it into
one place, on a live 3D globe, using only real public data. It refreshes on a schedule and every number shows its
source and age.

It answers three questions. Who got breached, and how did the data get out? Where are attacks coming from right
now? Which software flaws should a company patch first?

Then it does what a bank or an email provider does at sign-in: it checks whether a login has an alibi. Is this
the real owner, from their usual place, network and device, or someone on Tor, a new VPN, a malware server, or
a trip no plane could make? A model trained on 31 million logins catches 14 of the 22 account takeovers in its
test data while asking fewer than 1 in 100 people for a code. On top of the model, a rule layer uses today's
threat data, and every verdict comes with plain-English reasons."

## 2-minute demo (open https://impossible-travel-auth-anomaly-engi.vercel.app)

| Time | Do this | Say this |
|---|---|---|
| 0:00 | Home page | "These are today's numbers: breaches, live malware servers, ransomware victims this week, newly exploited flaws. Each comes from a public source, refreshed on a schedule." |
| 0:15 | **Live globe** (`/#globe`), spin it, click Maharashtra | "Each state is coloured by malware servers per million IP addresses, so big countries don't win just by being big. Click a state for its own count and the country's hotspot cities." |
| 0:35 | Switch the metric to *Websites blocked* | "Same globe, censorship data from OONI volunteers. Country-level data is labelled as country-level." |
| 0:45 | **Attacks** tab | "The surprise: about half of these malware servers are hijacked home routers and cameras, not rented servers. Blocking data centers alone misses them." |
| 1:00 | **Account takeover**, *Same person, but through Tor* (`/#check/tor`) | "Same account, same laptop, but through Tor. Alibi raises it to HIGH and asks for a one-time code, and says why." |
| 1:15 | *Mumbai, then London 10 min later* (`/#check/travel`) | "7,192 km in 10 minutes is 43,150 km/h. No plane does that, so it's HIGH: impossible travel." |
| 1:30 | Usual home India, sign-in from *United Arab Emirates (Dubai)* on *a VPN / cloud server*, 600 minutes | "A plausible trip, but from a data-center network this account has never used, so Alibi asks for a code and says it's unusual for this user." |
| 1:45 | **Data & accuracy** | "Here's what's real and current: when each feed was last downloaded, and the honest caveat that the login models were trained on 2020 to 2021 data. Next I'm collecting 2025 to 2026 data with a honeypot." |

## Answers to the questions interviewers ask

- **Only 22 takeovers in the test set?** Yes. That's why I report a confidence interval (43% to 80% recall)
  and compare against simple rules on the same data instead of quoting one accuracy number. Accuracy is
  meaningless here: flagging nothing scores 99.9996%.
- **The login data is from 2020?** It is the largest public login dataset with takeover labels (Wiefling et al.,
  2022). Its authors synthesized values from 33M+ real logins. I treat the model as a baseline and put today's
  threat data in a rule layer on top. The next step is a honeypot for real 2025 to 2026 attack data.
- **Why gradient boosting?** Tabular features, heavy class imbalance, and fast inference. The plan adds logistic
  regression and rule baselines and an ablation to show what each part adds.
- **How does it scale?** The snapshot is precomputed and the globe textures are rendered once and cached by the
  CDN. Scoring is one model call plus in-memory lookups. Login history would move to a database for production.
