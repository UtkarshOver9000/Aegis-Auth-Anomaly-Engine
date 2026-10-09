# Training-data policy

1. **Real data only.** No model is trained, validated or tested on generated data. Demo presets use real IP
   addresses from public data (each country's largest networks, live malware servers, Tor exits) and real city
   coordinates. Unit tests may use real coordinates and fixtures saved from real feed responses.
2. **New models use data collected in 2025 or later.** Any model added from now on is trained only on real data
   dated 2025 or later: honeypot telemetry from infrastructure we own, dated public archives (abuse.ch, CISA KEV,
   Have I Been Pwned breach dates, ransomware.live), and consented login data. Every record keeps its original
   timestamp.
3. **The RBA models are a labelled baseline.** The two models trained on the RBA login dataset (Wiefling et al.,
   2022, CC BY 4.0) stay in place as a baseline. Their data runs from 3 Feb 2020 to 28 Feb 2021. Its authors
   synthesized each value from 33M+ real logins and its city values are random. Wherever their numbers appear,
   the app and README say the data period and these caveats.
4. **Out-of-time evaluation only.** Train on earlier weeks, validate on the next, test on the latest. Never
   split randomly, and no feature may use information from after the event it describes.
5. **Every dataset has a data card** with its source, dates, size, labels, known biases, licence and legal
   notes. It is versioned with a content hash.
6. **Consent and privacy.** Login data from people is collected only with consent (own test accounts and
   volunteers). It is kept with IPs truncated or hashed. Attempted passwords are never stored in plain text.
7. **Honest reporting.** Metrics come with the test period, sample size and confidence intervals. When a newer
   test shows a model has degraded, the drop is reported, not hidden.
