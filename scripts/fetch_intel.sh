#!/usr/bin/env bash
# Download every public source behind the intel snapshot, then build it:
#   bash scripts/fetch_intel.sh && PYTHONPATH=src python -m ittravel.intel.snapshot --raw data/intel
set -euo pipefail
mkdir -p data/intel && cd data/intel
get() { curl -fsSL --retry 3 -m 600 -o "$1" "$2" && echo "ok  $1"; }

get hibp_breaches.json        https://haveibeenpwned.com/api/v3/breaches
get cisa_kev.json             https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
get ip2asn-v4.tsv.gz          https://iptoasn.com/data/ip2asn-v4.tsv.gz
get public_dns_nameservers.csv https://public-dns.info/nameservers.csv
since=$(date -u -d '30 days ago' +%Y-%m-%d); until=$(date -u +%Y-%m-%d)
get ooni_by_country.json      "https://api.ooni.io/api/v1/aggregation?test_name=web_connectivity&since=$since&until=$until&axis_x=probe_cc"
get feodo_c2.json             https://feodotracker.abuse.ch/downloads/ipblocklist.json
get urlhaus_recent.csv        https://urlhaus.abuse.ch/downloads/csv_recent/
get threatfox_recent.json     https://threatfox.abuse.ch/export/json/recent/
get spamhaus_drop_v4.json     https://www.spamhaus.org/drop/drop_v4.json
get spamhaus_asndrop.json     https://www.spamhaus.org/drop/asndrop.json
get ransomware_recent.json    https://api.ransomware.live/v2/recentvictims
get cable_geo.json            https://www.submarinecablemap.com/api/v3/cable/cable-geo.json
get landing_points.json       https://www.submarinecablemap.com/api/v3/landing-point/landing-point-geo.json
get dbip-city-lite.csv.gz     "https://download.db-ip.com/free/dbip-city-lite-$(date -u +%Y-%m).csv.gz" \
  || get dbip-city-lite.csv.gz "https://download.db-ip.com/free/dbip-city-lite-$(date -u -d 'last month' +%Y-%m).csv.gz"
get ne_10m_admin1.geojson     https://raw.githubusercontent.com/nvkelso/natural-earth-vector/master/geojson/ne_10m_admin_1_states_provinces.geojson
# Optional: torproject.org is blocked on some networks. Without it, the app fetches the exit list live.
get onionoo_exits.json "https://onionoo.torproject.org/details?flag=Exit&running=true&fields=exit_addresses,country" \
  || echo "skip onionoo_exits.json (unreachable)"
date -u +%Y-%m-%dT%H:%M:%SZ > fetched_at.txt
cp fetched_at.txt fetched_at_threats.txt
