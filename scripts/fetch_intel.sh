#!/usr/bin/env bash
# Download every feed listed in sources.yaml (see src/ittravel/intel/fetch.py), then build:
#   bash scripts/fetch_intel.sh && PYTHONPATH=src python -m ittravel.intel.snapshot --raw data/intel
# Pass --force to ignore each feed's cadence, or --only id1,id2 for specific feeds.
set -euo pipefail
cd "$(dirname "$0")/.."
PYTHONPATH=src python -m ittravel.intel.fetch --raw data/intel "$@"
