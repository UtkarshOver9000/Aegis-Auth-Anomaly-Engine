# make dev | test | lint | fetch | snapshot | train
PY ?= python
export PYTHONPATH := src

dev:  ## run the API and dashboard at http://localhost:8000
	$(PY) -m uvicorn ittravel.api.app:app --reload --port 8000

test:
	$(PY) -m pytest -q

lint:
	$(PY) -m ruff check . && $(PY) -m ruff format --check .

fetch:  ## download the feeds that are due (see sources.yaml)
	$(PY) -m ittravel.intel.fetch --raw data/intel

snapshot: fetch  ## rebuild src/ittravel/intel_data from the downloads
	$(PY) -m ittravel.intel.snapshot --raw data/intel

train:  ## retrain the login models (needs data/rba-dataset.zip, 1.1 GB)
	$(PY) -m ittravel.rba.load --zip data/rba-dataset.zip --db data/rba.duckdb
	$(PY) -m ittravel.rba.train --db data/rba.duckdb

.PHONY: dev test lint fetch snapshot train
