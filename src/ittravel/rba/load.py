"""
Stream the RBA login dataset into a local DuckDB database.

    python -m ittravel.rba.load --zip data/rba-dataset.zip --db data/rba.duckdb

The 9 GB CSV inside the Zenodo archive is read in chunks straight from the
zip, so it never has to be extracted to disk.
"""

from __future__ import annotations

import argparse
import io
import time
import zipfile
from pathlib import Path

import duckdb
import pandas as pd

COLUMNS = {
    "Login Timestamp": "ts",
    "User ID": "user_id",
    "Round-Trip Time [ms]": "rtt_ms",
    "IP Address": "ip",
    "Country": "country",
    "ASN": "asn",
    "User Agent String": "ua",
    "Browser Name and Version": "browser",
    "OS Name and Version": "os",
    "Device Type": "device",
    "Login Successful": "success",
    "Is Attack IP": "attack_ip",
    "Is Account Takeover": "ato",
}


def load(zip_path: Path, db_path: Path, chunk_rows: int = 1_000_000) -> int:
    con = duckdb.connect(str(db_path))
    con.execute("DROP TABLE IF EXISTS logins")
    total, t0 = 0, time.time()
    with zipfile.ZipFile(zip_path) as zf, zf.open("rba-dataset.csv") as raw:
        reader = pd.read_csv(
            io.TextIOWrapper(raw, encoding="utf-8"),
            usecols=list(COLUMNS),
            chunksize=chunk_rows,
            dtype={"User ID": "int64", "ASN": "int64", "Round-Trip Time [ms]": "float64"},
            keep_default_na=False,
            na_values={"Round-Trip Time [ms]": [""]},
        )
        for chunk in reader:
            chunk = chunk.rename(columns=COLUMNS)
            chunk["ts"] = pd.to_datetime(chunk["ts"])
            for col in ("success", "attack_ip", "ato"):
                chunk[col] = chunk[col].astype(str).str.lower().eq("true")
            con.register("chunk", chunk)
            if total == 0:
                con.execute("CREATE TABLE logins AS SELECT * FROM chunk")
            else:
                con.execute("INSERT INTO logins SELECT * FROM chunk")
            con.unregister("chunk")
            total += len(chunk)
            print(f"{total:,} rows loaded ({time.time() - t0:.0f}s)", flush=True)
    con.close()
    return total


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    parser.add_argument("--zip", type=Path, default=Path("data/rba-dataset.zip"))
    parser.add_argument("--db", type=Path, default=Path("data/rba.duckdb"))
    args = parser.parse_args()
    print(f"loaded {load(args.zip, args.db):,} login attempts into {args.db}")


if __name__ == "__main__":
    main()
