"""
Per-login risk features computed from each user's own history (DuckDB SQL).

Every feature for a login uses only that user's (or that IP's) earlier
attempts, never later ones. These are the same signals ``engine.py`` keeps in
memory for live scoring.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:  # duckdb is a training-only dependency; the API only needs FEATURE_COLUMNS
    import duckdb

FEATURE_COLUMNS = [
    "log_prior_logins",
    "log_secs_since_prev",
    "new_country",
    "new_asn",
    "new_ip",
    "new_ua",
    "new_browser",
    "new_os",
    "new_device",
    "country_hop_1h",
    "prev_failed",
    "fails_prev10",
    "success",
    "log_rtt_ms",
    "rtt_missing",
    "hour",
    "weekday",
    "ip_attempts_1h",
    "ip_failures_1h",
]

FEATURE_SQL = """
CREATE OR REPLACE TABLE features AS
WITH w AS (
    SELECT
        ts, user_id, country, asn, ip, device, success, attack_ip, ato, rtt_ms,
        row_number() OVER u - 1 AS n_prior,
        epoch(ts) - epoch(lag(ts) OVER u) AS secs_since_prev,
        lag(country) OVER u AS prev_country,
        lag(success) OVER u AS prev_success,
        sum(CASE WHEN success THEN 0 ELSE 1 END)
            OVER (PARTITION BY user_id ORDER BY ts ROWS BETWEEN 10 PRECEDING AND 1 PRECEDING) AS fails_prev10,
        row_number() OVER (PARTITION BY user_id, country ORDER BY ts) = 1 AS first_country,
        row_number() OVER (PARTITION BY user_id, asn ORDER BY ts) = 1 AS first_asn,
        row_number() OVER (PARTITION BY user_id, ip ORDER BY ts) = 1 AS first_ip,
        row_number() OVER (PARTITION BY user_id, ua ORDER BY ts) = 1 AS first_ua,
        row_number() OVER (PARTITION BY user_id, browser ORDER BY ts) = 1 AS first_browser,
        row_number() OVER (PARTITION BY user_id, os ORDER BY ts) = 1 AS first_os,
        row_number() OVER (PARTITION BY user_id, device ORDER BY ts) = 1 AS first_device,
        count(*) OVER (PARTITION BY ip ORDER BY ts RANGE BETWEEN INTERVAL 1 HOUR PRECEDING AND CURRENT ROW) - 1
            AS ip_attempts_1h,
        sum(CASE WHEN success THEN 0 ELSE 1 END)
            OVER (PARTITION BY ip ORDER BY ts RANGE BETWEEN INTERVAL 1 HOUR PRECEDING AND CURRENT ROW)
            - CASE WHEN success THEN 0 ELSE 1 END AS ip_failures_1h
    FROM logins
    WINDOW u AS (PARTITION BY user_id ORDER BY ts)
)
SELECT
    ts, user_id, ato, attack_ip,
    ln(1 + n_prior) AS log_prior_logins,
    ln(1 + coalesce(secs_since_prev, 1e8)) AS log_secs_since_prev,
    CAST(first_country AND n_prior > 0 AS INTEGER) AS new_country,
    CAST(first_asn AND n_prior > 0 AS INTEGER) AS new_asn,
    CAST(first_ip AND n_prior > 0 AS INTEGER) AS new_ip,
    CAST(first_ua AND n_prior > 0 AS INTEGER) AS new_ua,
    CAST(first_browser AND n_prior > 0 AS INTEGER) AS new_browser,
    CAST(first_os AND n_prior > 0 AS INTEGER) AS new_os,
    CAST(first_device AND n_prior > 0 AS INTEGER) AS new_device,
    CAST(prev_country IS NOT NULL AND country <> prev_country AND secs_since_prev < 3600 AS INTEGER)
        AS country_hop_1h,
    CAST(coalesce(NOT prev_success, false) AS INTEGER) AS prev_failed,
    coalesce(fails_prev10, 0) AS fails_prev10,
    CAST(success AS INTEGER) AS success,
    ln(1 + coalesce(rtt_ms, 0)) AS log_rtt_ms,
    CAST(rtt_ms IS NULL AS INTEGER) AS rtt_missing,
    hour(ts) AS hour,
    dayofweek(ts) AS weekday,
    ip_attempts_1h,
    ip_failures_1h
FROM w
"""


def build_features(con: duckdb.DuckDBPyConnection) -> int:
    con.execute(FEATURE_SQL)
    return con.execute("SELECT count(*) FROM features").fetchone()[0]
