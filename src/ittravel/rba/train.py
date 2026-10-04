"""
Train and evaluate the login-risk model on the full RBA dataset.

    python -m ittravel.rba.train --db data/rba.duckdb

Targets (both labelled by the online service, not by this project):
* ``ato``: the login was an account takeover (confirmed by its incident team)
* ``attack_ip``: the login came from an IP in a known attacker data set

The data is split by time (first 70% of the period for training, next 15% for
validation, last 15% for testing). Every training positive is kept, plus a
random sample of 3,000,000 training negatives, re-weighted so the model sees
the true class balance. Validation picks the boosting round and the alert
threshold; the test period is scored in full, every login, once.
"""

from __future__ import annotations

import argparse
import json
import platform
import time
from datetime import datetime, timedelta
from pathlib import Path

import duckdb
import joblib
import numpy as np
import sklearn
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.metrics import (
    average_precision_score,
    brier_score_loss,
    confusion_matrix,
    log_loss,
    precision_recall_curve,
    roc_auc_score,
)

from .features import FEATURE_COLUMNS, build_features

ARTIFACT_DIR = Path(__file__).resolve().parents[1] / "artifacts"
NEG_SAMPLE = 3_000_000
VAL_NEG_SAMPLE = 1_000_000
ALERT_BUDGET = 0.01  # share of logins that may be sent to step-up authentication
SEED = 7


def _clip(p):
    return np.clip(p, 1e-7, 1 - 1e-7)


def period_bounds(con) -> tuple:
    lo, hi = con.execute("SELECT min(ts), max(ts) FROM features").fetchone()
    span = hi - lo
    return lo, lo + span * 0.70, lo + span * 0.85, hi + timedelta(seconds=1)


# Account-takeover labels only exist from 2020-02 to 2020-11 (the incident team's
# labels stop there), so that target is split inside the labelled window.
ATO_BOUNDS = (datetime(2020, 2, 1), datetime(2020, 8, 1), datetime(2020, 10, 1), datetime(2020, 12, 1))


def fetch(con, where: str, target: str, neg_sample: int | None = None):
    cols = ", ".join(FEATURE_COLUMNS)
    if neg_sample:
        pos = con.execute(f"SELECT {cols}, {target} FROM features WHERE {where} AND {target}").fetchnumpy()
        n_neg = con.execute(f"SELECT count(*) FROM features WHERE {where} AND NOT {target}").fetchone()[0]
        neg = con.execute(
            f"SELECT {cols}, {target} FROM (SELECT * FROM features WHERE {where} AND NOT {target}) "
            f"USING SAMPLE {neg_sample} ROWS (reservoir, {SEED})"
        ).fetchnumpy()
        x = np.vstack(
            [np.column_stack([pos[c] for c in FEATURE_COLUMNS]), np.column_stack([neg[c] for c in FEATURE_COLUMNS])]
        ).astype(np.float32)
        y = np.r_[np.ones(len(pos[target])), np.zeros(len(neg[target]))].astype(int)
        w = np.r_[np.ones(len(pos[target])), np.full(len(neg[target]), n_neg / max(1, len(neg[target])))]
        return x, y, w
    data = con.execute(f"SELECT {cols}, {target} FROM features WHERE {where}").fetchnumpy()
    x = np.column_stack([data[c] for c in FEATURE_COLUMNS]).astype(np.float32)
    return x, data[target].astype(int), None


def threshold_for_budget(proba, weights, budget: float) -> float:
    order = np.argsort(-proba)
    cum = np.cumsum(weights[order]) / weights.sum()
    idx = int(np.searchsorted(cum, budget))
    return float(proba[order][min(idx, len(order) - 1)])


def score_quantiles(proba, weights, levels: int = 400) -> dict:
    """Weighted quantiles of validation scores, so live scores can be shown as a percentile of real logins."""
    order = np.argsort(proba)
    cum = np.cumsum(weights[order]) / weights.sum()
    grid = np.linspace(0, 1, levels + 1)
    values = np.interp(grid, cum, proba[order])
    return {"levels": [round(float(g), 5) for g in grid], "values": [float(v) for v in values]}


def evaluate(y, proba, threshold) -> dict:
    pred = (proba >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    return {
        "logins": int(len(y)),
        "positives": int(y.sum()),
        "roc_auc": round(roc_auc_score(y, proba), 4),
        "pr_auc": round(average_precision_score(y, proba), 4),
        "log_loss": round(log_loss(y, _clip(proba), labels=[0, 1]), 5),
        "brier": round(brier_score_loss(y, proba), 6),
        "threshold": round(float(threshold), 6),
        "accuracy": round((tp + tn) / len(y), 6),
        "precision": round(tp / (tp + fp), 4) if tp + fp else 0.0,
        "recall": round(tp / (tp + fn), 4) if tp + fn else 0.0,
        "alert_rate": round((tp + fp) / len(y), 5),
        "alerts_per_10k_logins": round(10_000 * (tp + fp) / len(y), 1),
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
    }


def rule(x, name: str) -> np.ndarray:
    col = {c: i for i, c in enumerate(FEATURE_COLUMNS)}
    if name == "new_country_or_new_asn":
        return np.maximum(x[:, col["new_country"]], x[:, col["new_asn"]])
    if name == "country_hop_within_1h":
        return x[:, col["country_hop_1h"]]
    if name == "new_device_and_new_country":
        return x[:, col["new_device"]] * x[:, col["new_country"]]
    raise ValueError(name)


def train_target(con, target: str, bounds) -> tuple[dict, HistGradientBoostingClassifier, dict]:
    lo, t_val, t_test, hi = bounds
    train_where = f"ts >= TIMESTAMP '{lo}' AND ts < TIMESTAMP '{t_val}'"
    val_where = f"ts >= TIMESTAMP '{t_val}' AND ts < TIMESTAMP '{t_test}'"
    test_where = f"ts >= TIMESTAMP '{t_test}' AND ts < TIMESTAMP '{hi}'"

    xt, yt, wt = fetch(con, train_where, target, NEG_SAMPLE)
    xv, yv, wv = fetch(con, val_where, target, VAL_NEG_SAMPLE)
    params = dict(
        learning_rate=0.05,
        max_leaf_nodes=31,
        min_samples_leaf=50,
        l2_regularization=1.0,
        early_stopping=False,
        random_state=SEED,
    )
    full = HistGradientBoostingClassifier(max_iter=500, **params).fit(xt, yt, sample_weight=wt)
    train_curve = [log_loss(yt, _clip(p[:, 1]), sample_weight=wt, labels=[0, 1]) for p in full.staged_predict_proba(xt)]
    val_curve = [log_loss(yv, _clip(p[:, 1]), sample_weight=wv, labels=[0, 1]) for p in full.staged_predict_proba(xv)]
    best = int(np.argmin(val_curve)) + 1
    model = HistGradientBoostingClassifier(max_iter=best, **params).fit(xt, yt, sample_weight=wt)
    threshold = threshold_for_budget(model.predict_proba(xv)[:, 1], wv, ALERT_BUDGET)

    quantiles = score_quantiles(model.predict_proba(xv)[:, 1], wv)
    x_test, y_test, _ = fetch(con, test_where, target)
    p_test = model.predict_proba(x_test)[:, 1]
    result = {
        "periods": {
            "train": [str(lo), str(t_val)],
            "validation": [str(t_val), str(t_test)],
            "test": [str(t_test), str(hi)],
        },
        "training_rows": {
            "positives": int(yt.sum()),
            "sampled_negatives": int((yt == 0).sum()),
            "negative_weight": round(float(wt[yt == 0][0]), 3),
        },
        "best_round": best,
        "model_test": evaluate(y_test, p_test, threshold),
        "model_test_at_0.1pct_budget": evaluate(
            y_test, p_test, threshold_for_budget(model.predict_proba(xv)[:, 1], wv, 0.001)
        ),
        "rules_test": {
            name: evaluate(y_test, rule(x_test, name), 0.5)
            for name in ("new_country_or_new_asn", "country_hop_within_1h", "new_device_and_new_country")
        },
    }
    prec, rec, _ = precision_recall_curve(y_test, p_test)
    result["score_quantiles"] = quantiles
    curves = {
        "train_log_loss": train_curve,
        "val_log_loss": val_curve,
        "best_round": best,
        "pr_precision": prec[:: max(1, len(prec) // 400)],
        "pr_recall": rec[:: max(1, len(rec) // 400)],
    }
    return result, model, curves


def save_figures(curves: dict, out_dir: Path) -> None:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    out_dir.mkdir(parents=True, exist_ok=True)
    fig, axes = plt.subplots(1, len(curves), figsize=(6 * len(curves), 4))
    for ax, (target, c) in zip(np.atleast_1d(axes), curves.items(), strict=True):
        ax.plot(c["train_log_loss"], label="train (re-weighted)")
        ax.plot(c["val_log_loss"], label="validation (re-weighted)")
        ax.axvline(c["best_round"] - 1, color="grey", ls="--", label=f"kept: round {c['best_round']}")
        ax.set(title=f"{target}: log loss per boosting round", xlabel="round", ylabel="log loss", yscale="log")
        ax.legend()
    fig.tight_layout()
    fig.savefig(out_dir / "rba_training_curves.png", dpi=130)
    plt.close(fig)

    fig, axes = plt.subplots(1, len(curves), figsize=(6 * len(curves), 4))
    for ax, (target, c) in zip(np.atleast_1d(axes), curves.items(), strict=True):
        ax.plot(c["pr_recall"], c["pr_precision"])
        ax.set(title=f"{target}: precision-recall (test period, every login)", xlabel="recall", ylabel="precision")
    fig.tight_layout()
    fig.savefig(out_dir / "rba_precision_recall.png", dpi=130)
    plt.close(fig)


def main() -> None:
    parser = argparse.ArgumentParser(description="Train the login-risk model on the RBA dataset")
    parser.add_argument("--db", type=Path, default=Path("data/rba.duckdb"))
    parser.add_argument("--reports-dir", type=Path, default=Path("reports"))
    args = parser.parse_args()

    t0 = time.time()
    con = duckdb.connect(str(args.db))
    con.execute("SET preserve_insertion_order = false")
    con.execute("SET memory_limit = '6GB'")
    con.execute(f"SET temp_directory = '{args.db.parent / 'duckdb_tmp'}'")
    if "features" not in {r[0] for r in con.execute("SHOW TABLES").fetchall()}:
        print("building features...", flush=True)
        build_features(con)
    totals = con.execute(
        "SELECT count(*), count(DISTINCT user_id), sum(ato::INT), sum(attack_ip::INT), min(ts), max(ts) FROM features"
    ).fetchone()
    bounds = period_bounds(con)

    report = {
        "dataset": {
            "name": "Login Data Set for Risk-Based Authentication (Wiefling et al., 2022)",
            "source": "https://zenodo.org/records/6782156",
            "note": "Synthesized by its authors from 33M+ real logins at a Norwegian SSO service; "
            "feature values are artificial but keep real per-user statistics.",
            "logins": int(totals[0]),
            "users": int(totals[1]),
            "account_takeovers": int(totals[2]),
            "attack_ip_logins": int(totals[3]),
            "from": str(totals[4]),
            "to": str(totals[5]),
        },
        "features": FEATURE_COLUMNS,
        "alert_budget": ALERT_BUDGET,
        "targets": {},
    }
    curves, models = {}, {}
    for target in ("ato", "attack_ip"):
        print(f"training {target}...", flush=True)
        target_bounds = ATO_BOUNDS if target == "ato" else bounds
        report["targets"][target], models[target], curves[target] = train_target(con, target, target_bounds)
        print(json.dumps(report["targets"][target]["model_test"], indent=1), flush=True)

    save_figures(curves, args.reports_dir / "figures")
    ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(models, ARTIFACT_DIR / "rba_models.joblib", compress=3)
    card = {
        "features": FEATURE_COLUMNS,
        "score_quantiles": {t: report["targets"][t].pop("score_quantiles") for t in models},
        "thresholds": {t: report["targets"][t]["model_test"]["threshold"] for t in models},
        "test_metrics": {t: report["targets"][t]["model_test"] for t in models},
        "alert_budget": ALERT_BUDGET,
        "dataset": report["dataset"],
        "scikit_learn": sklearn.__version__,
    }
    (ARTIFACT_DIR / "rba_model_card.json").write_text(json.dumps(card, indent=2))
    report["environment"] = {
        "python": platform.python_version(),
        "scikit_learn": sklearn.__version__,
        "duckdb": duckdb.__version__,
    }
    report["runtime_seconds"] = round(time.time() - t0, 1)
    args.reports_dir.mkdir(parents=True, exist_ok=True)
    (args.reports_dir / "rba_metrics.json").write_text(json.dumps(report, indent=2, default=str))
    print(json.dumps(report["dataset"], indent=1))


if __name__ == "__main__":
    main()
