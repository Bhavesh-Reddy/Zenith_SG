"""Phase 2: ML risk scorer vs. hand-tuned baseline, honest holdout validation.

- Baseline: explicit hand-tuned weighted formula (documented below), built
  ONLY from deterministic-core signals. Threshold 0.40 -> risky.
- Model: sklearn HistGradientBoostingClassifier on dependency_labels.csv
  (is_risky binary), 80/20 split stratified by risk_type, random_state=42.
- Both evaluated on the SAME holdout: precision, recall, F1, FPR.
- Separately, the brief's own methodology (full 500-row label set) is run
  for both and reported as "full-set self-eval" — clearly distinct from
  the honest holdout numbers.
- Selection rule (skill): trained model must CLEARLY beat the baseline on
  holdout, else ship the simpler baseline formula.

Never touches the deterministic core's findings — scores are additive.

Run:  python -m src.ml.train
Writes reports/ml_metrics.json and reports/risk_scores.json
(dep_id -> {score, source}).
"""

import json

import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.model_selection import train_test_split

from src.config import REPO_ROOT
from src.ingestion import load_dataset
from src.ml.features import FEATURE_NAMES, build_feature_table

SEED = 42
BASELINE_THRESHOLD = 0.40

# Hand-tuned baseline weights (transparent, documented):
#   CVE name-match is the dominant signal (the dataset's ground truth is
#   name-based); CVSS magnitude, license conflict, staleness add on top;
#   compound paths / shared libs are small additive exposure boosts.
W = {
    "name_match": 0.45,        # any CVE name match (num_cves > 0)
    "cvss": 0.15,              # * (max_cvss / 10)
    "in_range": 0.05,          # version inside documented affected range
    "no_patch": 0.05,          # matched CVE without available patch
    "license_conflict": 0.70,  # viral copyleft in proprietary app
    "license_unknown": 0.55,   # undeclared license
    "unmaintained": 0.50,      # last update > 2 years before reference
    "multi_path": 0.05,        # diamond / compound exposure
    "shared": 0.03,            # library shared across apps
}
F = {n: i for i, n in enumerate(FEATURE_NAMES)}


def baseline_score(x):
    """Hand-tuned formula -> risk score in [0, 1]."""
    s = 0.0
    if x[F["num_cves"]] > 0:
        s += W["name_match"] + W["cvss"] * x[F["cvss_score"]] / 10.0
        s += W["in_range"] * x[F["version_in_range"]]
        s += W["no_patch"] * (1 - x[F["has_patch"]])
    s = max(s, W["license_conflict"] * x[F["license_conflict"]])
    s = max(s, W["license_unknown"] * x[F["license_unknown"]])
    s = max(s, W["unmaintained"] * (x[F["days_since_update"]] > 730))
    s += W["multi_path"] * (x[F["num_paths_to_dependency"]] > 1)
    s += W["shared"] * x[F["is_shared_across_apps"]]
    return min(s, 1.0)


def metrics(y_true, y_pred):
    y_true, y_pred = np.asarray(y_true), np.asarray(y_pred)
    tp = int(((y_true == 1) & (y_pred == 1)).sum())
    fp = int(((y_true == 0) & (y_pred == 1)).sum())
    fn = int(((y_true == 1) & (y_pred == 0)).sum())
    n_clean = int((y_true == 0).sum())
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    return {
        "precision": round(p, 4), "recall": round(r, 4),
        "f1": round(2 * p * r / (p + r), 4) if p + r else 0.0,
        "fpr": round(fp / n_clean, 4) if n_clean else 0.0,
        "tp": tp, "fp": fp, "fn": fn, "n": len(y_true),
    }


def main():
    ds = load_dataset()
    dep_ids, X = build_feature_table(ds)
    X = np.array(X, dtype=float)
    truth = {r["dep_id"]: r for r in ds.dependency_labels}
    y = np.array([int(truth[d]["is_risky"]) for d in dep_ids])
    strat = [truth[d]["risk_type"] for d in dep_ids]

    idx = np.arange(len(y))
    tr, te = train_test_split(idx, test_size=0.20, random_state=SEED,
                              stratify=strat)

    # --- baseline (no training; same formula everywhere) ---
    base_scores = np.array([baseline_score(x) for x in X])
    base_pred = (base_scores >= BASELINE_THRESHOLD).astype(int)

    # --- gradient-boosted trees ---
    clf = HistGradientBoostingClassifier(random_state=SEED,
                                         max_iter=200, max_depth=4)
    clf.fit(X[tr], y[tr])
    ml_prob = clf.predict_proba(X)[:, 1]
    ml_pred = clf.predict(X).astype(int)

    results = {
        "holdout": {"baseline": metrics(y[te], base_pred[te]),
                    "gbdt": metrics(y[te], ml_pred[te])},
        "full_set_self_eval": {"baseline": metrics(y, base_pred),
                               "gbdt": metrics(y, ml_pred)},
        "note": ("holdout = honest 20% stratified split never seen by the "
                 "model; full_set = the brief's own methodology (GBDT number "
                 "is optimistic there because 80% of those rows were its "
                 "training data)"),
    }

    hb, hg = results["holdout"]["baseline"], results["holdout"]["gbdt"]
    # Selection: model must CLEARLY beat baseline on holdout F1 (margin 0.02).
    selected = "gbdt" if hg["f1"] > hb["f1"] + 0.02 else "baseline"
    results["selected"] = selected
    results["selection_reason"] = (
        f"holdout F1 baseline={hb['f1']} vs gbdt={hg['f1']}; "
        + ("GBDT clearly better" if selected == "gbdt" else
           "no clear GBDT win -> ship the simpler, transparent rule-based "
           "formula (per project policy)"))

    scores = base_scores if selected == "baseline" else ml_prob
    out = {d: {"risk_score": round(float(s) * 100, 1), "source": selected}
           for d, s in zip(dep_ids, scores)}

    rep = REPO_ROOT / "reports"
    rep.mkdir(exist_ok=True)
    (rep / "ml_metrics.json").write_text(json.dumps(results, indent=2))
    (rep / "risk_scores.json").write_text(json.dumps(out, indent=2))

    fmt = lambda m: (f"P {m['precision']:.1%}  R {m['recall']:.1%}  "
                     f"F1 {m['f1']:.3f}  FPR {m['fpr']:.1%}  "
                     f"(tp {m['tp']} fp {m['fp']} fn {m['fn']} n {m['n']})")
    print("=== HOLDOUT VALIDATION (honest, 20% stratified, seed 42) ===")
    print(f"  baseline formula : {fmt(hb)}")
    print(f"  GBDT             : {fmt(hg)}")
    print("=== FULL-SET SELF-EVAL (brief's methodology; GBDT optimistic) ===")
    print(f"  baseline formula : {fmt(results['full_set_self_eval']['baseline'])}")
    print(f"  GBDT             : {fmt(results['full_set_self_eval']['gbdt'])}")
    print(f"SELECTED: {selected} — {results['selection_reason']}")
    print(f"risk scores written for {len(out)} dependencies "
          f"-> reports/risk_scores.json")


if __name__ == "__main__":
    main()
