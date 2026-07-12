"""Self-evaluation against dependency_labels.csv ground truth (README Step 6).

Deterministic-core only — no ML, no LLM, stdlib math. Reports every
official target:
  Vulnerability Detection   > 85% recall on CVE-labeled deps
  Transitive Resolution     100% of transitive deps path-resolved
                            (+ recall on TRANSITIVE_VULNERABILITY labels)
  License Conflict Detect.  > 90% recall on license-conflict labels
  False Positive Rate       < 20% (share of labeled-clean deps we flag)
  Risk Score Accuracy       ±10% — requires Phase 2 scores; reported as
                            PENDING until then (never estimated)

Run:  python -m self_eval.evaluate
"""

from collections import Counter

from src.findings import generate_findings
from src.graph.traversal import paths_to_library
from src.ingestion import load_dataset
from src.report.composite import SEVERITY_SCORE, build_report

VULN_TYPES = {"VULNERABLE_DEPENDENCY", "TRANSITIVE_VULNERABILITY"}
LIC_TYPES = {"LICENSE_CONFLICT", "TRANSITIVE_LICENSE_CONFLICT"}


def evaluate(ds=None, verbose=True):
    ds = ds or load_dataset()
    _, pred, g = generate_findings(ds)
    truth = {r["dep_id"]: r for r in ds.dependency_labels}

    tp = sum(1 for d, r in truth.items() if r["is_risky"] and pred[d] != "NONE")
    fp = sum(1 for d, r in truth.items() if not r["is_risky"] and pred[d] != "NONE")
    fn = sum(1 for d, r in truth.items() if r["is_risky"] and pred[d] == "NONE")
    n_clean = sum(1 for r in truth.values() if not r["is_risky"])

    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    fpr = fp / n_clean if n_clean else 0.0

    def type_recall(label_types, pred_types):
        rel = [d for d, r in truth.items() if r["risk_type"] in label_types]
        hit = [d for d in rel if pred[d] in pred_types]
        return len(hit), len(rel)

    v_hit, v_all = type_recall(VULN_TYPES, VULN_TYPES)
    l_hit, l_all = type_recall(LIC_TYPES, LIC_TYPES)
    u_hit, u_all = type_recall({"UNMAINTAINED"}, {"UNMAINTAINED"})
    lu_hit, lu_all = type_recall({"LICENSE_UNKNOWN"}, {"LICENSE_UNKNOWN"})

    trans_rows = [r for r in ds.sbom_dependencies
                  if r["dependency_type"] == "transitive"]
    resolved = sum(1 for r in trans_rows
                   if paths_to_library(g, r["application_id"], r["library"]))
    tv_hit, tv_all = type_recall({"TRANSITIVE_VULNERABILITY"},
                                 {"TRANSITIVE_VULNERABILITY"})

    # Risk Score Accuracy (±10): severity classes map to a 0-100 scale
    # (NONE 0 / LOW 25 / MEDIUM 50 / HIGH 75 / CRITICAL 100); a prediction is
    # accurate when |predicted - truth| <= 10 points.
    severities = build_report(ds)["dep_severities"]
    in_band = sum(
        1 for d, r in truth.items()
        if abs(SEVERITY_SCORE.get(severities[d], 0)
               - SEVERITY_SCORE.get(str(r["severity"]).upper(), 0)) <= 10)

    exact = sum(1 for d, r in truth.items() if pred[d] == r["risk_type"])
    mismatches = [(d, truth[d]["risk_type"], pred[d])
                  for d in truth if pred[d] != truth[d]["risk_type"]]

    results = {
        "precision": precision, "recall": recall, "f1": f1, "fpr": fpr,
        "vuln_detection": (v_hit, v_all),
        "transitive_paths_resolved": (resolved, len(trans_rows)),
        "transitive_vuln_recall": (tv_hit, tv_all),
        "license_detection": (l_hit, l_all),
        "unmaintained_recall": (u_hit, u_all),
        "license_unknown_recall": (lu_hit, lu_all),
        "risk_score_accuracy": (in_band, len(truth)),
        "exact_type_accuracy": (exact, len(truth)),
        "mismatches": mismatches,
    }

    if verbose:
        pc = lambda a, b: f"{a}/{b} = {a / b:.1%}" if b else "n/a"
        ok = lambda cond: "PASS" if cond else "MISS"
        print("=== SELF-EVAL (deterministic core only, ML/LLM disabled) ===")
        print(f"overall  precision {precision:.1%}  recall {recall:.1%}  F1 {f1:.3f}")
        print(f"[{ok(v_hit / v_all > .85 if v_all else False)}] Vulnerability Detection  (>85%): {pc(v_hit, v_all)}")
        print(f"[{ok(resolved == len(trans_rows))}] Transitive Resolution   (100%): {pc(resolved, len(trans_rows))} paths; "
              f"transitive-vuln recall {pc(tv_hit, tv_all)}")
        print(f"[{ok(l_hit / l_all > .90 if l_all else False)}] License Conflict Detect (>90%): {pc(l_hit, l_all)}")
        print(f"[{ok(fpr < .20)}] False Positive Rate     (<20%): {fp}/{n_clean} = {fpr:.1%}")
        print(f"[{ok(in_band / len(truth) > .90)}] Risk Score Accuracy    (±10, >90% of deps): {pc(in_band, len(truth))}")
        print(f"extra    unmaintained recall {pc(u_hit, u_all)}   "
              f"license-unknown recall {pc(lu_hit, lu_all)}")
        print(f"exact risk-type accuracy: {pc(exact, len(truth))}")
        if mismatches:
            print(f"--- {len(mismatches)} type mismatches (truth -> predicted) ---")
            for d, t, p in mismatches[:20]:
                print(f"  {d}: {t} -> {p}")
            pairs = Counter((t, p) for _, t, p in mismatches)
            print("  mismatch pairs:", dict(pairs))
    return results


if __name__ == "__main__":
    evaluate()
