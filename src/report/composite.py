"""Assemble the composite, ranked, per-application risk report (Phase 3).

Combines: deterministic findings (Phase 1) + numeric risk scores from the
SELECTED scorer (Phase 2) + a deterministic severity class per dependency.

Severity rules (deterministic, evidence-based; calibrated to the dataset's
documented conventions and verified in self-eval — never trained):
  vulnerability          severity field of the highest-CVSS matched CVE
  LICENSE_CONFLICT       CRITICAL for AGPL-3.0/GPL-3.0 (aggressive copyleft),
                         HIGH for other viral licenses
  TRANSITIVE_LICENSE_CONFLICT  HIGH (inherited, one step removed)
  LICENSE_UNKNOWN        MEDIUM (legal review needed, no known exploit)
  UNMAINTAINED           HIGH if stale > 3 years, MEDIUM if 2-3 years
  NONE                   NONE

App risk score = mean of the app's top-10 finding scores (prioritization
signal, 0-100).

Run:  python -m src.report.composite   -> reports/risk_report.json
"""

import json
from datetime import date, datetime, timedelta

from src.config import REPO_ROOT
from src.findings import REFERENCE_DATE, generate_findings
from src.ingestion import load_dataset

REPORTS = REPO_ROOT / "reports"
SEVERITY_SCORE = {"NONE": 0, "LOW": 25, "MEDIUM": 50, "HIGH": 75, "CRITICAL": 100}
_THREE_YEARS = REFERENCE_DATE - timedelta(days=1095)


def predict_severity(primary_type, row, finding_evidence):
    """Deterministic severity class for a dependency's primary finding."""
    if primary_type in ("VULNERABLE_DEPENDENCY", "TRANSITIVE_VULNERABILITY"):
        cves = finding_evidence["cves"]
        best = max(cves, key=lambda c: c["cvss_score"])
        return str(best.get("severity") or "MEDIUM").upper()
    if primary_type == "LICENSE_CONFLICT":
        return "CRITICAL" if row["license"] in ("AGPL-3.0", "GPL-3.0") else "HIGH"
    if primary_type == "TRANSITIVE_LICENSE_CONFLICT":
        return "HIGH"
    if primary_type == "LICENSE_UNKNOWN":
        return "MEDIUM"
    if primary_type == "UNMAINTAINED":
        try:
            return ("HIGH" if date.fromisoformat(str(row["last_updated"]))
                    < _THREE_YEARS else "MEDIUM")
        except ValueError:
            return "MEDIUM"
    return "NONE"


def build_report(ds=None):
    ds = ds or load_dataset()
    findings, classifications, _ = generate_findings(ds)
    scores_path = REPORTS / "risk_scores.json"
    scores = json.loads(scores_path.read_text()) if scores_path.is_file() else {}
    rows = {r["dep_id"]: r for r in ds.sbom_dependencies}

    # first (= priority) finding per dep of the primary type, for evidence
    primary_evidence = {}
    for f in findings:
        if f["type"] == classifications.get(f["dep_id"]) and \
                f["dep_id"] not in primary_evidence:
            primary_evidence[f["dep_id"]] = f

    severities = {}
    for dep_id, primary in classifications.items():
        ev = primary_evidence.get(dep_id, {}).get("evidence", {})
        severities[dep_id] = predict_severity(primary, rows[dep_id], ev)

    for f in findings:
        entry = scores.get(f["dep_id"])
        base = entry["risk_score"] if entry else None
        uplift = min(max(f["num_paths"] - 1, 0) * 5, 15)
        f["risk_score"] = (round(min(base * (1 + uplift / 100), 100.0), 1)
                           if base is not None else None)
        f["score_source"] = entry["source"] if entry else "unavailable"
        f["compound_uplift_pct"] = uplift
        f["severity"] = severities[f["dep_id"]]

    apps_out = []
    for app in ds.applications:
        app_f = sorted((f for f in findings if f["app_id"] == app["app_id"]),
                       key=lambda f: -(f["risk_score"] or 0))
        top = [f["risk_score"] for f in app_f[:10] if f["risk_score"] is not None]
        counts = {}
        for f in app_f:
            counts[f["type"]] = counts.get(f["type"], 0) + 1
        apps_out.append({
            "app_id": app["app_id"], "name": app["name"],
            "criticality": app.get("criticality"),
            "license_model": app.get("license_model"),
            "business_owner": app.get("business_owner"),
            "app_risk_score": round(sum(top) / len(top), 1) if top else 0.0,
            "num_findings": len(app_f),
            "num_compound": sum(1 for f in app_f if f["compound_exposure"]),
            "finding_counts": counts,
            "findings": app_f,
        })
    apps_out.sort(key=lambda a: -a["app_risk_score"])

    report = {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "reference_date": REFERENCE_DATE.isoformat(),
        "score_source": next(iter(scores.values()))["source"] if scores else None,
        "totals": {
            "applications": len(apps_out),
            "dependencies": len(ds.sbom_dependencies),
            "findings": len(findings),
            "compound_exposure_findings":
                sum(1 for f in findings if f["compound_exposure"]),
        },
        "applications": apps_out,
        "dep_classifications": classifications,
        "dep_severities": severities,
    }
    return report


def main():
    report = build_report()
    REPORTS.mkdir(exist_ok=True)
    (REPORTS / "risk_report.json").write_text(json.dumps(report, indent=2))
    print(f"composite risk report -> {REPORTS / 'risk_report.json'}")
    print(f"  score source: {report['score_source']}")
    print("  app ranking (risk score desc):")
    for a in report["applications"]:
        print(f"    {a['app_risk_score']:5.1f}  {a['app_id']}  {a['name']:22s} "
              f"({a['criticality']}, {a['num_findings']} findings, "
              f"{a['num_compound']} compound)")


if __name__ == "__main__":
    main()
