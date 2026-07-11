"""Deterministic core orchestrator: raw findings list (NO scoring here).

Finding types produced (all purely rule-based — no ML, no LLM):
  vulnerability  — direct dep whose (lib, version) matches a CVE
  transitive_vulnerability — same, reached only through other libraries
  license_conflict — license incompatible with proprietary use
  unmaintained  — last_updated older than 18 months, flagged independently
                  of CVE presence

Every finding cites full evidence: app, ALL dependency paths (diamond
paths kept, never deduplicated — compound risk), and the CVE record or
license rule or staleness dates that triggered it.

Run:  python -m src.findings   (writes reports/raw_findings.json + summary)
"""

import json
from collections import Counter
from datetime import date
from pathlib import Path

from src.config import REPO_ROOT
from src.graph.builder import build_graph
from src.graph.traversal import paths_to_library
from src.ingestion import load_dataset
from src.license.engine import build_rule_index, check_license
from src.vuln_match import build_vuln_index, cves_for

UNMAINTAINED_DAYS = 548  # 18 months


def _days_stale(last_updated, today):
    try:
        return (today - date.fromisoformat(str(last_updated))).days
    except ValueError:
        return None  # unparseable date: don't guess


def generate_findings(ds, today=None):
    """Return (findings, graph). Deterministic; safe to re-run."""
    today = today or date.today()
    g = build_graph(ds.sbom_dependencies, ds.applications)
    vuln_idx = build_vuln_index(ds.vulnerability_db)
    rule_idx = build_rule_index(ds.license_rules)

    findings, fid = [], 0

    def add(app_id, ftype, row, paths, evidence):
        nonlocal fid
        fid += 1
        findings.append({
            "finding_id": f"F-{fid:04d}", "app_id": app_id, "type": ftype,
            "library_name": row["library_name"], "version": row["version"],
            "is_direct": row["is_direct"],
            "num_paths": len(paths), "paths": paths,
            "compound_exposure": len(paths) > 1,
            "evidence": evidence,
        })

    for row in ds.sbom_dependencies:
        app_id, lib = row["app_id"], row["library_name"]
        paths = paths_to_library(g, app_id, lib)

        cves = cves_for(vuln_idx, lib, row["version"])
        if cves:
            ftype = "vulnerability" if row["is_direct"] else "transitive_vulnerability"
            add(app_id, ftype, row, paths, {
                "cves": [{"cve_id": c["cve_id"], "cvss_score": c["cvss_score"],
                          "has_patch": c["has_patch"],
                          "affected_versions": c["affected_versions"]} for c in cves],
                "max_cvss": max(c["cvss_score"] for c in cves),
                "any_unpatched": any(not c["has_patch"] for c in cves),
            })

        conflict, rule, note = check_license(rule_idx, row["license_type"])
        if conflict:
            add(app_id, "license_conflict", row, paths, {
                "license_type": row["license_type"],
                "rule": rule, "scope_known": False, "note": note,
            })

        stale = _days_stale(row["last_updated"], today)
        if stale is not None and stale > UNMAINTAINED_DAYS:
            add(app_id, "unmaintained", row, paths, {
                "last_updated": row["last_updated"], "days_since_update": stale,
                "threshold_days": UNMAINTAINED_DAYS,
                "note": "flagged for maintenance risk independently of CVE presence",
            })

    return findings, g


def main():
    ds = load_dataset()
    findings, g = generate_findings(ds)

    out_dir = REPO_ROOT / "reports"
    out_dir.mkdir(exist_ok=True)
    out = out_dir / "raw_findings.json"
    out.write_text(json.dumps(findings, indent=2))

    by_type = Counter(f["type"] for f in findings)
    apps_covered = {f["app_id"] for f in findings}
    all_apps = {a["id"] for a in ds.applications}
    diamonds = sum(1 for f in findings if f["compound_exposure"])
    zero_path = [f for f in findings if f["num_paths"] == 0]

    print(f"raw findings written to {out}")
    print(f"  total findings : {len(findings)}")
    for t, n in sorted(by_type.items()):
        print(f"    {t:26s} {n}")
    print(f"  apps covered   : {len(apps_covered)}/{len(all_apps)}"
          f"  (missing: {sorted(all_apps - apps_covered) or 'none'})")
    print(f"  multi-path (compound/diamond) findings: {diamonds}")
    print(f"  findings with NO resolvable path (should be 0): {len(zero_path)}")


if __name__ == "__main__":
    main()
