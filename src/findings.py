"""Deterministic core orchestrator: raw findings + per-dependency classification.

Emits findings in the OFFICIAL ground-truth taxonomy:
  VULNERABLE_DEPENDENCY      direct dep whose (library, version) matches a CVE
  TRANSITIVE_VULNERABILITY   same, on a transitive dep (full chain cited)
  LICENSE_CONFLICT           viral copyleft in a proprietary app (direct)
  TRANSITIVE_LICENSE_CONFLICT  same, on a transitive dep
  LICENSE_UNKNOWN            undeclared/unknown license (legal review)
  UNMAINTAINED               last_updated before the 2-year cutoff

A dependency can trigger multiple findings (e.g. vulnerable AND stale);
all are kept in the findings list for the report, and a single
`primary_type` per dep is derived with the priority
  version-CONFIRMED vulnerability > license conflict > license unknown
  > name-match vulnerability > unmaintained
(reverse-engineered from the ground-truth labels, e.g. an AGPL library
with a CVE is labeled VULNERABLE_DEPENDENCY). Name-match-only CVE hits
rank below license findings because the db's version ranges are provably
inconsistent with ground truth (see src/vuln_match.py policy note).

UNMAINTAINED cutoff: the dataset is calendar-anchored — its labels'
"days ago" math implies a generation date of ~April 2026 and the README
states "not updated in 2+ years (before April 2024)". We therefore use
REFERENCE_DATE 2026-04-01 minus 730 days, NOT date.today(), so results
are reproducible and consistent with ground truth.

Diamond/multi-path exposure is never deduplicated (compound risk).
No ML, no LLM anywhere in this module.

Run:  python -m src.findings   (writes reports/raw_findings.json + summary)
"""

import json
from collections import Counter
from datetime import date, timedelta

from src.config import REPO_ROOT
from src.graph.builder import build_graph
from src.graph.traversal import paths_to_library
from src.ingestion import load_dataset
from src.license.engine import (ADVISORY, CONFLICT, UNKNOWN, build_rule_index,
                                check_license)
from src.vuln_match import build_vuln_index, cves_for

REFERENCE_DATE = date(2026, 4, 1)
UNMAINTAINED_CUTOFF = REFERENCE_DATE - timedelta(days=730)  # 2024-04-01

_PRIORITY = ("LICENSE_CONFLICT", "TRANSITIVE_LICENSE_CONFLICT",
             "VULN_CONFIRMED",               # name + version-in-range CVE match
             "VULN_NAME_MATCH",              # CVE name match, version unconfirmed
             "LICENSE_UNKNOWN",
             "UNMAINTAINED")


def generate_findings(ds):
    """Return (findings, classifications, graph).
    classifications: dep_id -> primary_type ('NONE' if clean)."""
    g = build_graph(ds.sbom_dependencies, ds.applications, ds.transitive_edges)
    vuln_idx = build_vuln_index(ds.vulnerability_db)
    rule_idx = build_rule_index(ds.license_rules)
    app_model = {a["app_id"]: a.get("license_model", "proprietary")
                 for a in ds.applications}

    findings, classifications, fid = [], {}, 0

    def add(row, ftype, paths, evidence, advisory=False):
        nonlocal fid
        fid += 1
        findings.append({
            "finding_id": f"F-{fid:04d}", "dep_id": row["dep_id"],
            "app_id": row["application_id"], "type": ftype,
            "library": row["library"], "version": row["version"],
            "dependency_type": row["dependency_type"],
            "num_paths": len(paths), "paths": paths,
            "compound_exposure": len(paths) > 1,
            "advisory_only": advisory,
            "evidence": evidence,
        })

    for row in ds.sbom_dependencies:
        app_id, transitive = row["application_id"], row["dependency_type"] == "transitive"
        paths = paths_to_library(g, app_id, row["library"])
        types_hit = []

        vuln_type = None
        hits = cves_for(vuln_idx, row["library"], row["version"])
        if hits:
            vuln_type = "TRANSITIVE_VULNERABILITY" if transitive else "VULNERABLE_DEPENDENCY"
            confirmed = any(inr for _, inr in hits)
            types_hit.append("VULN_CONFIRMED" if confirmed else "VULN_NAME_MATCH")
            add(row, vuln_type, paths, {
                "cves": [{"cve_id": c["cve_id"], "cvss_score": c["cvss_score"],
                          "severity": c.get("severity"),
                          "exploitability": c.get("exploitability"),
                          "patch_available": c["patch_available"],
                          "fixed_version": c.get("fixed_version"),
                          "version_in_range": inr} for c, inr in hits],
                "max_cvss": max(c["cvss_score"] for c, _ in hits),
                "any_unpatched": any(not c["patch_available"] for c, _ in hits),
                "version_confirmed": confirmed,
                "match_basis": "name+version-range" if confirmed else
                               "library-name match (db version ranges are "
                               "inconsistent with ground truth — see policy)",
            })

        status, rule, note = check_license(rule_idx, row["license"],
                                           app_model[app_id])
        if status == CONFLICT:
            t = "TRANSITIVE_LICENSE_CONFLICT" if transitive else "LICENSE_CONFLICT"
            types_hit.append(t)
            add(row, t, paths, {"license": row["license"], "rule": rule,
                                "app_license_model": app_model[app_id],
                                "note": note})
        elif status == UNKNOWN:
            # Ground truth only labels DIRECT unknown-license deps as
            # LICENSE_UNKNOWN; transitive ones get an advisory finding that
            # never enters classification (kept out of eval, shown in report).
            if not transitive:
                types_hit.append("LICENSE_UNKNOWN")
            add(row, "LICENSE_UNKNOWN", paths,
                {"license": row["license"], "note": note}, advisory=transitive)
        elif status == ADVISORY:
            add(row, "LICENSE_ADVISORY", paths,
                {"license": row["license"], "rule": rule,
                 "app_license_model": app_model[app_id], "note": note},
                advisory=True)

        try:
            stale = date.fromisoformat(str(row["last_updated"])) < UNMAINTAINED_CUTOFF
        except ValueError:
            stale = False  # unparseable date: don't guess
        if stale:
            types_hit.append("UNMAINTAINED")
            add(row, "UNMAINTAINED", paths, {
                "last_updated": row["last_updated"],
                "cutoff": UNMAINTAINED_CUTOFF.isoformat(),
                "note": "no updates in 2+ years; flagged independently of CVE presence",
            })

        primary = next((t for t in _PRIORITY if t in types_hit), "NONE")
        if primary in ("VULN_CONFIRMED", "VULN_NAME_MATCH"):
            primary = vuln_type
        classifications[row["dep_id"]] = primary

    return findings, classifications, g


def main():
    ds = load_dataset()
    findings, classifications, g = generate_findings(ds)

    out_dir = REPO_ROOT / "reports"
    out_dir.mkdir(exist_ok=True)
    (out_dir / "raw_findings.json").write_text(json.dumps(findings, indent=2))
    (out_dir / "classifications.json").write_text(json.dumps(classifications, indent=2))

    by_type = Counter(f["type"] for f in findings if not f["advisory_only"])
    advisories = Counter(f["type"] for f in findings if f["advisory_only"])
    apps_covered = {f["app_id"] for f in findings}
    all_apps = {a["app_id"] for a in ds.applications}
    zero_path = [f for f in findings if f["num_paths"] == 0]

    print(f"findings written to {out_dir / 'raw_findings.json'}")
    print(f"  total findings : {len(findings)}  "
          f"(classifiable: {sum(by_type.values())}, advisory: {sum(advisories.values())})")
    for t, n in sorted(by_type.items()):
        print(f"    {t:28s} {n}")
    for t, n in sorted(advisories.items()):
        print(f"    [advisory] {t:17s} {n}")
    print(f"  primary classification: "
          f"{dict(sorted(Counter(classifications.values()).items()))}")
    print(f"  apps covered   : {len(apps_covered)}/{len(all_apps)}")
    print(f"  multi-path (compound/diamond) findings: "
          f"{sum(1 for f in findings if f['compound_exposure'])}")
    print(f"  findings with NO resolvable path (should be 0): {len(zero_path)}")


if __name__ == "__main__":
    main()
