"""Feature engineering for the ML risk scorer (one row per dependency).

Features (the skill's minimum set, from deterministic-core outputs only —
NEVER from labels):
  cvss_score            max CVSS across name-matched CVEs (0 if none)
  has_patch             any matched CVE has patch_available
  version_in_range      any matched CVE's affected range contains the version
  num_cves              number of name-matched CVEs for the library
  dependency_depth      shortest hops from app, minus 1 (0 = direct)
  days_since_update     REFERENCE_DATE - last_updated
  license_risk_tier     0 LOW / 1 MEDIUM / 2 HIGH / 3 CRITICAL (rule table)
  license_conflict      viral copyleft in proprietary app (core engine)
  license_unknown       undeclared/unknown license
  num_paths_to_dependency  all simple paths app -> lib (diamond signal)
  is_shared_across_apps library used by 2+ applications
  app_criticality       LOW 0 / MEDIUM 1 / HIGH 2 / CRITICAL 3
"""

from datetime import date

from src.findings import REFERENCE_DATE
from src.graph.builder import build_graph
from src.graph.traversal import depth_of, paths_to_library
from src.license.engine import (CONFLICT, UNKNOWN, build_rule_index,
                                check_license, license_risk_tier)
from src.vuln_match import build_vuln_index, cves_for

FEATURE_NAMES = [
    "cvss_score", "has_patch", "version_in_range", "num_cves",
    "dependency_depth", "days_since_update", "license_risk_tier",
    "license_conflict", "license_unknown", "num_paths_to_dependency",
    "is_shared_across_apps", "app_criticality",
]

_CRIT = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


def build_feature_table(ds):
    """Return (dep_ids, X) where X is a list of feature lists (FEATURE_NAMES
    order), one per sbom_dependencies row."""
    g = build_graph(ds.sbom_dependencies, ds.applications, ds.transitive_edges)
    vuln_idx = build_vuln_index(ds.vulnerability_db)
    rule_idx = build_rule_index(ds.license_rules)
    app_meta = {a["app_id"]: a for a in ds.applications}

    apps_per_lib = {}
    for r in ds.sbom_dependencies:
        apps_per_lib.setdefault(r["library"], set()).add(r["application_id"])

    dep_ids, X = [], []
    for r in ds.sbom_dependencies:
        app_id, lib = r["application_id"], r["library"]
        hits = cves_for(vuln_idx, lib, r["version"])
        status, _, _ = check_license(
            rule_idx, r["license"], app_meta[app_id].get("license_model", "proprietary"))
        try:
            days = (REFERENCE_DATE - date.fromisoformat(str(r["last_updated"]))).days
        except ValueError:
            days = -1
        depth = depth_of(g, app_id, lib)
        dep_ids.append(r["dep_id"])
        X.append([
            max((c["cvss_score"] for c, _ in hits), default=0.0),
            int(any(c["patch_available"] for c, _ in hits)),
            int(any(inr for _, inr in hits)),
            len(hits),
            (depth - 1) if depth else 0,
            days,
            license_risk_tier(rule_idx, r["license"]),
            int(status == CONFLICT),
            int(status == UNKNOWN),
            len(paths_to_library(g, app_id, lib)),
            int(len(apps_per_lib[lib]) > 1),
            _CRIT.get(str(app_meta[app_id].get("criticality", "")).upper(), 1),
        ])
    return dep_ids, X
