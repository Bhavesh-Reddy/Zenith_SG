"""Phase 5: hand-crafted edge-case fixtures for the ambiguous PB-10 scenarios.

These entries are DELIBERATELY SEPARATE from the real dataset and the
self-eval label set — they are never loaded by src.ingestion, never scored
by the ML layer, never counted in any metric. Their sole purpose is to
prove the deterministic core behaves correctly on the five ambiguous
situations the brief calls out. Each scenario is run through the REAL
pipeline (build_graph -> cves_for -> check_license -> generate_findings),
not a mock, and asserted against a documented expected behavior.

Run:  python -m tests.edge_cases   (prints PASS/FAIL, writes reports/edge_cases.md)
"""

import json

from src.findings import generate_findings
from src.ingestion import Dataset

# ---- license rules (only the two we need) --------------------------------
LICENSE_RULES = [
    {"license": "MIT", "risk_level": "LOW",
     "compatible_with_proprietary": True, "viral": False},
    {"license": "GPL-3.0", "risk_level": "CRITICAL",
     "compatible_with_proprietary": False, "viral": True},
]

# ---- applications --------------------------------------------------------
APPLICATIONS = [
    {"app_id": "EDGE-PROP", "name": "Edge Proprietary App",
     "criticality": "HIGH", "license_model": "proprietary"},
    {"app_id": "EDGE-INT", "name": "Edge Internal Tool",
     "criticality": "MEDIUM", "license_model": "internal-only"},
    {"app_id": "EDGE-A", "name": "Edge App A",
     "criticality": "HIGH", "license_model": "proprietary"},
    {"app_id": "EDGE-B", "name": "Edge App B",
     "criticality": "MEDIUM", "license_model": "proprietary"},
]


def _row(dep_id, app, lib, ver, lic, dtype, updated):
    return {"dep_id": dep_id, "application_id": app, "library": lib,
            "version": ver, "license": lic, "dependency_type": dtype,
            "last_updated": updated}


# ---- SBOM rows, one block per scenario -----------------------------------
SBOM = [
    # 1) critical CVE but a patch IS available (recent, so no staleness noise)
    _row("EC-1", "EDGE-PROP", "imageio", "2.5.0", "MIT", "direct", "2026-01-01"),
    # 2) unmaintained 2+ yrs, ZERO CVEs in the db
    _row("EC-2", "EDGE-PROP", "legacy-xml", "1.0.0", "MIT", "direct", "2024-01-01"),
    # 3) GPL used ONLY in an internal (non-distributed) app ...
    _row("EC-3", "EDGE-INT", "gpl-tool", "1.0.0", "GPL-3.0", "direct", "2026-01-01"),
    #    ... plus the same GPL lib in a PROPRIETARY app, as the contrast case
    _row("EC-3P", "EDGE-PROP", "gpl-tool", "1.0.0", "GPL-3.0", "direct", "2026-01-01"),
    # 4) the SAME vulnerable library reachable from two different apps
    _row("EC-4A", "EDGE-A", "netcore", "1.0.0", "MIT", "direct", "2026-01-01"),
    _row("EC-4B", "EDGE-B", "netcore", "1.0.0", "MIT", "direct", "2026-01-01"),
    # 5) genuine diamond: two direct roots -> one transitive vulnerable lib
    _row("EC-5R1", "EDGE-PROP", "web-framework", "3.1.0", "MIT", "direct", "2026-01-01"),
    _row("EC-5R2", "EDGE-PROP", "auth-module", "1.4.0", "MIT", "direct", "2026-01-01"),
    _row("EC-5T", "EDGE-PROP", "log-lib", "2.0.0", "MIT", "transitive", "2026-01-01"),
]

# ---- diamond edges (wired by name within the app, per builder convention) -
TRANSITIVE_EDGES = [
    {"application_id": "EDGE-PROP", "parent_library": "web-framework",
     "child_library": "log-lib"},
    {"application_id": "EDGE-PROP", "parent_library": "auth-module",
     "child_library": "log-lib"},
]

# ---- vulnerability db ----------------------------------------------------
VULN_DB = [
    {"cve_id": "CVE-EDGE-0001", "library": "imageio",
     "affected_versions": ["2.0.0", "2.9.0"], "cvss_score": 9.8,
     "severity": "CRITICAL", "exploitability": "HIGH",
     "patch_available": True, "fixed_version": "3.0.0"},
    {"cve_id": "CVE-EDGE-0004", "library": "netcore",
     "affected_versions": ["1.0.0"], "cvss_score": 8.1,
     "severity": "HIGH", "exploitability": "MEDIUM",
     "patch_available": False, "fixed_version": None},
    {"cve_id": "CVE-EDGE-0005", "library": "log-lib",
     "affected_versions": ["2.0.0"], "cvss_score": 9.1,
     "severity": "CRITICAL", "exploitability": "HIGH",
     "patch_available": True, "fixed_version": "2.5.0"},
]


def _fixture():
    return Dataset(
        applications=APPLICATIONS, sbom_dependencies=SBOM,
        vulnerability_db=VULN_DB, license_rules=LICENSE_RULES,
        dependency_labels=[], transitive_edges=TRANSITIVE_EDGES)


def run():
    ds = _fixture()
    findings, cls, _ = generate_findings(ds)
    by_dep = {}
    for f in findings:
        by_dep.setdefault(f["dep_id"], []).append(f)

    results = []  # (n, title, passed, expected, observed)

    # --- 1) patched critical CVE: flagged, but the patch is recorded --------
    f1 = next((f for f in by_dep["EC-1"] if f["type"] == "VULNERABLE_DEPENDENCY"), None)
    cve1 = f1["evidence"]["cves"][0] if f1 else {}
    p1 = bool(f1) and cve1.get("patch_available") is True and cve1.get("fixed_version") == "3.0.0"
    results.append((
        1, "Critical CVE with an available patch is flagged but the patch is noted",
        p1,
        "one VULNERABLE_DEPENDENCY finding whose evidence records patch_available=true "
        "and fixed_version, so downstream ranking/narrative can de-emphasise it",
        f"finding={'yes' if f1 else 'no'}, patch_available={cve1.get('patch_available')}, "
        f"fixed_version={cve1.get('fixed_version')}"))

    # --- 2) unmaintained, zero CVEs: UNMAINTAINED, independent of any CVE ----
    types2 = {f["type"] for f in by_dep["EC-2"]}
    p2 = types2 == {"UNMAINTAINED"} and cls["EC-2"] == "UNMAINTAINED"
    results.append((
        2, "Unmaintained library with zero CVEs is still flagged for maintenance risk",
        p2,
        "exactly one UNMAINTAINED finding (no vulnerability finding), classified UNMAINTAINED",
        f"finding_types={sorted(types2)}, primary_class={cls['EC-2']}"))

    # --- 3) GPL internal-only: ADVISORY not CONFLICT; proprietary = CONFLICT -
    t3_int = {f["type"] for f in by_dep["EC-3"]}
    adv3 = next((f for f in by_dep["EC-3"] if f["type"] == "LICENSE_ADVISORY"), None)
    t3_prop = {f["type"] for f in by_dep["EC-3P"]}
    p3 = (t3_int == {"LICENSE_ADVISORY"} and adv3 and adv3["advisory_only"]
          and cls["EC-3"] == "NONE"
          and "LICENSE_CONFLICT" in t3_prop and cls["EC-3P"] == "LICENSE_CONFLICT")
    results.append((
        3, "GPL in an internal-only app is an advisory, not a distribution conflict",
        bool(p3),
        "internal-only -> LICENSE_ADVISORY (advisory_only, not classified as risky); "
        "same GPL lib in a proprietary app -> LICENSE_CONFLICT",
        f"internal={sorted(t3_int)} (class {cls['EC-3']}), "
        f"proprietary={sorted(t3_prop)} (class {cls['EC-3P']})"))

    # --- 4) same vuln lib in two apps: two findings, NOT deduplicated -------
    v4 = [f for f in findings if f["library"] == "netcore"
          and f["type"] == "VULNERABLE_DEPENDENCY"]
    apps4 = sorted({f["app_id"] for f in v4})
    p4 = len(v4) == 2 and apps4 == ["EDGE-A", "EDGE-B"]
    results.append((
        4, "Same vulnerable library in two apps = compound exposure, not deduplicated",
        p4,
        "two independent VULNERABLE_DEPENDENCY findings, one per application",
        f"findings={len(v4)}, apps={apps4}"))

    # --- 5) genuine diamond: both converging paths reported -----------------
    f5 = next((f for f in by_dep["EC-5T"] if f["type"] == "TRANSITIVE_VULNERABILITY"), None)
    paths5 = sorted(tuple(p) for p in f5["paths"]) if f5 else []
    expect5 = sorted([("EDGE-PROP", "web-framework", "log-lib"),
                      ("EDGE-PROP", "auth-module", "log-lib")])
    p5 = bool(f5) and f5["num_paths"] == 2 and f5["compound_exposure"] and paths5 == expect5
    results.append((
        5, "Genuine diamond dependency reports BOTH converging paths",
        p5,
        "one TRANSITIVE_VULNERABILITY finding with num_paths=2 and both distinct chains",
        f"num_paths={(f5 or {}).get('num_paths')}, paths={[list(p) for p in paths5]}"))

    return results


MD_HEADER = (
    "# Phase 5 — Edge-Case Injection Results\n\n"
    "Five hand-crafted scenarios from the PB-10 brief, each run through the "
    "**real deterministic core** (graph build → path enumeration → CVE match → "
    "license engine → findings). This fixture is isolated: it is never loaded "
    "by ingestion, never scored by the ML layer, and never counted in self-eval.\n\n"
    "| # | Scenario | Result |\n|---|---|---|\n")


def write_md(results):
    from src.config import REPO_ROOT
    lines = [MD_HEADER]
    for n, title, ok, *_ in results:
        lines.append(f"| {n} | {title} | {'✅ PASS' if ok else '❌ FAIL'} |\n")
    lines.append("\n## Detail\n")
    for n, title, ok, expected, observed in results:
        lines.append(f"\n### {n}. {title} — {'PASS' if ok else 'FAIL'}\n")
        lines.append(f"- **Expected:** {expected}\n")
        lines.append(f"- **Observed:** {observed}\n")
    path = REPO_ROOT / "reports" / "edge_cases.md"
    path.parent.mkdir(exist_ok=True)
    path.write_text("".join(lines), encoding="utf-8")
    return path


if __name__ == "__main__":
    results = run()
    print("=== PHASE 5 EDGE-CASE FIXTURES (real deterministic core) ===")
    for n, title, ok, expected, observed in results:
        print(f"[{'PASS' if ok else 'FAIL'}] {n}. {title}")
        print(f"        observed: {observed}")
    n_pass = sum(1 for r in results if r[2])
    print(f"\n{n_pass}/{len(results)} edge cases pass")
    path = write_md(results)
    print(f"summary written -> {path}")
    if n_pass != len(results):
        raise SystemExit(1)
