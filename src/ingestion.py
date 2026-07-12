"""Load and normalize the PB-10 input files from config.DATA_DIR.

Canonical schema = the REAL dataset's schema (sample_data/, verified
2026-07-12). The older placeholder dataset's column names are normalized
to canonical via alias maps, so both load identically downstream.

Canonical records:
  applications:      app_id, name, criticality, license_model, business_owner, ...
  sbom_dependencies: dep_id, application_id, library, version, license,
                     dependency_type ('direct'|'transitive'), last_updated
  vulnerability_db:  cve_id, library, affected_versions, fixed_version,
                     cvss_score, severity, exploitability, patch_available
  license_rules:     license, risk_level, compatible_with_proprietary, viral
  dependency_labels: dep_id, application_id, library, version, is_risky,
                     risk_type, severity, explanation
  transitive_edges:  parent_library, child_library, application_id
                     (OPTIONAL — absent in placeholder; versions in this
                     file are known-inconsistent with the SBOM and ignored)

Stdlib-only on purpose: the deterministic core must run with the ML/LLM
layers absent. dependency_labels.csv ships as cp1252, not UTF-8.

Run:  python -m src.ingestion
"""

import csv
import json
from dataclasses import dataclass, field

from src.config import DATA_DIR, FILES, USING_PLACEHOLDER

_TRUE = {"true", "1", "yes"}


def _b(v):
    return v if isinstance(v, bool) else str(v).strip().lower() in _TRUE


def _read_text(path):
    raw = path.read_bytes()
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("cp1252")


def _read_csv(path):
    return list(csv.DictReader(_read_text(path).splitlines()))


def _apply_aliases(rec, aliases):
    for old, new in aliases.items():
        if old in rec and new not in rec:
            rec[new] = rec.pop(old)
    return rec


@dataclass
class Dataset:
    applications: list = field(default_factory=list)
    sbom_dependencies: list = field(default_factory=list)
    vulnerability_db: list = field(default_factory=list)
    license_rules: list = field(default_factory=list)
    dependency_labels: list = field(default_factory=list)
    transitive_edges: list = field(default_factory=list)

    def summary(self):
        lines = [f"DATA_DIR = {DATA_DIR}  "
                 f"({'PLACEHOLDER data' if USING_PLACEHOLDER else 'REAL sample_data'})"]
        for name in ("applications", "sbom_dependencies", "vulnerability_db",
                     "license_rules", "dependency_labels", "transitive_edges"):
            n = len(getattr(self, name))
            note = "  (absent — synthetic parent assignment will be used)" \
                if name == "transitive_edges" and n == 0 else ""
            lines.append(f"  {name:20s} {n:4d} records{note}")
        return "\n".join(lines)


def load_dataset() -> Dataset:
    apps = json.loads(_read_text(FILES["applications"]))
    for a in apps:
        _apply_aliases(a, {"id": "app_id", "business_criticality": "criticality",
                           "owner": "business_owner"})
        a.setdefault("license_model", "proprietary")

    sbom = _read_csv(FILES["sbom_dependencies"])
    for i, r in enumerate(sbom, 1):
        _apply_aliases(r, {"app_id": "application_id", "library_name": "library",
                           "license_type": "license"})
        if "dependency_type" not in r:
            r["dependency_type"] = "direct" if _b(r.pop("is_direct", True)) else "transitive"
        r.setdefault("dep_id", f"DEP-{i:04d}")

    vulns = json.loads(_read_text(FILES["vulnerability_db"]))
    for v in vulns:
        _apply_aliases(v, {"affected_library": "library", "has_patch": "patch_available"})
        v["patch_available"] = _b(v["patch_available"])
        v.setdefault("fixed_version", None)
        v.setdefault("exploitability", "UNKNOWN")

    rules = json.loads(_read_text(FILES["license_rules"]))
    for r in rules:
        _apply_aliases(r, {"license_type": "license"})
        if "compatible_with_proprietary" not in r:   # placeholder schema
            r["compatible_with_proprietary"] = "Proprietary" in r.get("compatible_with", [])
        r["compatible_with_proprietary"] = _b(r["compatible_with_proprietary"])
        r["viral"] = _b(r.get("viral", not r["compatible_with_proprietary"]))
        r["risk_level"] = str(r.get("risk_level", "LOW")).upper()

    labels = _read_csv(FILES["dependency_labels"])
    sbom_by_key = {(r["application_id"], r["library"]): r["dep_id"] for r in sbom}
    for r in labels:
        _apply_aliases(r, {"app_id": "application_id", "library_name": "library"})
        r["is_risky"] = _b(r["is_risky"])
        r.setdefault("dep_id", sbom_by_key.get((r["application_id"], r["library"])))

    edges_path = DATA_DIR / "transitive_dependencies.json"
    edges = json.loads(_read_text(edges_path)) if edges_path.is_file() else []

    ds = Dataset(apps, sbom, vulns, rules, labels, edges)

    app_ids = {a["app_id"] for a in ds.applications}
    for name in ("sbom_dependencies", "dependency_labels"):
        unknown = {r["application_id"] for r in getattr(ds, name)} - app_ids
        if unknown:
            raise ValueError(f"{name}: unknown application_ids {sorted(unknown)}")
    label_ids = {r["dep_id"] for r in ds.dependency_labels}
    sbom_ids = {r["dep_id"] for r in ds.sbom_dependencies}
    if label_ids != sbom_ids:
        raise ValueError(f"labels/sbom dep_id mismatch: {len(label_ids ^ sbom_ids)} differ")
    return ds


if __name__ == "__main__":
    print(load_dataset().summary())
