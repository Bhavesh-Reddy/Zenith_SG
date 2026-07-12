"""Load and validate the official PB-10 dataset from config.DATA_DIR.

Schema (verified against the delivered files, 2026-07-12):
  applications.json      app_id, name, criticality, license_model, ...
  sbom_dependencies.csv  dep_id, application_id, library, version, license,
                         dependency_type ('direct'|'transitive'), last_updated
  vulnerability_db.json  cve_id, library, affected_versions, fixed_version,
                         cvss_score, severity, exploitability, patch_available
  license_rules.json     license, risk_level, compatible_with_proprietary, viral
  dependency_labels.csv  dep_id, ..., is_risky, risk_type, severity, explanation
  transitive_dependencies.json  parent_library, child_library, application_id
                         (versions in this file are known-inconsistent with the
                         SBOM and are ignored — edges are wired by name)

Stdlib-only on purpose: the deterministic core must run with the ML/LLM
layers absent. dependency_labels.csv ships as cp1252, not UTF-8.

Run:  python -m src.ingestion
"""

import csv
import json
from dataclasses import dataclass, field

from src.config import DATA_DIR, FILES

REQUIRED = {
    "applications": {"app_id", "name", "criticality", "license_model"},
    "sbom_dependencies": {"dep_id", "application_id", "library", "version",
                          "license", "dependency_type", "last_updated"},
    "vulnerability_db": {"cve_id", "library", "affected_versions", "cvss_score",
                         "patch_available"},
    "license_rules": {"license", "risk_level", "compatible_with_proprietary",
                      "viral"},
    "dependency_labels": {"dep_id", "application_id", "library", "version",
                          "is_risky", "risk_type", "severity", "explanation"},
    "transitive_dependencies": {"parent_library", "child_library",
                                "application_id"},
}

_TRUE = {"true", "1", "yes"}


def _b(v):
    return v if isinstance(v, bool) else str(v).strip().lower() in _TRUE


def _read_text(path):
    if not path.is_file():
        raise FileNotFoundError(f"missing data file: {path}")
    raw = path.read_bytes()
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("cp1252")


def _check(name, records):
    if not records:
        raise ValueError(f"{name}: no records in {FILES[name]}")
    missing = REQUIRED[name] - set(records[0])
    if missing:
        raise ValueError(f"{name}: missing fields {sorted(missing)}")
    return records


def _load_json(name):
    return _check(name, json.loads(_read_text(FILES[name])))


def _load_csv(name):
    return _check(name, list(csv.DictReader(_read_text(FILES[name]).splitlines())))


@dataclass
class Dataset:
    applications: list = field(default_factory=list)
    sbom_dependencies: list = field(default_factory=list)
    vulnerability_db: list = field(default_factory=list)
    license_rules: list = field(default_factory=list)
    dependency_labels: list = field(default_factory=list)
    transitive_edges: list = field(default_factory=list)

    def summary(self):
        lines = [f"DATA_DIR = {DATA_DIR}"]
        for name in ("applications", "sbom_dependencies", "vulnerability_db",
                     "license_rules", "dependency_labels", "transitive_edges"):
            lines.append(f"  {name:20s} {len(getattr(self, name)):4d} records")
        return "\n".join(lines)


def load_dataset() -> Dataset:
    ds = Dataset(
        applications=_load_json("applications"),
        sbom_dependencies=_load_csv("sbom_dependencies"),
        vulnerability_db=_load_json("vulnerability_db"),
        license_rules=_load_json("license_rules"),
        dependency_labels=_load_csv("dependency_labels"),
        transitive_edges=_load_json("transitive_dependencies"),
    )
    for v in ds.vulnerability_db:
        v["patch_available"] = _b(v["patch_available"])
    for r in ds.license_rules:
        r["compatible_with_proprietary"] = _b(r["compatible_with_proprietary"])
        r["viral"] = _b(r["viral"])
        r["risk_level"] = str(r["risk_level"]).upper()
    for r in ds.dependency_labels:
        r["is_risky"] = _b(r["is_risky"])

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
