"""Load and validate the 5 PB-10 input files from config.DATA_DIR.

Stdlib-only on purpose: the deterministic core must run with the ML/LLM
layers absent, so ingestion carries no heavy dependencies.

Run:  python -m src.ingestion
"""

import csv
import json
from dataclasses import dataclass, field

from src.config import DATA_DIR, FILES, USING_PLACEHOLDER

REQUIRED_COLUMNS = {
    "sbom_dependencies": {"app_id", "library_name", "version", "license_type",
                          "is_direct", "last_updated"},
    "dependency_labels": {"app_id", "library_name", "is_risky", "risk_type",
                          "severity", "explanation"},
}
REQUIRED_KEYS = {
    "applications": {"id", "name", "business_criticality", "owner"},
    "vulnerability_db": {"cve_id", "affected_library", "affected_versions",
                         "cvss_score", "has_patch"},
    "license_rules": {"license_type", "compatible_with", "risk_level"},
}

_TRUE = {"true", "1", "yes"}


def _parse_bool(v):
    if isinstance(v, bool):
        return v
    return str(v).strip().lower() in _TRUE


@dataclass
class Dataset:
    applications: list = field(default_factory=list)
    sbom_dependencies: list = field(default_factory=list)
    vulnerability_db: list = field(default_factory=list)
    license_rules: list = field(default_factory=list)
    dependency_labels: list = field(default_factory=list)

    def summary(self) -> str:
        lines = [f"DATA_DIR = {DATA_DIR}  "
                 f"({'PLACEHOLDER data' if USING_PLACEHOLDER else 'real sample_data'})"]
        for name in ("applications", "sbom_dependencies", "vulnerability_db",
                     "license_rules", "dependency_labels"):
            lines.append(f"  {name:20s} {len(getattr(self, name)):4d} records")
        return "\n".join(lines)


def _load_json(name):
    path = FILES[name]
    if not path.is_file():
        raise FileNotFoundError(f"{name}: missing file {path}")
    records = json.loads(path.read_text())
    if not isinstance(records, list) or not records:
        raise ValueError(f"{name}: expected a non-empty JSON list in {path}")
    missing = REQUIRED_KEYS[name] - set(records[0])
    if missing:
        raise ValueError(f"{name}: first record missing keys {sorted(missing)}")
    return records


def _load_csv(name, bool_cols=()):
    path = FILES[name]
    if not path.is_file():
        raise FileNotFoundError(f"{name}: missing file {path}")
    with open(path, newline="") as f:
        rows = list(csv.DictReader(f))
    if not rows:
        raise ValueError(f"{name}: no data rows in {path}")
    missing = REQUIRED_COLUMNS[name] - set(rows[0])
    if missing:
        raise ValueError(f"{name}: missing columns {sorted(missing)}")
    for row in rows:
        for col in bool_cols:
            row[col] = _parse_bool(row[col])
    return rows


def load_dataset() -> Dataset:
    """Load all 5 input files; raises with a precise message on any problem."""
    ds = Dataset(
        applications=_load_json("applications"),
        sbom_dependencies=_load_csv("sbom_dependencies", bool_cols=("is_direct",)),
        vulnerability_db=_load_json("vulnerability_db"),
        license_rules=_load_json("license_rules"),
        dependency_labels=_load_csv("dependency_labels", bool_cols=("is_risky",)),
    )
    # Cross-file referential check: every SBOM/label app_id must be a known app.
    app_ids = {a["id"] for a in ds.applications}
    for name in ("sbom_dependencies", "dependency_labels"):
        unknown = {r["app_id"] for r in getattr(ds, name)} - app_ids
        if unknown:
            raise ValueError(f"{name}: unknown app_ids {sorted(unknown)}")
    return ds


if __name__ == "__main__":
    ds = load_dataset()
    print(ds.summary())
