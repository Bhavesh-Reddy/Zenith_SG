"""Central config. All ingestion must read paths from DATA_DIR — never hardcode.

DATA_DIR resolution order:
  1. SBOM_DATA_DIR environment variable, if set (explicit override)
  2. <repo>/sample_data/ — the official PB-10 dataset
"""

import os
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

_env = os.environ.get("SBOM_DATA_DIR")
DATA_DIR = Path(_env) if _env else REPO_ROOT / "sample_data"

if not DATA_DIR.is_dir():
    raise FileNotFoundError(
        f"DATA_DIR not found: {DATA_DIR} — place the official dataset in "
        f"sample_data/ or set SBOM_DATA_DIR")

FILES = {
    "applications": DATA_DIR / "applications.json",
    "sbom_dependencies": DATA_DIR / "sbom_dependencies.csv",
    "vulnerability_db": DATA_DIR / "vulnerability_db.json",
    "license_rules": DATA_DIR / "license_rules.json",
    "dependency_labels": DATA_DIR / "dependency_labels.csv",
    "transitive_dependencies": DATA_DIR / "transitive_dependencies.json",
}
