"""Central config. All ingestion must read paths from DATA_DIR — never hardcode.

DATA_DIR resolution order:
  1. SBOM_DATA_DIR environment variable, if set (explicit override)
  2. <repo>/sample_data/        — the official dataset, once it arrives
  3. <repo>/sample_data_placeholder/ — schema-matching dev/self-test data
"""

import os
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

_env = os.environ.get("SBOM_DATA_DIR")
if _env:
    DATA_DIR = Path(_env)
elif (REPO_ROOT / "sample_data").is_dir():
    DATA_DIR = REPO_ROOT / "sample_data"
else:
    DATA_DIR = REPO_ROOT / "sample_data_placeholder"

USING_PLACEHOLDER = DATA_DIR.name == "sample_data_placeholder"

FILES = {
    "applications": DATA_DIR / "applications.json",
    "sbom_dependencies": DATA_DIR / "sbom_dependencies.csv",
    "vulnerability_db": DATA_DIR / "vulnerability_db.json",
    "license_rules": DATA_DIR / "license_rules.json",
    "dependency_labels": DATA_DIR / "dependency_labels.csv",
}
