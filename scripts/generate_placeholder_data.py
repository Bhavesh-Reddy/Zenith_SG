"""Generate sample_data_placeholder/ matching the PB-10 brief schema.

Development/self-test data ONLY — never present as the official dataset.
Seeded for reproducibility. Labels are internally consistent with the data:
  - every 'vulnerable'/'transitive_vulnerability' row has a matching CVE
    (library + exact version) in vulnerability_db.json
  - every 'license_conflict' row uses a copyleft license whose rule in
    license_rules.json is incompatible with 'Proprietary'
  - every 'unmaintained' row has last_updated > 18 months before 2026-07-11
    and no CVE
  - 'clean' rows have recent dates, permissive licenses, no CVE

Target label distribution per the brief: ~18% vulnerable, ~12% license
conflict, ~15% unmaintained, ~10% transitive vulnerability, ~45% clean.
"""

import csv
import json
import random
from datetime import date, timedelta
from pathlib import Path

random.seed(42)

OUT = Path(__file__).resolve().parent.parent / "sample_data_placeholder"
OUT.mkdir(exist_ok=True)

TODAY = date(2026, 7, 11)

# ---------------------------------------------------------------- applications
APP_DEFS = [
    ("APP-001", "PaymentsGateway", "critical"),
    ("APP-002", "TradeSettlement", "critical"),
    ("APP-003", "CustomerPortal", "high"),
    ("APP-004", "RiskAnalyticsEngine", "high"),
    ("APP-005", "FraudMonitor", "high"),
    ("APP-006", "LoanOrigination", "medium"),
    ("APP-007", "InternalHRSuite", "medium"),
    ("APP-008", "MarketDataFeed", "medium"),
    ("APP-009", "DevOpsTooling", "low"),
    ("APP-010", "DocArchiveService", "low"),
]
OWNERS = ["alice.tan", "ravi.kumar", "meiling.chua", "john.lee", "priya.nair"]

applications = [
    {"id": app_id, "name": name, "business_criticality": crit,
     "owner": OWNERS[i % len(OWNERS)]}
    for i, (app_id, name, crit) in enumerate(APP_DEFS)
]

# ---------------------------------------------------------------- license rules
PERMISSIVE = ["MIT", "Apache-2.0", "BSD-3-Clause", "BSD-2-Clause", "ISC",
              "Unlicense", "Zlib"]
WEAK_COPYLEFT = ["LGPL-2.1", "LGPL-3.0", "MPL-2.0", "EPL-2.0", "CDDL-1.0"]
STRONG_COPYLEFT = ["GPL-2.0", "GPL-3.0", "AGPL-3.0"]

license_rules = []
for lic in PERMISSIVE:
    license_rules.append({
        "license_type": lic,
        "compatible_with": ["Proprietary", "MIT", "Apache-2.0", "GPL-3.0",
                            "LGPL-3.0", "MPL-2.0"],
        "risk_level": "low",
    })
for lic in WEAK_COPYLEFT:
    license_rules.append({
        "license_type": lic,
        "compatible_with": ["MIT", "Apache-2.0", "GPL-3.0", "LGPL-3.0",
                            "MPL-2.0"],
        "risk_level": "medium",
    })
for lic in STRONG_COPYLEFT:
    license_rules.append({
        "license_type": lic,
        "compatible_with": ["GPL-3.0", "AGPL-3.0"],
        "risk_level": "high",
    })
assert len(license_rules) == 15

# ---------------------------------------------------------------- library pools
def make_pool(prefix, names, n):
    pool = list(names)
    i = 1
    while len(pool) < n:
        pool.append(f"{prefix}-{i:02d}")
        i += 1
    return pool[:n]

# Disjoint pools so a library's role (and license) is globally consistent.
POOL_VULN = make_pool("vlib", [
    "log4shell-core", "openssl-py", "urllib3", "pyyaml", "pillow", "jinja2",
    "cryptolib", "xml-parser", "http-agent", "zip-utils", "serde-json",
    "auth-token", "img-magick", "net-sock", "db-driver"], 30)
POOL_TRANS = make_pool("tlib", [
    "deep-base64", "tls-shim", "buffer-kit", "regex-engine", "yaml-loader",
    "proto-wire", "mem-alloc", "chrono-util"], 18)
POOL_LIC = make_pool("gpl-lib", [
    "readline-gnu", "gnu-plotter", "copyleft-orm", "agpl-queue",
    "gpl-crypto", "gnu-tables"], 15)
POOL_UNMAINT = make_pool("stale", [
    "legacy-soap", "old-ftp", "ancient-xmlrpc", "py2-compat", "flash-bridge",
    "deprecated-auth"], 25)
POOL_CLEAN = make_pool("lib", [
    "requests", "flask", "numpy", "pandas", "click", "rich", "pytest",
    "sqlalchemy", "pydantic", "httpx", "boto3", "redis-py", "celery",
    "gunicorn", "uvicorn", "fastapi", "typer", "attrs", "orjson",
    "structlog"], 60)

LIB_LICENSE = {}
for lib in POOL_VULN + POOL_TRANS + POOL_UNMAINT + POOL_CLEAN:
    LIB_LICENSE[lib] = random.choice(PERMISSIVE)
for lib in POOL_LIC:
    LIB_LICENSE[lib] = random.choice(STRONG_COPYLEFT)

def ver():
    return f"{random.randint(0, 4)}.{random.randint(0, 12)}.{random.randint(0, 20)}"

# Each vulnerable-pool library gets one fixed "bad version" that its CVE(s)
# affect; SBOM rows for that lib always use the bad version.
BAD_VERSION = {lib: ver() for lib in POOL_VULN + POOL_TRANS}
SAFE_VERSION = {lib: ver() for lib in POOL_LIC + POOL_UNMAINT + POOL_CLEAN}

def recent_date():
    return TODAY - timedelta(days=random.randint(15, 330))

def stale_date():
    return TODAY - timedelta(days=random.randint(620, 1400))  # 20+ months

# ---------------------------------------------------------------- SBOM + labels
# Per app (50 rows): 9 vulnerable, 6 license_conflict, 8 or 7 unmaintained
# (alternating -> 75 total), 5 transitive_vulnerability, rest clean.
sbom_rows, label_rows = [], []
SEV = lambda cvss: ("critical" if cvss >= 9 else "high" if cvss >= 7
                    else "medium" if cvss >= 4 else "low")
CVSS_FOR = {lib: round(random.uniform(4.0, 10.0), 1) for lib in POOL_VULN + POOL_TRANS}

for ai, app in enumerate(applications):
    app_id = app["id"]
    n_unmaint = 8 if ai % 2 == 0 else 7
    picks = {
        "vulnerable": random.sample(POOL_VULN, 9),
        "license_conflict": random.sample(POOL_LIC, 6),
        "unmaintained": random.sample(POOL_UNMAINT, n_unmaint),
        "transitive_vulnerability": random.sample(POOL_TRANS, 5),
        "clean": random.sample(POOL_CLEAN, 50 - 9 - 6 - n_unmaint - 5),
    }
    for risk_type, libs in picks.items():
        for lib in libs:
            if risk_type in ("vulnerable", "transitive_vulnerability"):
                version, last_upd = BAD_VERSION[lib], recent_date()
                is_direct = risk_type == "vulnerable"
                is_risky, severity = True, SEV(CVSS_FOR[lib])
                expl = f"{lib}@{version} matches a CVE in vulnerability_db"
                if not is_direct:
                    expl += " via a transitive path"
            elif risk_type == "license_conflict":
                version, last_upd, is_direct = SAFE_VERSION[lib], recent_date(), True
                is_risky, severity = True, "high"
                expl = (f"{LIB_LICENSE[lib]} is incompatible with proprietary "
                        f"distribution per license_rules")
            elif risk_type == "unmaintained":
                version, last_upd = SAFE_VERSION[lib], stale_date()
                is_direct = random.random() < 0.7
                is_risky, severity = True, "medium"
                expl = f"no update since {last_upd.isoformat()} (>18 months)"
            else:
                version, last_upd = SAFE_VERSION[lib], recent_date()
                is_direct = random.random() < 0.6
                is_risky, severity, expl = False, "none", "no known risk"
            sbom_rows.append({
                "app_id": app_id, "library_name": lib, "version": version,
                "license_type": LIB_LICENSE[lib], "is_direct": is_direct,
                "last_updated": last_upd.isoformat(),
            })
            label_rows.append({
                "app_id": app_id, "library_name": lib, "is_risky": is_risky,
                "risk_type": risk_type if is_risky else "clean",
                "severity": severity, "explanation": expl,
            })

assert len(sbom_rows) == 500 and len(label_rows) == 500

# ---------------------------------------------------------------- vulnerability db
vulns, cve_n = [], 1000
for lib in POOL_VULN + POOL_TRANS:
    vulns.append({
        "cve_id": f"CVE-2025-{cve_n}", "affected_library": lib,
        "affected_versions": [BAD_VERSION[lib]],
        "cvss_score": CVSS_FOR[lib], "has_patch": random.random() < 0.55,
    })
    cve_n += 1
# Filler CVEs: real-looking noise the matcher must NOT flag — either a
# library absent from every SBOM, or a version no SBOM row uses.
decoy_libs = [f"decoy-lib-{i:03d}" for i in range(1, 121)]
for lib in decoy_libs:
    vulns.append({
        "cve_id": f"CVE-2024-{cve_n}", "affected_library": lib,
        "affected_versions": [ver()],
        "cvss_score": round(random.uniform(2.0, 9.9), 1),
        "has_patch": random.random() < 0.5,
    })
    cve_n += 1
for lib in random.sample(POOL_CLEAN, 200 - len(vulns)):
    wrong = ver()
    while wrong == SAFE_VERSION[lib]:
        wrong = ver()
    vulns.append({
        "cve_id": f"CVE-2023-{cve_n}", "affected_library": lib,
        "affected_versions": [wrong],  # version NOT used in any SBOM row
        "cvss_score": round(random.uniform(2.0, 9.9), 1),
        "has_patch": True,
    })
    cve_n += 1
assert len(vulns) == 200

# ---------------------------------------------------------------- write files
(OUT / "applications.json").write_text(json.dumps(applications, indent=2))
(OUT / "vulnerability_db.json").write_text(json.dumps(vulns, indent=2))
(OUT / "license_rules.json").write_text(json.dumps(license_rules, indent=2))

with open(OUT / "sbom_dependencies.csv", "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=list(sbom_rows[0]))
    w.writeheader()
    w.writerows(sbom_rows)
with open(OUT / "dependency_labels.csv", "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=list(label_rows[0]))
    w.writeheader()
    w.writerows(label_rows)

from collections import Counter
dist = Counter(r["risk_type"] for r in label_rows)
print(f"Wrote placeholder dataset to {OUT}")
print(f"  applications: {len(applications)}  sbom rows: {len(sbom_rows)}  "
      f"CVEs: {len(vulns)}  license rules: {len(license_rules)}  "
      f"labels: {len(label_rows)}")
print("  label distribution:",
      {k: f"{v} ({v / 5:.0f}%)" for k, v in sorted(dist.items())})
