# Phase 5 — Edge-Case Injection Results

Five hand-crafted scenarios from the PB-10 brief, each run through the **real deterministic core** (graph build → path enumeration → CVE match → license engine → findings). This fixture is isolated: it is never loaded by ingestion, never scored by the ML layer, and never counted in self-eval.

| # | Scenario | Result |
|---|---|---|
| 1 | Critical CVE with an available patch is flagged but the patch is noted | ✅ PASS |
| 2 | Unmaintained library with zero CVEs is still flagged for maintenance risk | ✅ PASS |
| 3 | GPL in an internal-only app is an advisory, not a distribution conflict | ✅ PASS |
| 4 | Same vulnerable library in two apps = compound exposure, not deduplicated | ✅ PASS |
| 5 | Genuine diamond dependency reports BOTH converging paths | ✅ PASS |

## Detail

### 1. Critical CVE with an available patch is flagged but the patch is noted — PASS
- **Expected:** one VULNERABLE_DEPENDENCY finding whose evidence records patch_available=true and fixed_version, so downstream ranking/narrative can de-emphasise it
- **Observed:** finding=yes, patch_available=True, fixed_version=3.0.0

### 2. Unmaintained library with zero CVEs is still flagged for maintenance risk — PASS
- **Expected:** exactly one UNMAINTAINED finding (no vulnerability finding), classified UNMAINTAINED
- **Observed:** finding_types=['UNMAINTAINED'], primary_class=UNMAINTAINED

### 3. GPL in an internal-only app is an advisory, not a distribution conflict — PASS
- **Expected:** internal-only -> LICENSE_ADVISORY (advisory_only, not classified as risky); same GPL lib in a proprietary app -> LICENSE_CONFLICT
- **Observed:** internal=['LICENSE_ADVISORY'] (class NONE), proprietary=['LICENSE_CONFLICT'] (class LICENSE_CONFLICT)

### 4. Same vulnerable library in two apps = compound exposure, not deduplicated — PASS
- **Expected:** two independent VULNERABLE_DEPENDENCY findings, one per application
- **Observed:** findings=2, apps=['EDGE-A', 'EDGE-B']

### 5. Genuine diamond dependency reports BOTH converging paths — PASS
- **Expected:** one TRANSITIVE_VULNERABILITY finding with num_paths=2 and both distinct chains
- **Observed:** num_paths=2, paths=[['EDGE-PROP', 'auth-module', 'log-lib'], ['EDGE-PROP', 'web-framework', 'log-lib']]
