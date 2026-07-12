# Problem 10 – Software Supply Chain Risk Scorer (SBOM Analyzer)

**Track:** Third-Party & Software Risk  **Difficulty:** Intermediate–Advanced

## Enterprise Challenge

Log4j shocked the world—organizations had no idea which applications used the vulnerable library. Software supply chains are invisible attack surfaces.

## The Business Problem

**Scenario:** A development team maintains 10 enterprise applications, each depending on 50+ open-source libraries. One day, a critical vulnerability (like Log4j CVE-2021-44228) is announced. The security team faces immediate chaos:

- Which applications use the vulnerable library?
- Is the vulnerable function actually called in our code?
- Are there transitive dependencies hiding the risk (App A → Library B → Vulnerable Library C)?
- Do any of these libraries have expired or incompatible licenses?
- Which libraries haven't been updated in years and pose maintenance risk?

### The Pain Points

- **No Visibility:** No centralized inventory of software dependencies across applications
- **Manual Tracking:** Developers maintain spreadsheets (often outdated) of their dependencies
- **Transitive Blindness:** Direct dependencies are tracked, but nested dependencies are invisible
- **License Confusion:** GPL libraries accidentally included in proprietary products
- **Unmaintained Risk:** Libraries with no updates in 2+ years silently accumulate vulnerabilities
- **Slow Response:** When vulnerabilities emerge, it takes days to identify affected applications

### Real Impact

- **Risk:** A single vulnerable transitive dependency can expose multiple production systems
- **Compliance:** License violations can result in legal action (GPL in commercial software)
- **Operational Cost:** 40+ hours per vulnerability incident spent on manual dependency tracing
- **Reputation:** Public disclosure of using vulnerable/unmaintained libraries damages trust

## Challenge Overview

Build an automated SBOM (Software Bill of Materials) analysis tool that:

- Ingests SBOMs from multiple applications (JSON/CSV format)
- Cross-references dependencies against a vulnerability database (simulated NVD)
- Resolves transitive dependencies (A → B → C vulnerability chains)
- Checks license compatibility and flags conflicts (e.g., GPL in proprietary code)
- Identifies unmaintained libraries (no updates in 2+ years)
- Computes a per-application software supply chain risk score
- Outputs a ranked risk report with remediation priorities

## Data Reality & Edge Cases (Making it Complex)

Your solution must handle real-world dependency chaos.

### Transitive Dependency Complexity

- App uses Library A (safe) → Library A depends on Library B (safe) → Library B depends on Library C (VULNERABLE)
- Multiple paths to the same vulnerable library
- Version conflicts
- Diamond dependencies

### Vulnerability Context

- Not all CVEs are equal
- Exploitability matters
- Patch availability varies
- False positives exist

### License Complexity

- GPL viral licenses
- LGPL nuances
- Dual licensing
- Unknown licenses

### Maintenance Risk

- Abandoned projects
- Low bus factor
- No security policy

### Ambiguous Scenarios

- CVE with patch
- Old but clean library
- Internal-only GPL usage
- Shared dependencies

## Approach Options

### Option A: AI-Powered Supply Chain Intelligence (Advanced)

Uses graphs, ML, and LLMs for deep analysis.

### Option B: Graph-Based Dependency Analysis (Intermediate)

Dependency graphs and rules-based scoring.

### Option C: Simple SBOM Scanner (Beginner–Intermediate)

Basic parsing, rules, and reporting.

## Sample Data Provided

| File | Records | Coverage | Description |
|------|--------:|----------|-------------|
| applications.json | 10 | Application inventory | App metadata, criticality, owner |
| sbom_dependencies.csv | 500 | 10×50 | Library details |
| vulnerability_db.json | 200 | Simulated NVD | CVEs and scores |
| license_rules.json | 15 | License compatibility | Rules and risk |
| dependency_labels.csv | 500 | All deps | Ground truth labels |

## Success Criteria

| Metric | Target | Why |
|-------|--------|-----|
| Vulnerability Detection | >85% | Catch known CVEs |
| Transitive Resolution | 100% | No hidden risks |
| License Conflict Detection | >90% | Prevent legal exposure |
| False Positive Rate | <20% | Avoid noise |
| Risk Score Accuracy | ±10% | Reliable prioritization |

## Deliverables

- SBOM Parser
- Vulnerability Matcher
- Dependency Graph Builder
- License Checker
- Maintenance Analyzer
- Risk Scoring Engine
- Dashboard / Report Generator

## Framework Alignment

- **NIST CSF:** ID.SC-2, PR.DS-6, DE.CM-8
- **OWASP:** A06:2021
- **Executive Order 14028:** SBOM requirements
- **OpenSSF Scorecard**

## Bonus Features (Challenge Yourself!)

### Level 1

- Real-time ingestion
- Graph visualization
- CVE alerts
- SPDX/CycloneDX export

### Level 2

- Reachability analysis
- Automated PRs
- Library alternatives
- Risk trends

### Level 3

- Multi-language support
- CI/CD integration
- Org-wide inventory
- Supply chain attack simulation
