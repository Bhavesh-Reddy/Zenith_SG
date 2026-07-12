# Problem 11: Policy Conflict & Staleness Detector

**Track:** Policy Governance  
**Difficulty:** Intermediate

## Enterprise Challenge
Security policies written by different teams over different years contradict each other, and nobody notices until an auditor does.

## The Business Problem
**Scenario:** A large enterprise has accumulated 30 security and compliance policies over the past 5 years, authored by different teams.

- IT Security wrote the Password Policy (2021)
- Cloud Engineering wrote the Cloud Security Policy (2024)
- Compliance wrote the Data Classification Policy (2022)
- HR wrote the Acceptable Use Policy (2020)
- Legal wrote the Data Retention Policy (2023)
- Infrastructure wrote the Network Security Policy (2021)

One day, an external auditor discovers the following contradiction:
- The **Password Policy** says: `rotate passwords every 90 days`
- The **Cloud Security Policy** says: `do not rotate passwords; enforce MFA instead`
- Both are active and approved.

This is not an isolated incident. Across 30 policies, hidden conflicts, redundant rules, and outdated content create real governance risk.

### Pain Points
- Contradictory requirements confuse employees and create compliance gaps.
- Multiple policies say the same thing in different words, increasing maintenance burden.
- Policies written 3+ years ago may reference deprecated technologies or outdated regulations.
- Language strength varies between `must`, `should`, and `recommended`.
- Policies are managed in silos and not reviewed holistically.
- Conflicting policies become audit findings.

### Real Impact
- Employees may follow whichever policy they find first.
- Conflicting policies violate `ISO 27001 A.5.1`.
- Teams spend 20+ hours per quarter resolving disputes.
- Inconsistent data retention rules create GDPR and SOX risk.

## Challenge Overview
Build a system that:
1. Ingests policy documents provided as text or markdown.
2. Extracts obligations using NLP from `must`, `shall`, `required`, and prohibited statements.
3. Builds a policy graph linking related obligations across documents.
4. Detects conflicts on the same topic.
5. Identifies redundancies and overlaps.
6. Flags stale policies not updated in 18+ months or referencing deprecated items.
7. Outputs a policy health report with prioritized findings.

## Data Reality & Edge Cases
### Language Ambiguity
- `Must` vs `should` vs `recommended` vs `expected`
- `Passwords must be rotated` vs `Credential refresh cycles shall be enforced`
- Passive voice such as `Encryption is to be applied`
- Implicit obligations such as `The company follows NIST 800-53`

### Scope Complexity
- Two policies may seem to conflict but apply to different scopes.
  - `All employees must use VPN`
  - `Developers may bypass VPN for CI/CD pipelines`
- Geographic scope differences such as EU-only requirements.
- System-specific exceptions such as cloud exemptions from on-prem policies.

### Conflict Nuances
- Direct conflict: do X vs do not do X
- Temporal conflict: retain 7 years vs delete after 3 years
- Strength conflict: must encrypt vs should encrypt
- Partial overlap: one policy subsumes another

### Staleness Indicators
- Last review date older than 18 months
- Deprecated technologies such as `TLS 1.0`, `SHA-1`, or `Windows Server 2012`
- Superseded regulations or standards
- Owner no longer with the organization
- No version history or changelog

### Ambiguous Scenarios Your System Must Handle
- `Data must be retained for 7 years` vs `Personal data must be deleted upon request`
- `All systems must use MFA` vs an older `Systems must use strong passwords`
- `NIST SP 800-53 Rev 4` references after Rev 5 has been out for years
- Two identical encryption requirements: redundancy or intentional reinforcement?

## Approach Options
### Option A: LLM-Powered Policy Intelligence
**Best for:** Teams with NLP or LLM experience

**Technical approach**
- Use an LLM to extract structured obligations from free text.
- Build semantic embeddings to find related or overlapping obligations.
- Use LLM reasoning to classify pairs as `CONFLICT`, `REDUNDANT`, `COMPLEMENTARY`, or `UNRELATED`.
- Generate natural-language explanations for conflicts.
- Build a policy knowledge graph with obligations as nodes and relationships as edges.
- Output an interactive dashboard with remediation suggestions.

**Example extraction**
```json
{
  "obligation": "rotate_password",
  "frequency": "90_days",
  "scope": "all_employees",
  "strength": "mandatory"
}
```

**Stack:** Python, LLM APIs, embeddings, NetworkX, visualization  
**Complexity:** 4/5  
**Effort:** 30–40 hours

### Option B: Rule-Based NLP & Graph Analysis
**Best for:** Backend engineers and data-focused teams

**Technical approach**
- Parse policy documents using regex and NLP such as spaCy.
- Identify obligation keywords like `must`, `shall`, `required`, `prohibited`, and `may not`.
- Categorize obligations by topic using keyword matching and TF-IDF.
- Build an obligation graph using NetworkX.
- Apply rule-based conflict detection for opposite actions, parameter mismatches, and duplicates.
- Flag stale policies using metadata and reference checks.

**Typical topics**
- `password`
- `encryption`
- `access_control`
- `data_retention`
- `logging`
- `network`

**Stack:** Python, spaCy/NLTK, NetworkX, regex, basic web UI  
**Complexity:** 3/5  
**Effort:** 20–30 hours

### Option C: Simple Policy Scanner
**Best for:** Full-stack developers new to NLP

**Technical approach**
- Build a web app to upload policy documents.
- Extract `must`, `shall`, and `required` sentences with regex.
- Group obligations by manually defined categories or keyword match.
- Detect conflicts when the same category contains opposing obligations.
- Compare `last_reviewed` against an 18-month staleness threshold.
- Generate HTML or PDF policy health reports with traffic-light indicators.

**Stack:** Python (Flask/FastAPI), regex, HTML/CSS, basic NLP  
**Complexity:** 2/5  
**Effort:** 15–20 hours

## Example Walkthrough
### Input: Two Policy Excerpts
```text
--- Password Policy (v2.1, Last Reviewed: 2021-08-15) ---
Section 3.1: All employees must rotate their passwords every 90 days.
Section 3.2: Passwords must be at least 12 characters with uppercase,
lowercase, numbers, and special characters.
Section 3.3: Previous 10 passwords may not be reused.

--- Cloud Security Policy (v1.0, Last Reviewed: 2024-11-20) ---
Section 5.1: All cloud-hosted systems must enforce multi-factor
authentication (MFA) for all user accounts.
Section 5.2: Password rotation shall not be required for cloud systems;
MFA replaces the need for periodic credential changes.
Section 5.3: Service accounts must use API keys with automatic rotation
every 365 days.
```

### Expected Output
```json
{
  "findings": [
    {
      "finding_type": "CONFLICT",
      "severity": "HIGH",
      "policy_a": "Password Policy §3.1",
      "policy_b": "Cloud Security Policy §5.2",
      "description": "Password Policy requires 90-day password rotation for ALL employees, but Cloud Security Policy explicitly prohibits password rotation for cloud systems, relying on MFA instead.",
      "scope_analysis": "Conflict applies to employees accessing cloud-hosted systems (estimated 80% of workforce).",
      "recommendation": "Harmonize policies: Update Password Policy to exempt cloud systems with MFA, or update Cloud Security Policy to allow rotation as defense-in-depth.",
      "compliance_impact": ["ISO 27001 A.5.1", "NIST IA-5"]
    },
    {
      "finding_type": "STALE",
      "severity": "MEDIUM",
      "policy": "Password Policy v2.1",
      "description": "Last reviewed on 2021-08-15 — over 4 years ago. References password complexity requirements that may conflict with updated NIST SP 800-63B guidance (which discourages forced rotation).",
      "recommendation": "Schedule immediate policy review. Consider aligning with NIST 800-63B (2024) which recommends against periodic rotation.",
      "compliance_impact": ["NIST IA-5", "ISO 27001 A.9.4"]
    },
    {
      "finding_type": "PARTIAL_REDUNDANCY",
      "severity": "LOW",
      "policy_a": "Password Policy §3.2",
      "policy_b": "Cloud Security Policy §5.1",
      "description": "Both policies address authentication strength but using different mechanisms (complexity vs MFA). Not a conflict, but overlapping governance creates confusion about which control is primary.",
      "recommendation": "Cross-reference policies and clarify which authentication control applies where."
    }
  ],
  "policy_health_score": {
    "password_policy": 42,
    "cloud_security_policy": 78,
    "overall": 60
  }
}
```

## Sample Data Required
| File | Records | Coverage | Description |
| --- | ---: | --- | --- |
| `policies/` | 30 documents | Full corpus | Markdown or text files covering security, privacy, access, data, network, cloud, HR, and more |
| `policy_metadata.csv` | 30 | All policies | Title, author, department, version, `last_reviewed`, status |
| `obligation_extracts_labels.csv` | 350 | Extracted obligations | Ground truth for obligation text, topic, strength, and scope |
| `findings_labels.csv` | 80 | Known issues | Ground truth for finding type, severity, involved policies, and explanation |

### Issue Distribution in Labels
- Direct conflicts: ~15
- Partial conflicts: ~10
- Redundancies: ~20
- Stale policies: ~12
- Stale references: ~8
- False-positive-prone pairs: ~15

## Self-Evaluation
```python
import pandas as pd
from sklearn.metrics import precision_score, recall_score, f1_score

labels = pd.read_csv('findings_labels.csv')
# labels['predicted_finding'] = your_detector.predict(policy_pairs)

y_true = labels['is_finding'].astype(int)
y_pred = labels['predicted_finding'].astype(int)

print(f"Precision: {precision_score(y_true, y_pred):.2%}")
print(f"Recall:    {recall_score(y_true, y_pred):.2%}")
print(f"F1 Score:  {f1_score(y_true, y_pred):.2f}")
# Target: Precision > 70%, Recall > 65%
```

> High precision is critical here. False conflict alerts erode trust with policy owners.

## Success Criteria
| Metric | Target | Why |
| --- | --- | --- |
| Conflict Detection Rate | >75% | Catch real contradictions |
| Redundancy Detection | >70% | Identify duplicate governance overhead |
| Staleness Detection | >90% | Easy to detect and should be comprehensive |
| False Positive Rate | <20% | Policy owners must trust findings |
| Obligation Extraction | >80% accuracy | Foundation for downstream analysis |

## Deliverables
- Policy ingestion engine for markdown and text documents.
- Obligation extractor.
- Policy graph with topic, scope, and relationship links.
- Conflict detector with explanations.
- Redundancy finder.
- Staleness checker.
- Policy health report with per-policy and overall scores.
- Dashboard for graph visualization, browsing findings, and severity filters.

## Framework Alignment
### ISO 27001
- `A.5.1`: Policies for Information Security
- `A.5.2`: Review of Policies

### NIST SP 800-53
- `PL-1`: Policy and Procedures
- `PM-1`: Information Security Program Plan

### GDPR
- `Article 24`: Responsibility of the Controller
- `Article 5`: Principles of Processing

### COBIT 2019
- `APO01.03`: Maintain Policy Framework

## Bonus Features
### Level 1: Implementation Bonus
- Interactive policy graph visualization
- Side-by-side conflict view
- Policy review scheduler
- Export findings to PDF or Excel

### Level 2: Advanced Intelligence
- Semantic similarity scoring for near-duplicate detection
- Scope-aware conflict resolution
- Policy change impact analysis
- Automated policy harmonization suggestions

### Level 3: Enterprise Features
- Version diff analysis
- Regulatory mapping to GDPR, NIST, and ISO clauses
- Organization-wide policy coverage analysis
- Natural language policy query interface
