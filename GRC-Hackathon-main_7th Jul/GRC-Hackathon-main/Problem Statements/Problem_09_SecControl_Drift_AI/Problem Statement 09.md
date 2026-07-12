# Problem 09: Security Control Drift & Misconfiguration Detection Across Enterprise Systems

**Track:** Configuration Governance & Risk Management  
**Difficulty:** Intermediate–Advanced

## Enterprise Challenge
Silent control drift causes real breaches. Do you detect risk as configurations change, or only after damage is done?

## The Business Problem
**Scenario:** An enterprise operates 200+ security controls spanning cloud infrastructure, on-prem firewalls and switches, endpoint agents, and identity platforms. Each control has a defined baseline such as encryption strength, logging state, firewall rules, or access policies. But every day, deployments, hotfixes, scaling events, and manual interventions change these configurations. When a change weakens a control and nobody notices, that silent drift becomes the breach vector.

> This problem focuses on **cross-system drift correlation and attack-path impact**. Problem 02 covers configuration drift detection within individual systems.

### Real Incidents
- **Case 1:** An auto-deploy pipeline downgraded database encryption from `AES-256` to `AES-128` during a routine release. The change was whitelisted and went unnoticed for 4 months.
- **Case 2:** An engineer disabled CloudTrail logging at 2:47 AM to reduce noise during debugging and forgot to re-enable it. An attacker exfiltrated data from S3 during the 14-hour blind spot.
- **Case 3:** A firewall rule was broadened to allow port `8080` temporarily for a vendor integration and remained open for two years.
- **Case 4:** An endpoint agent was silently disabled on 30 servers after a patch conflict, while posture dashboards still showed the agent as installed.

### The Pain
- Teams can detect diffs, but struggle to separate safe change from dangerous drift.
- Frequent CI/CD and autoscaling changes create low-value alert volume.
- Control context is fragmented across cloud, endpoint, and network platforms.
- Audit and compliance mapping is manual and slows remediation.
- Multiple weak drifts can combine into a larger attack path.
- Temporary changes become permanent when nobody tracks revert deadlines.

### Real Impact
- Misconfigurations remain active longer and extend exposure windows.
- False positives reduce trust and delay response.
- Audit findings increase because drift lacks clear evidence narratives.
- Combined drift across domains creates exposure invisible to single-control tools.

### Compliance Impact
- `NIST CM-2/CM-3`: Baseline configuration and change control must be continuously enforced.
- `NIST SI-4`: Continuous monitoring must detect drift, not just presence.
- `GDPR Article 32`: Configurations must remain compliant.
- `GDPR Article 25`: Drift undermines protection by design.
- `CIS Benchmarks`: Security configuration management across cloud, endpoint, and network.

## Challenge Overview
Build a system to:
1. Ingest and normalize control state from multiple domains.
2. Learn baseline control configurations across environments.
3. Detect and prioritize security-impacting drift in near real time.
4. Correlate drift signals across domains to identify compound exposure paths.
5. Map misconfigurations to compliance controls such as CIS, NIST, and GDPR.
6. Produce explainable remediation guidance with sequenced priorities.

## Data Reality & Edge Cases
### Change Classification Complexity
- CI/CD deployments change configs constantly.
- Approved temporary changes may never revert.
- Maintenance window changes may not be restored.
- Autoscaling events can modify security groups and create noise.
- Emergency bypass changes may have no approval trail.

### Cross-Domain Ambiguity
- Logging disabled plus firewall broadened in the same window: coincidence or coordinated attack?
- Encryption downgraded by pipeline with no change ticket: automation bug or insider risk?
- Endpoint agent reports installed but process not running.
- Vendors use different names for equivalent controls.

### Temporal Challenges
- Configs change 100+ times daily and most are benign.
- Historical data may be incomplete.
- Drift may have happened weeks ago but only be detected during quarterly review.
- A 1-week temporary change may still exist 6 months later.

### Ambiguous Scenarios Your System Must Handle
- Port `8080` opened: dangerous or justified?
- `AES-256` to `AES-128`: always risky, or acceptable in test?
- Logging disabled for 2 hours at 3 AM: debugging or cover-up?
- 30 endpoint agents stopped after patch: conflict or defense evasion?

## Approach Options
### Option A: ML-Driven Cross-Domain Drift Intelligence
**Best for:** ML engineers and cloud security architects

**Technical approach**
- Simulate control state snapshots and change events across 3–4 domains.
- Define baseline templates per control type and environment.
- Extract features such as severity delta, approval status, time of day, actor history, and environment criticality.
- Train anomaly detection on labeled benign changes.
- Correlate drift across domains using time-window, actor, and system grouping.
- Estimate blast radius and generate LLM-powered analyst narratives.

**Stack:** Python, scikit-learn, NetworkX, LLM API, Pandas, Plotly  
**Complexity:** 4/5  
**Effort:** 35–45 hours

### Option B: Baseline Comparison + Risk Heuristics
**Best for:** DevSecOps teams and security analysts

**Technical approach**
- Generate simulated baselines and change streams for 2–3 domains.
- Define policy templates in JSON or YAML.
- Compare current versus baseline and compute drift severity using rule weights.
- Suppress benign changes using change tickets, maintenance windows, pipeline context, and autoscaler identity.
- Score each event with environment criticality and suppression discounts.
- Map each drift to compliance controls and output a prioritized queue.

**Suggested rule weights**
- `Logging disabled` → `CRITICAL` (10)
- `Encryption downgraded` → `HIGH` (8)
- `Firewall rule broadened` → `MEDIUM` (5)
- `Timeout increased` → `LOW` (2)

**Stack:** Python, Pandas, rule engine, SQL/SQLite, Plotly  
**Complexity:** 3/5  
**Effort:** 25–35 hours

### Option C: Compliance-Centric Drift Checker
**Best for:** GRC teams and full-stack beginners

**Technical approach**
- Create a small simulated dataset of 100–200 control states and 300–500 change events.
- Define simple JSON baselines.
- Build a checker that marks each control as pass, fail, or degraded.
- Apply deterministic alert rules.
- Build a web dashboard with scorecards, severity-sorted drift list, and export.

**Stack:** Python (Flask/FastAPI), SQLite, CSV/JSON ingestion, HTML/CSS/JS  
**Complexity:** 2/5  
**Effort:** 15–25 hours

## Sample Data Required
Participants must simulate control configurations and change events across multiple domains.

| Source | Records (suggested) | Description |
| --- | ---: | --- |
| Baseline configs | 50–100 | Control baselines per domain: firewall rules, logging state, encryption settings, endpoint agent status, access policies |
| Change events | 500–1,000 | Timestamped changes with `control_id`, parameter, old/new value, actor, approval status, and source |
| Control metadata | 50–100 | Control-to-compliance mapping for NIST, CIS, and GDPR |
| Maintenance windows | 20–50 | Scheduled maintenance periods with approved change scope |

### Expected Anomaly Mix
- Critical drift: ~5–8%
- High-risk drift: ~8–12%
- Medium-risk drift: ~10–15%
- Benign changes: ~40–50%
- Ambiguous changes: ~10–15%
- Normal state: ~10–20%

## Self-Evaluation
```python
import pandas as pd
from sklearn.metrics import classification_report

labels = pd.read_csv('drift_event_labels.csv')
# labels['predicted_risky'] = your_detector.predict(change_events)

y_true = labels['is_risky'].astype(int)
y_pred = labels['predicted_risky'].astype(int)

print(classification_report(y_true, y_pred, target_names=['Benign', 'Risky Drift']))

critical = labels[labels['severity'] == 'CRITICAL']
print(f"Critical drift recall: {labels.loc[critical.index]['predicted_risky'].mean():.2%}")

benign = labels[labels['is_risky'] == False]
print(f"Benign suppression rate: {1 - labels.loc[benign.index]['predicted_risky'].mean():.2%}")
# Target: Precision > 75%, Recall > 70%, Critical recall > 95%, Benign suppression > 85%
```

## Sample Records
### Sample Baseline Config
```json
{
  "control_id": "LOG-012",
  "domain": "cloud",
  "system": "AWS CloudTrail",
  "parameter": "cloudtrail_enabled",
  "baseline_value": true,
  "environment": "production",
  "severity_if_drifted": "CRITICAL",
  "compliance_mappings": ["NIST AU-2", "NIST CM-3", "CIS 8.5"]
}
```

### Sample Change Event
```json
{
  "event_id": "drift-evt-7c2a",
  "timestamp": "2026-04-08T02:47:00Z",
  "control_id": "LOG-012",
  "action": "modification",
  "parameter": "cloudtrail_enabled",
  "baseline_value": true,
  "current_value": false,
  "changed_by": "admin_003",
  "change_source": "manual",
  "approval_status": "pending",
  "environment": "production",
  "maintenance_window": false
}
```

### Sample Compound Drift Scenario
```json
[
  {"timestamp": "2026-04-08T02:47:00Z", "control_id": "LOG-012", "drift": "cloudtrail disabled", "domain": "cloud"},
  {"timestamp": "2026-04-08T03:15:00Z", "control_id": "FW-001", "drift": "port 8080 opened", "domain": "network"},
  {"timestamp": "2026-04-08T03:22:00Z", "control_id": "ENC-044", "drift": "AES-256 → AES-128", "domain": "cloud"}
]
```

## Success Criteria
| Metric | Target | Why |
| --- | --- | --- |
| Control Coverage | ≥95% controls continuously evaluated | Minimize unmanaged configuration risk |
| Drift Detection Timeliness | Near real time | Reduce exposure window |
| Critical Drift Recall | >95% critical drifts caught | Never miss logging or encryption failures |
| False Positive Rate | <15% | Escalate only risk-relevant drift |
| Cross-Domain Correlation | Compound incidents identified | Surface attack paths, not isolated changes |
| Compliance Mapping | CIS / NIST / GDPR correlation | Translate drift into regulatory risk |
| Operational Efficiency | ≥50% reduction in manual reviews | Enable sustainable governance operations |

## Deliverables
- Working prototype with simulated multi-domain control data and a data dictionary.
- Baseline configuration store in JSON format.
- Drift detection engine.
- Benign change suppression logic.
- Cross-domain incident correlator.
- Dashboard with control health heatmap, drift timeline, compound incidents, and compliance impact.
- Architecture documentation and explanation of AI or ML approach.
- Sample drift report with 5–10 detected risky drifts and compliance mappings.

## Framework Alignment
### NIST SP 800-53
- `CM-2`: Baseline Configuration
- `CM-3`: Configuration Change Control
- `CM-6`: Configuration Settings
- `SI-4`: Information System Monitoring

### CIS Benchmarks
- Security Configuration Management across cloud, endpoint, and network
- Continuous Monitoring and Remediation

### MITRE ATT&CK
- `T1562`: Impair Defenses
- `T1556`: Modify Authentication Process
- `T1036`: Masquerading

### GDPR
- `Article 32`: Security of Processing
- `Article 25`: Data Protection by Design

## Expected Output Example
```text
CONTROL DRIFT SUMMARY — 2026-04-15
=====================================
Period: 2026-01-01 to 2026-04-15
Total Controls Monitored: 200
Total Changes Detected: 8,420
Risky Drift Events: 47 (0.6%)

HIGH RISK DRIFTS (Require Immediate Action)

1. LOG-012: CloudTrail logging disabled
   Changed: 2026-04-08 02:47 UTC by admin_003
   Baseline: enabled → Current: disabled
   Exposure: 14 hours before detection
   MITRE: T1562.008 (Disable Cloud Logs)
   Compliance: NIST AU-2, CIS 8.5
   Action: Re-enable immediately, audit activity during blind period

2. ENC-044: Database encryption downgraded
   Changed: 2026-04-10 by auto-deploy pipeline
   Baseline: AES-256 → Current: AES-128
   MITRE: T1600 (Weaken Encryption)
   Compliance: NIST SC-13, GDPR Article 32
   Action: Restore AES-256, review pipeline config
```

### Example Walkthrough
**Input: Configuration Change Event**
```json
{
  "timestamp": "2026-04-08T02:47:00Z",
  "control_id": "LOG-012",
  "action": "modification",
  "parameter": "cloudtrail_enabled",
  "baseline_value": true,
  "current_value": false,
  "changed_by": "admin_003",
  "approval_status": "pending"
}
```

**Expected Output**
```json
{
  "drift_id": "LOG-012-20260408",
  "severity": "CRITICAL",
  "risk_score": 92,
  "classification": "Logging Disabled — Visibility Gap",
  "evidence": [
    "CloudTrail changed from enabled to disabled",
    "Change by admin_003 at 02:47 UTC (off-hours)",
    "No approval recorded",
    "Logging gap creates audit blind spot"
  ],
  "mitre_mapping": ["T1562.008"],
  "compliance_impact": ["NIST AU-2", "NIST CM-3", "CIS 8.5"],
  "recommended_action": "Immediately re-enable logging and audit all access during blind period"
}
```
