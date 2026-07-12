#  GRC Hackathon Datasets - Complete Guide

Welcome! This folder contains **sample/dummy datasets** for 8 problem statements (Problems 01-06, 10-11). Problems 07-09 have problem statements only. Each problem has its own folder with carefully crafted sample data designed to be realistic while remaining safely shareable.

---

##  Folder Structure

```
datasets/
 Problem_01_Identity_Access/
    README.md (detailed guide)
    sample_data/
        identity_users.csv (300 users - diverse names)  
        identity_users_labels.csv (300 ground truth labels)  
        identity_events.csv (900 events - 365 days)  
        identity_events_labels.csv (900 ground truth labels)  

 Problem_02_Config_Drift/
    README.md
    sample_data/
        baseline_configs.json (8 controls)  
        config_drift_events.csv (1,000 changes - 365 days)  
        config_drift_labels.csv (1,000 ground truth labels)  

 Problem_03_Compliance_Evidence/
    README.md
    sample_data/
        policy_documents.txt (6 policies)  
        evidence_artifacts.csv (500 records)  
        evidence_labels.csv (500 ground truth labels)  

 Problem_04_Data_Access/
    README.md
    sample_data/
        data_access_logs.csv (1,200 events - 365 days)  
        data_access_labels.csv (1,200 ground truth labels)  
        user_profiles.csv (100 profiles)  
        user_profile_labels.csv (100 ground truth labels)  

 Problem_05_Exceptions/
    README.md
    sample_data/
        exception_registry.csv (600 exceptions - 365 days)  
        exception_labels.csv (600 ground truth labels)  

 Problem_06_Vendor_Risk/
    README.md
    sample_data/
        vendor_registry.csv (400 vendors)  
        vendor_labels.csv (400 ground truth labels)  

 Problem_07_Ephemeral_Risk/
    Problem Statement 07.md
   

 Problem_08_Identity_Sprawl_AI/
    Problem Statement 08.md
    

 Problem_09_SecControl_Drift_AI/
    Problem Statement 09.md
    

 Problem_10_Supply_Chain_Risk/
    Problem Statement 10.md
    README.md
    sample_data/
        applications.json
        license_rules.json
        transitive_dependencies.json
        vulnerability_db.json

 Problem_11_Policy_Conflict/
    Problem Statement 11.md
    sample_data/
        findings_labels.json
        obligation_extracts_labels.json
        policy_metadata.json
        README.md
        policies/ (30 policy documents)

 THIS_FILE (README.md)
```

---

##  Quick Start

### Option 1: Pick a problem and dive in
```bash
cd Problem_01_Identity_Access/
# Read the README.md to understand the data
# Load sample_data/identity_users.csv in Python/Excel/your tool
# Start analyzing!
```

### Option 2: Get all data at once
```bash
# Every problem follows pattern:
# [Problem_Name]/sample_data/[file1.csv, file2.json, etc.]

# Total data size: ~2.5 MB for 8 problems with sample data (loads instantly in Python/SQL)
# Name diversity: 100+ unique first names, 60+ unique last names
# Realistic patterns: Email addresses, roles, departments, anomalies
# Note: Problems 07-09 have problem statements only (sample data coming soon)
```

---

## Data Summary - PHASE 1 COMPLETE (8 Problem Datasets Available)

**Note:** Problems 07-09 have problem statements available.

### Data Files

| Problem | Data File | Records | Coverage | Anomaly % |
|---------|-----------|---------|----------|-----------|
| **01** Identity | `identity_users.csv` | 300 | Current snapshot | 16% |
| **01** Identity | `identity_events.csv` | 900 | 365 days | 41% |
| **02** Config Drift | `config_drift_events.csv` | 1,000 | 365 days | 57% |
| **03** Compliance | `evidence_artifacts.csv` | 500 | Multi-period | 69% |
| **04** Data Access | `data_access_logs.csv` | 1,200 | 365 days | 46% |
| **04** Data Access | `user_profiles.csv` | 100 | Current snapshot | 17% |
| **05** Exceptions | `exception_registry.csv` | 600 | 365 days | 37% |
| **06** Vendor Risk | `vendor_registry.csv` | 400 | Current snapshot | 80% |
| **10** Supply Chain | `applications.json` | ~200 | Current snapshot | varies |
| **10** Supply Chain | `transitive_dependencies.json` | ~500 | Dependency graph | varies |
| **10** Supply Chain | `vulnerability_db.json` | ~800 | Vulnerability records | varies |
| **11** Policy Conflict | `policies/` | 30 documents | Policy collection | varies |
| **11** Policy Conflict | `policy_metadata.json` | ~30 | Metadata | varies |
| **TOTAL DATA** | | **~7,800+** | | varies |

### Ground Truth Label Files (NEW in Phase 1)

| Problem | Label File | Labels | Purpose |
|---------|------------|--------|---------|
| **01** | `identity_users_labels.csv` | 300 | Evaluate account risk detection |
| **01** | `identity_events_labels.csv` | 900 | Evaluate event anomaly detection |
| **02** | `config_drift_labels.csv` | 1,000 | Evaluate drift classification |
| **03** | `evidence_labels.csv` | 500 | Evaluate compliance gap detection |
| **04** | `data_access_labels.csv` | 1,200 | Evaluate insider threat detection |
| **04** | `user_profile_labels.csv` | 100 | Evaluate user risk scoring |
| **05** | `exception_labels.csv` | 600 | Evaluate exception risk detection |
| **06** | `vendor_labels.csv` | 400 | Evaluate vendor risk scoring |
| **10** | `findings_labels.json` | varies | Evaluate supply chain risk detection |
| **11** | `findings_labels.json` | varies | Evaluate policy conflict detection |
| **TOTAL LABELS** | | **~5,800+** | |

### Evolution Timeline:
- **v1 (Initial)**: ~190 records, 78 KB — sample size only
- **v2 (First Expansion)**: ~1,650 records, 350 KB — 8.7x growth
- **v3 (Diverse Names)**: ~3,700 records, 860 KB — international name diversity
- **v4 (Phase 1 — Current)**: 5,000 data + 5,000 labels, 365-day temporal coverage

### What Phase 1 Added:
- **Ground truth labels** for all 8 data files — teams can now self-evaluate precision/recall
- **365-day temporal coverage** for Problems 01, 02, 04, 05 — seasonal patterns, quarterly spikes
- **Anomaly type taxonomy** — each label includes anomaly_type, severity, and plain-English explanation
- **Self-evaluation code snippets** in every problem statement

---

##  How to Use Datasets

### For Python Analysis
```python
import pandas as pd
import json

# Problem 01
users = pd.read_csv('Problem_01_Identity_Access/sample_data/identity_users.csv')
events = pd.read_csv('Problem_01_Identity_Access/sample_data/identity_events.csv')

# Problem 02
with open('Problem_02_Config_Drift/sample_data/baseline_configs.json') as f:
    baselines = [json.loads(line) for line in f]
drifts = pd.read_csv('Problem_02_Config_Drift/sample_data/config_drift_events.csv')

# ... and so on for other problems
```

### For Excel/Spreadsheet Analysis
- Open any CSV file in Excel
- CSVs are pre-formatted with headers
- Easy to explore, filter, sort

### For Direct Inspection
- CSVs are human-readable
- JSON files follow prettified format
- TXT files contain full policy documents

---

##  Key Features of Sample Data

###  Realistic
- Data matches enterprise patterns
- Mix of normal and anomalous behavior
- Real compliance frameworks (GDPR, NIST, CIS)

###  Small & Fast
- 78 KB total (not 1 GB!)
- Loads instantly
- Perfect for hackathon time constraints

###  Annotated
- `anomaly_marker` columns indicate what's suspicious
- Used for evaluation/validation
- Helps teams understand what to look for

###  Diverse
- Multiple data formats (CSV, JSON, TXT)
- Mix of structured and semi-structured
- Tests different technical approaches

###  Safe
- No real company data
- No customer PII
- Compliant with all privacy regulations

---

##  Learning Path

### Step 1: Choose a problem
Pick based on your interests:
- **01 Identity/Access**: ML + behavior analysis
- **02 Config Drift**: Change detection + rules
- **03 Compliance**: NLP + policy analysis
- **04 Data Access**: Anomaly detection + risk scoring
- **05 Exceptions**: Process automation + workflows
- **06 Vendor Risk**: Multi-factor risk assessment
- **07 Ephemeral Risk**: Cloud & Kubernetes security governance
- **08 Identity Sprawl AI**: Hybrid identity management with AI
- **09 SecControl Drift AI**: Configuration governance with ML
- **10 Supply Chain Risk**: SBOM analysis & vulnerability scoring
- **11 Policy Conflict**: Policy analysis & compliance conflict detection

### Step 2: Read the README
Each problem folder has detailed README explaining:
- File contents and columns
- Real-world context
- Analysis ideas
- Anomalies to find
- Evaluation metrics

### Step 3: Load the data
```python
# Example
import pandas as pd
df = pd.read_csv('Problem_X/sample_data/file.csv')
df.info()
df.head()
```

### Step 4: Explore
- What's the data distribution?
- What patterns exist?
- Where are the anomalies?
- How would you solve this?

### Step 5: Build
- Implement your solution
- Train models / build dashboards
- Test on ground truth if provided
- Document your approach

---

##  What Each Problem Tests

| Problem | Primary Skills | Secondary Skills | Output Type |
|---------|---|---|---|
| 01 | ML/Anomaly Detection | Graph Analysis, SQL | Risk Dashboard |
| 02 | Configuration Mgmt | Rules Engine, NLP | Change Alerts |
| 03 | NLP/LLMs | Policy Analysis, Semantic Search | Compliance Report |
| 04 | Behavioral Analytics | Time-Series, ML | Risk Dashboard |
| 05 | Process Automation | Risk Scoring, Workflow | Exception Portal |
| 06 | Risk Assessment | Multi-Factor Analysis | Risk Dashboard |
| 07 | Cloud Security | Kubernetes, Infrastructure | Risk Report |
| 08 | ML/Identity Analysis | Behavioral Profiling | Risk Dashboard |
| 09 | ML/Configuration Mgmt | Drift Detection, NLP | Configuration Report |
| 10 | Supply Chain Security | Graph Analysis, Vulnerability | Risk Scorecard |
| 11 | NLP/Policy Analysis | Semantic Search, Conflict Detection | Compliance Report |

---

##  Pro Tips

### For Data Scientists
- Start with Problem 01, 04, 08, or 09 (heavy ML)
- Use pandas for exploration
- Scikit-learn or PyTorch for algorithms
- Consider LLM integration for explanations

### For Full-Stack Developers
- Start with Problem 05, 06, or 11 (workflow/UI heavy)
- Build web apps with Flask/FastAPI
- Use SQLite or PostgreSQL for data storage
- Create interactive dashboards

### For Security Analysts
- Start with Problem 02, 03, 05, 07, or 11 (domain focus)
- Map to compliance frameworks
- Focus on business impact
- Create audit-ready reports

### For Data Engineers
- Start with Problem 04, 10, or specialized infrastructure tracks
- Focus on data quality & freshness
- Build scalable architectures
- Think about real-world scale

### For Cloud/DevOps Engineers
- Start with Problem 07, 09, or 10 (infrastructure focus)
- Work with cloud APIs (AWS, Azure, GCP)
- Build automation pipelines
- Focus on governance and compliance

---

##  Data Scaling Guide

Too small? Here's how to expand:

### Simple Scaling
```python
# Duplicate rows 10x
large_df = pd.concat([df] * 10, ignore_index=True)
# Modify timestamps/IDs to avoid duplication
```

### Realistic Scaling
- Problem 01: Expand to 2,000 users from 20
- Problem 04: Expand to 1M events from 30
- Problem 06: Expand to 1,000 vendors from 15

### Production Volumes
- Identity (Problem 01): 10M+ events, 10k+ users
- Config Drift (Problem 02): 100M+ changes
- Compliance (Problem 03): 500k+ evidence records
- Data Access (Problem 04): 1B+ log entries
- Exceptions (Problem 05): Meta-small (growth is rare)
- Vendor (Problem 06): Meta-small with qualitative depth
- Ephemeral Risk (Problem 07): 100k+ cloud resource events
- Identity Sprawl AI (Problem 08): 50k+ identity records across systems
- SecControl Drift AI (Problem 09): 1M+ configuration drift events
- Supply Chain (Problem 10): 100k+ components, 10M+ dependencies
- Policy Conflict (Problem 11): 1k+ policies, 100k+ obligations

---

##  Data Dictionary Quick Reference

### Common Columns Across Datasets

| Column | Meaning | Format | Notes |
|--------|---------|--------|-------|
| `_id` | Unique key | string | Primary identifier |
| `timestamp` | When it happened | ISO 8601 datetime | Sortable |
| `status` | State | enum | varies by problem |
| `risk_level` | Severity | LOW\|MEDIUM\|HIGH\|CRITICAL | 4-level |
| `_marker` | Evaluation label | string | For testing |
| `approved` | Authorization | boolean | true/false |

---

##  Special Features

### Ground Truth Labels
Most problems include anomaly markers:
- Use these to validate your detection approach
- Calculate precision/recall metrics
- Understand false positives/negatives

### Framework Alignment
All data ties to real standards:
- GDPR, NIST, CIS, ISO 27001, PCI-DSS, SOX
- Learn compliance while analyzing

### Realistic Patterns
- Business hours vs after-hours
- Role-based access patterns
- Seasonal variations (month-end close, audits)
- Natural non-anomalies alongside anomalies

---

##  Hackathon Timeline

**48-72 Hour Typical Timeline:**
- Hour 0-2: Choose problem, read README, load data
- Hour 2-8: Explore data, identify patterns
- Hour 8-24: Build first version of solution
- Hour 24-36: Refine, test, improve metrics
- Hour 36-48: Documentation, dashboard/presentation
- Hour 48-72: Polish, final submission

---

##  FAQ

**Q: Can I use all 11 datasets?**
A: Yes! Submit multiple solutions if you have time. Consider focusing on 1-3 related problems for depth.

**Q: Are these realistic?**
A: Yes, modeled after real enterprise patterns. Sensitivity/Scope/Duration match real systems.

**Q: Can I expand the data?**
A: Absolutely. Duplicate wisely. See "Scaling Guide" above.

**Q: Do I get ground truth labels?**
A: Yes, anomaly markers in relevant files. Use for validation.

**Q: How do I know if my solution is good?**
A: Compare precision/recall against marked anomalies. See each problem's README.

**Q: What if my solution uses this data format but different problem?**
A: That's fine! Innovation encouraged. Document your approach.

---

##  Data Issues?

Found a problem with the data?
- Include: Problem #, file name, specific issue
- Bonus points for fixing it!

---

##  Next Steps

1. **Choose a problem** → read Problem_X/README.md
2. **Load the data** → start with sample files
3. **Explore** → understand patterns
4. **Build** → implement your solution
5. **Test** → validate using ground truth
6. **Document** → explain your approach
7. **Submit** → code + dashboard + docs

---



