---
name: sbom-risk-hackathon
description: Use this skill for all work on the Societe Generale iHackMyPlace PB-10 "Software Supply Chain Risk Scorer (SBOM Analyzer)" hackathon project — building the dependency graph engine, license rule engine, ML risk scorer, LLM narrative layer, dashboard, self-evaluation, or edge-case test data for this specific project. Trigger this whenever the user is working in the sbom-risk-scorer repo/project, mentions SBOM analysis, dependency risk scoring, transitive vulnerability resolution, license conflict detection for this hackathon, or asks to extend/debug/test any part of this system. Do not use for unrelated coding tasks.
---

# PB-10 SBOM Risk Scorer — Hackathon Build Skill

This skill encodes the architecture, data contracts, decisions, and quality bar for the 48-hour hackathon build so that every coding session — yours or your teammate's — stays consistent without re-explaining context each time.

## Project identity

Two-person team, 3rd-year CSE, 48-hour hackathon. Problem statement: PB-10, Software Supply Chain Risk Scorer (SBOM Analyzer), built at **"Option B+" / "Option A-Lite" scope**: a deterministic graph + license engine as the core, with an ML-trained risk scorer and an LLM narrative layer as additive, non-blocking enhancements. See `Architecture` below before writing any code.

**Golden rule for every task in this project:** the deterministic core (graph traversal + license engine) must work correctly and pass self-evaluation *without* the ML layer or the LLM layer running. Never make the core depend on either. If asked to add or debug an ML/LLM feature, check first that this rule still holds after the change.

## Architecture (do not deviate without being asked)

```
Ingestion (applications.json, sbom_dependencies.csv, vulnerability_db.json, license_rules.json)
  -> Deterministic Core: dependency graph (NetworkX) -> transitive traversal -> license rule engine
  -> ML Layer: engineered features -> trained GBDT risk scorer (validated on holdout split)
  -> Composite Risk Report (per-application, ranked, JSON)
  -> LLM Narrative Layer: top-N findings only -> plain-English remediation text
  -> Dashboard/Report (Flask or FastAPI + Chart.js, PDF/HTML export)
```

## Data readiness — read before touching ingestion code

The real `sample_data/` files may not be present yet — the problem-statement brief only describes their schema, it does not guarantee the files ship with it. Before writing or running ingestion code:

1. Check whether `sample_data/` exists in the repo with real files in it (not just a description). If it doesn't, work against `sample_data_placeholder/` instead — a hand-built, schema-matching placeholder dataset (10 apps, 500 dependency rows, 200 CVEs, 15 license rules, 500 labeled rows).
2. All ingestion code must read from a `DATA_DIR` config value, never a hardcoded path, so switching from placeholder to real data is a one-line change.
3. If asked to build or extend the placeholder dataset, match the brief's stated schema and label distribution exactly (~18% vulnerable, ~12% license conflict, ~15% unmaintained, ~10% transitive vulnerability, ~45% clean) — this is for development/self-test only, never present it as the official dataset.
4. The first time real `sample_data/` files appear in the repo, flag it explicitly and re-run the full pipeline + self-eval against them before trusting any prior result.

## Model routing (Fable vs. Sonnet — CLI or VS Code extension)

This project's domain (CVEs, exploitability, vulnerability chains) is likely to trigger Fable 5's safety-based reroute to Opus, and that reroute persists across turns until manually switched back — whether working from the terminal or the Claude Code VS Code extension panel. Do not assume the active model matches what was last explicitly requested — check the active-model indicator (`/status`, or the model name shown in the VS Code panel) when it matters, since teammates may be working from either surface.

Default to Sonnet for routine implementation (ingestion boilerplate, dashboard/route code, tests, formatting/export, small fixes). Only suggest or use Fable for genuinely ambiguous, architecture-level, or investigative work: designing the graph traversal algorithm, the diamond-dependency policy decision, the ML feature-engineering/holdout strategy, root-causing a self-eval metric that's off, or the architecture write-up for the deck. Switch via `/model fable` (works identically in the terminal and the VS Code chat input) or by clicking the model name in the VS Code panel to open the picker. Do not run high-volume routine work on Fable — it costs roughly 2-3x more per token than Sonnet and drains usage budget faster, which matters on a fixed 48-hour clock.

## Data contracts

Before writing ingestion code, actually inspect the real files in `sample_data/` — the columns below are the brief's description and may not exactly match the delivered files. Confirm actual column names/types first, then proceed.

- `applications.json` — 10 records: application metadata, business criticality, owner
- `sbom_dependencies.csv` — 500 records (10 apps × 50 deps): library name, version, license type, direct/transitive indicator, last-updated date
- `vulnerability_db.json` — 200 records: CVE ID, affected library+version, CVSS score, patch availability
- `license_rules.json` — 15 records: license type, compatibility matrix, risk level
- `dependency_labels.csv` — 500 records: ground-truth risk status, risk type, severity, explanation — **this is the eval target, never train the deterministic core's logic to fit it directly; only the ML layer trains on it, and only with a holdout split**

## Deterministic core rules

1. Build a directed graph: `Application -> Library(direct) -> Library(transitive, N levels deep)`.
2. Use full graph traversal (DFS/BFS) to find **every** path from an application to a CVE-flagged library. This must hit 100% transitive resolution — if a path exists in the data, it must be found. Write a unit test with a hand-built 4-node graph with a known 2-hop chain before running on the full dataset.
3. **Diamond dependencies / multiple paths to the same vulnerable library are treated as compound risk, not deduplicated.** A library reachable via 2+ paths increases the app's exposure and remediation surface — reflect this explicitly in the risk score and in the report text. This is a stated project decision; don't silently change it.
4. License engine looks up `license_rules.json` for compatibility. Distinguish distribution scope where the data allows it (a GPL library used only internally vs. distributed) — don't blindly flag all GPL identically if the data has a distribution/scope field; if it doesn't, note that as a documented limitation rather than guessing.
5. Every finding must cite its evidence: which app, which dependency path (full chain, not just the leaf), which CVE or license rule triggered it.

## ML risk scorer rules

1. Do feature engineering before modeling. Minimum feature set: `cvss_score`, `has_patch`, `dependency_depth`, `days_since_update`, `license_risk_tier`, `num_paths_to_dependency`, `is_shared_across_apps`.
2. Use a gradient-boosted tree model (`sklearn.ensemble.HistGradientBoostingClassifier` or `GradientBoostingRegressor`) — not a deep net, not an embeddings-only approach. The dataset is ~500 rows; a heavier model will overfit or add risk without benefit.
3. **Always do a real train/holdout split** (e.g. 80/20, stratified if the classifier). Report the holdout metric as the honest number. Separately, also run the brief's own self-eval script (which checks against the full label set) and report that number too — present both, labeled clearly as "holdout validation" vs. "full-set self-eval."
4. Compare the trained scorer against the hand-weighted deterministic formula on the same holdout split. If the trained model doesn't clearly outperform, that is a valid outcome — ship whichever performs better and say so plainly in any generated report or comment, don't force the ML result to "win."
5. Never let a change to this layer alter the deterministic core's output. The composite report should clearly separate "core findings" (deterministic, always present) from "risk score" (may come from either the hand-tuned formula or the trained model, whichever validated better).

## LLM narrative layer rules

1. Call the narrative generator only on the top 5–10 ranked findings per run, never the full result set — controls cost, latency, and demo risk.
2. Input to the prompt: structured finding data only (app, library, CVE ID, CVSS, full dependency path, license flag). Output: 2–3 sentence plain-English remediation narrative.
3. Cache every generated narrative to a local file (e.g. `narratives_cache.json`) keyed by finding ID as it's generated during development. If asked to prepare for a live demo, wire in a fallback that reads from this cache if the live API call fails or times out — never let the demo depend on a live network call succeeding.
4. These prompts are cybersecurity-flavored (CVE/vulnerability reasoning) and may be routed to a different underlying model automatically depending on the provider's safety routing. Do not write code that asserts or depends on a specific model identity in the response — only on getting a well-formed narrative string back.

## Edge-case test data (using vulnerability-dataset-generation experience)

When asked to generate or extend edge-case test entries for this project, hand-craft — do not synthetically mass-generate — a small, deliberate set of SBOM/CVE entries that map directly to the ambiguous scenarios named in the PB-10 brief:

1. Library with a critical CVE **but a patch already applied** — tests whether the system avoids a false positive on exploitability.
2. Library unmaintained 18+ months **with zero known CVEs** — tests whether maintenance risk is flagged independently of CVE presence.
3. GPL library used **only internally, never distributed** — tests whether the license engine accounts for distribution scope (see rule 4 above).
4. **Same vulnerable library reachable from two different applications** — tests that the report shows compound exposure across apps rather than silently deduplicating.
5. A genuine **diamond dependency** (two paths converging on the same library with different version requirements).

Each hand-crafted entry should be small, realistic, and self-contained (a few lines of SBOM/CVE JSON/CSV, not a full synthetic dataset). The goal is targeted verification and a strong live-demo moment, not training data volume. Do not add these rows into any file used for ML training — they are for functional/demo testing of the deterministic core and the report output only.

## Success criteria to keep visible during every session

| Metric | Target |
|---|---|
| Vulnerability Detection | > 85% |
| Transitive Resolution | 100% |
| License Conflict Detection | > 90% |
| False Positive Rate | < 20% |
| Risk Score Accuracy | ±10% of labeled ground truth |

Any code change touching the core pipeline should be checked against these before being considered done — re-run the self-eval script, don't assume.

## Definition of done for any task in this project

A task is not complete until:
1. The relevant self-eval metric(s) above have actually been re-run and checked, not assumed.
2. If the change touches the deterministic core, confirm the system still works correctly with the ML layer and LLM layer disabled/mocked out.
3. If the change touches the ML layer, both the holdout metric and the full-set self-eval metric are reported, not just one.
4. If the change touches the LLM layer, confirm the cached-fallback path still works if the live call is skipped.
5. Code is placed in the agreed repo layout (see below) — don't scatter new files ad hoc.

## Suggested repo layout

```
/data/                  raw + processed sample_data files
/src/graph/             dependency graph construction + traversal
/src/license/           license rule engine
/src/ml/                feature engineering, training, holdout eval
/src/llm/               narrative generation + cache
/src/report/            composite risk report assembly
/dashboard/             Flask/FastAPI app + templates/static
/tests/                 unit tests, incl. hand-built graph fixtures and edge-case entries
/self_eval/             the brief's provided self-eval script + outputs
```
