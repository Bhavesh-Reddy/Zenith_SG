# EXECUTION PLAN — PB-10 SBOM Risk Scorer
## For direct execution by Claude Fable 5

**How to use this file:** invoke one phase at a time — e.g. "Execute Phase 1 from EXECUTION_PLAN.md." Do not run multiple phases unattended in one go; each phase ends with a Stop Condition that requires human confirmation before continuing. This project's `SKILL.md` (`.claude/skills/sbom-risk-hackathon/SKILL.md`) is auto-loaded and holds the persistent rules (data contracts, deterministic-core policy, diamond-dependency decision, model-routing guidance) — this file is the task sequence, not a restatement of those rules. If anything below conflicts with the skill, the skill wins.

---

## Global non-negotiables (apply to every phase)

- The deterministic core (graph traversal + license engine) must work correctly and pass self-evaluation with the ML layer and LLM layer fully disabled. Never make it depend on either.
- Diamond dependencies / multiple paths to the same vulnerable library = compound risk, not deduplicated. Reflect this in scoring and report text.
- All ingestion reads from a `DATA_DIR` config value, never a hardcoded path.
- Every finding in every output must cite its evidence: application, full dependency path (not just the leaf), and the specific CVE or license rule that triggered it.
- Before marking any phase done: actually re-run the self-eval script and report the real numbers. Do not report a phase as complete based on assumption.

---

## Phase 0 — Data Readiness

**Goal:** the pipeline can ingest and run against data regardless of whether the real `sample_data/` has arrived yet.

**Do:**
1. Check whether `sample_data/` exists in the repo with real files (`applications.json`, `sbom_dependencies.csv`, `vulnerability_db.json`, `license_rules.json`, `dependency_labels.csv`).
2. If it does not exist, generate `sample_data_placeholder/` matching this exact schema:
   - `applications.json` — 10 applications, with `id`, `name`, `business_criticality`, `owner`
   - `sbom_dependencies.csv` — 500 rows (10 apps × 50 deps): `app_id`, `library_name`, `version`, `license_type`, `is_direct` (bool), `last_updated` (date)
   - `vulnerability_db.json` — 200 CVEs: `cve_id`, `affected_library`, `affected_versions`, `cvss_score`, `has_patch` (bool)
   - `license_rules.json` — 15 rows: `license_type`, `compatible_with` (list), `risk_level`
   - `dependency_labels.csv` — 500 rows: ground truth `app_id`, `library_name`, `is_risky` (bool), `risk_type`, `severity`, `explanation` — target distribution: ~18% vulnerable, ~12% license conflict, ~15% unmaintained, ~10% transitive vulnerability, ~45% clean
3. Write a `config.py` (or equivalent) exposing `DATA_DIR`, defaulting to `sample_data/` if present, else `sample_data_placeholder/`.

**Definition of done:** running the ingestion module against `DATA_DIR` successfully loads all 5 files into memory with correct row/record counts matching the schema above, and prints a summary (row counts per file) to confirm.

**Stop condition:** report the summary output and whether real or placeholder data was used, then wait for confirmation before Phase 1.

---

## Phase 1 — Deterministic Core: Dependency Graph + License Engine

**Goal:** a directed dependency graph (`Application → Library(direct) → Library(transitive, N levels)`) with 100% correct transitive path resolution to any CVE-flagged library, plus a license compatibility engine, both fully deterministic and independently testable.

**Do:**
1. Build the graph using NetworkX from `sbom_dependencies.csv`.
2. Implement full traversal (DFS/BFS) to enumerate every path from an application to any library present in `vulnerability_db.json`.
3. Build the license engine: for every dependency, look up `license_rules.json` and flag incompatibilities (e.g. GPL in a proprietary app), noting if the data includes any distribution-scope field — if not, document that as a known limitation rather than guessing.
4. Write a hand-built 4–6 node test graph with a known 2-hop and a known 3-hop vulnerable chain (including one diamond case: two paths converging on the same vulnerable library). Verify traversal finds all expected paths and none it shouldn't.
5. Run the full graph + license engine against all data in `DATA_DIR` and produce a raw findings list (no scoring yet — just: this app, this path, this CVE or license rule, cited evidence).

**Definition of done:** the hand-built test graph passes with the exact expected path set. Running against the full dataset produces a findings list with zero errors and covers every app in `applications.json`.

**Stop condition:** report the hand-built test result and a summary count of raw findings by type (vulnerability / license / both), then wait for confirmation before Phase 2.

---

## Phase 2 — ML Risk Scorer

**Goal:** a trained, validated risk-scoring model that outperforms or matches a hand-tuned rule-based baseline, with honest holdout validation.

**Do:**
1. Engineer these features per dependency: `cvss_score`, `has_patch`, `dependency_depth` (0 = direct), `days_since_update`, `license_risk_tier` (from Phase 1's license engine output), `num_paths_to_dependency` (diamond signal from Phase 1's graph), `is_shared_across_apps`.
2. Build a hand-tuned baseline formula (explicit weights, documented) as a comparison point.
3. Train a gradient-boosted tree model (`sklearn.ensemble.HistGradientBoostingClassifier` or `GradientBoostingRegressor`) on `dependency_labels.csv` using an 80/20 stratified train/holdout split.
4. Evaluate both the baseline formula and the trained model on the same holdout split. Report precision, recall, F1, and false-positive rate for both.
5. Also run the brief's own self-eval methodology (checking against the full label set) for whichever approach is selected, and report that number separately, clearly labeled as "full-set self-eval" vs. "holdout validation."
6. Select whichever approach performs better on holdout. If neither clearly wins, default to the simpler rule-based formula and state that explicitly.

**Definition of done:** both approaches have real, reported holdout numbers (not just full-set numbers), a decision is made and documented with the reasoning, and the composite risk report from Phase 1's findings now includes a numeric risk score per finding.

**Stop condition:** report both approaches' metrics side by side and which was selected, then wait for confirmation before Phase 3.

---

## Phase 3 — Composite Risk Report + Dashboard

**Goal:** a ranked, per-application risk report (JSON) and a working dashboard (Flask or FastAPI) that displays it, exportable to HTML/PDF.

**Do:**
1. Assemble Phase 1's findings + Phase 2's risk scores into one ranked JSON risk report, grouped by application, sorted by risk score descending.
2. Build a dashboard showing: per-application risk scorecard, ranked findings list with full evidence (path, CVE/license rule, score), and filter/drill-down by application.
3. Add export to HTML and/or PDF.
4. Run the brief's provided self-eval script against this final report and confirm actual numbers against these targets: Vulnerability Detection >85%, Transitive Resolution 100%, License Conflict Detection >90%, False Positive Rate <20%, Risk Score Accuracy within ±10% of ground truth.

**Definition of done:** the dashboard runs locally, displays real data end-to-end, export works, and the self-eval numbers are reported — explicitly flag any target that is not yet met.

**Stop condition:** report the self-eval numbers against each target. If any target is missed, do not proceed to Phase 4 — instead diagnose and fix the miss first, then re-run self-eval, then report again.

---

## Phase 4 — LLM Narrative Layer

**Goal:** plain-English remediation narratives for the top-ranked findings, generated at inference time only, with a cached fallback so a live demo never depends on a network call succeeding.

**Do:**
1. Build a narrative generator that takes the top 5–10 findings from Phase 3's report and, for each, calls an LLM with only structured finding data (app, library, CVE ID, CVSS, full path, license flag) to produce a 2–3 sentence remediation narrative.
2. Cache every generated narrative to `narratives_cache.json` keyed by finding ID as it's produced.
3. Wire the dashboard to read from cache first if available, falling back to a live call only if no cached entry exists, and to gracefully skip narrative display (not crash) if a live call fails and no cache exists.
4. Do not build any logic that depends on a specific model identity responding — only on receiving a well-formed narrative string.

**Definition of done:** running the narrative generator once produces cached narratives for the top findings; re-running the dashboard with the network disabled still displays those narratives correctly from cache.

**Stop condition:** report that the cache-fallback path was tested with network disabled, then wait for confirmation before Phase 5.

---

## Phase 5 — Edge-Case Injection

**Goal:** demonstrate the system correctly handles the specific ambiguous scenarios named in the PB-10 brief, using hand-crafted (not synthetically mass-generated) test entries.

**Do:** add these 5 entries to a separate test fixture (never mixed into the training or self-eval data):
1. A library with a critical CVE but `has_patch: true` — verify the system does not over-flag it as high risk without noting the patch.
2. A library unmaintained 18+ months with zero CVEs in `vulnerability_db.json` — verify it's still flagged for maintenance risk independently.
3. A GPL library used only in an internal (non-distributed) context — verify the license engine's behavior and that any limitation here is documented, not silently guessed.
4. The same vulnerable library reachable from two different applications — verify the report shows compound exposure across both apps, not deduplicated.
5. A genuine diamond dependency (two paths, different version requirements, converging on one vulnerable library) — verify both paths are reported.

**Definition of done:** all 5 fixtures run through the full pipeline and produce the expected, documented behavior for each; results captured in a short markdown summary suitable for quoting during the live demo.

**Stop condition:** report the 5 results, then wait for confirmation before Phase 6.

---

## Phase 6 — Stretch: Graph Visualization (only if ahead of schedule)

**Goal:** an interactive dependency graph visualization highlighting the vulnerable path for a selected finding.

**Do:** add a graph view to the dashboard (NetworkX + a JS rendering layer, e.g. vis.js or D3) that, given a selected finding, highlights the exact path from application to vulnerable library.

**Definition of done:** clicking a finding in the dashboard visually highlights its dependency chain.

**Stop condition:** only attempt this phase if Phases 0–5 are all complete and confirmed. Report completion or explicitly report "skipped — insufficient time" rather than leaving it half-built.

---

## Phase 7 — Freeze, Harden, Demo Prep

**Goal:** a stable, demo-ready system with no in-progress features.

**Do:**
1. Re-run the full self-eval one final time and confirm all target metrics from Phase 3.
2. Re-run all 5 edge-case fixtures from Phase 5 one final time.
3. Generate a short architecture README covering: the hybrid deterministic-core + ML-scorer + LLM-narrative design, the diamond-dependency policy decision, the holdout-validation numbers from Phase 2, and the 5 edge cases handled.
4. Confirm the dashboard runs cleanly from a fresh clone/restart (no leftover dev-only state required).

**Definition of done:** final self-eval numbers, final edge-case results, and the README are all produced and match what was reported in earlier phases (no silent regressions).

**Stop condition:** report final numbers and flag any discrepancy from earlier phase reports before considering the build complete.
