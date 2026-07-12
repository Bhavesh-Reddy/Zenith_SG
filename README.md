# PB-10 — Software Supply Chain Risk Scorer (SBOM Analyzer)

Societe Generale *iHackMyPlace* hackathon · Problem Statement 10.

Ingests an SBOM plus a vulnerability DB, a license-rule table and a
transitive-dependency graph; resolves **every** path from each application to
each flagged library; scores and ranks the risk per application; and presents
it in an offline dashboard with plain-English remediation narratives.

---

## Architecture — hybrid, deterministic-core-first

The system is three additive layers. **The deterministic core is the product;
the ML and LLM layers are strictly additive and non-blocking.** The core runs,
passes self-eval, and produces the full ranked report with both other layers
switched off.

```
        ┌─────────────────────── DETERMINISTIC CORE (authoritative) ──────────────────────┐
 data ─▶ ingestion ─▶ dependency graph (NetworkX) ─▶ exhaustive path enumeration ─▶ findings
        (stdlib)      app → direct → transitive       (all_simple_paths, DFS)        + license
                                                                                       engine
        └──────────────────────────────────────────┬──────────────────────────────────────┘
                                                    │  findings (evidence-cited)
                          ┌─────────────────────────┼──────────────────────────┐
                          ▼                          ▼                          ▼
                  ML risk scorer            composite ranked report      LLM narrative layer
                  (adds a 0-100 score;      (per-app scorecards,         (top-N findings only;
                   core ranks fine          diamond-aware ranking)       cache-first, offline
                   without it)                                            template fallback)
                                                    │
                                                    ▼
                                        Flask dashboard + HTML/PDF export
                                        + interactive dependency-chain viewer
```

**Why this shape.** A supply-chain risk tool has to be *auditable*: every claim
must trace to a specific CVE ID, license rule, or staleness date, along the
exact dependency path. A black-box model cannot do that. So the core is pure,
deterministic, stdlib-only rule logic; ML only re-orders the queue by attaching
a numeric score, and the LLM only rewrites an already-decided finding into
prose. Removing either upper layer degrades nothing about *correctness* — only
convenience.

### Layer 1 — Deterministic core
- **Graph** (`src/graph/`): a NetworkX `DiGraph`, one isolated subgraph per app
  (`("app",id)` / `("lib",id,name)` nodes) so a shared library never leaks paths
  between applications. Edges come from `transitive_dependencies.json`, wired by
  **library name** within each app (the edge file's version fields are
  inconsistent with the SBOM — all 372 mismatch — so versions always come from
  the SBOM row, matching the ground-truth labelling convention). 10 orphan
  transitive rows with no incoming edge are attached to the app root so **no
  dependency is ever pathless**.
- **Path enumeration** (`traversal.py`): `all_simple_paths` (DFS) returns *every*
  distinct app→library chain. This backs the 100 % transitive-resolution result.
- **CVE matching** (`vuln_match.py`): library-name match raises a finding;
  version-in-range is reported as a **confidence tier, not a filter** — see the
  dataset caveat below.
- **License engine** (`src/license/engine.py`): rule-table driven. Viral copyleft
  in a *proprietary* app → CONFLICT; the same in an *internal-only* app →
  ADVISORY (distribution scope matters); unknown/undeclared license → UNKNOWN
  (never silently assumed compatible).

### Layer 2 — ML risk scorer (`src/ml/`)
12 engineered features per dependency (CVSS, patch flag, dependency depth,
days-since-update, license risk tier, **number of paths to the dependency**
[the diamond signal], shared-across-apps, …). A hand-tuned baseline formula and
a `HistGradientBoostingClassifier` are both trained on an **80/20 stratified
holdout** and compared on the *same* holdout. See numbers below.

### Layer 3 — LLM narrative layer (`src/llm/narrative.py`)
Top-N ranked findings only. The prompt contains **structured finding data only**
(app, library, CVE + CVSS + patch info, full paths, license flag). Every
narrative is cached to `narratives_cache.json` **as produced**; the dashboard is
cache-first and never makes a network call, so a live demo cannot be broken by
the network. Two backends: Ollama (open-source, local, no rate limits) →
deterministic template fallback; **no logic depends on a specific model identity
answering** — only on receiving a well-formed string.

---

## Key design decision — diamond dependencies are compound risk, never deduplicated

When the same vulnerable library is reachable by two or more distinct paths (a
diamond), each path is a *separate* exposure with its own remediation surface,
so **every path is reported** and the risk score receives a compound uplift
(+5 % per extra path, capped +15 %). This is enforced in the graph traversal
(`all_simple_paths` returns all paths), the findings (`num_paths`,
`compound_exposure`), the composite score, and the dashboard's chain viewer,
which draws both branches visibly converging on the shared leaf. 105 of the
current findings are multi-path/compound.

---

## Phase 2 — honest holdout validation

Both scorers, evaluated on the identical 20 % stratified holdout (seed 42):

| Scorer            | Precision | Recall | F1     | FPR   |
|-------------------|-----------|--------|--------|-------|
| Baseline formula  | 73.4 %    | 100 %  | 0.847  | 32.1 %|
| GBDT (HistGBC)    | 83.3 %    | 74.5 % | **0.786** | 13.2 %|

The GBDT's full-set F1 (0.936) looks better only because it is scored on data it
trained on; on the honest holdout it **loses to the baseline (0.786 vs 0.847)**
and drops 25 points of recall. Per project policy — *if neither clearly wins,
ship the simpler, transparent rule-based formula* — **the baseline is shipped.**
This is consistent with the finding that the vulnerable-vs-decoy split in this
dataset carries no learnable signal beyond the rules (the decoys are
statistically indistinguishable by design).

---

## Self-eval vs. official targets (deterministic core only, ML/LLM disabled)

| Target                          | Required | Result           | Status |
|---------------------------------|----------|------------------|--------|
| Vulnerability Detection         | > 85 %   | **98.3 %** (173/176) | ✅ PASS |
| Transitive Resolution           | 100 %    | **100 %** (150/150)  | ✅ PASS |
| License Conflict Detection      | > 90 %   | **100 %** (16/16)    | ✅ PASS |
| False Positive Rate             | < 20 %   | 39.1 % (104/266)     | ❌ MISS |
| Risk Score Accuracy (±10)       | > 90 %   | 68.0 % (340/500)     | ❌ MISS |

**Why the two misses are dataset-inherent, not fixable without lying to the
labels.** The FPR miss and the risk-score miss share one root cause: the
vulnerability DB's `affected_versions` ranges **provably contradict the
ground-truth labels** (e.g. a library version *inside* its CVE's affected range
is labelled clean, while a version *outside* it is labelled vulnerable). We
verified predicates directly: exact version matching yields **0 %** vulnerability
detection; library-name matching yields **173/176**. We chose maximum security
value — catch every name-match and surface the version-range disagreement as an
explicit evidence tier — over gaming the FPR by suppressing true name-matches to
chase the labels. Suppressing them would forfeit real vulnerability recall to
satisfy a metric the data cannot jointly support. This is documented for the
jury rather than hidden. (39 of 200 DB entries also ship with reversed version
ranges, which the matcher normalises.)

---

## Phase 5 — edge cases (`python -m tests.edge_cases`)

Five hand-crafted scenarios from the brief, run through the **real** core (never
mixed into training or self-eval data). All 5 pass — full detail in
`reports/edge_cases.md`:

1. **Critical CVE with an available patch** → flagged, but evidence records
   `patch_available` + `fixed_version`, so ranking/narrative de-emphasise it.
2. **Unmaintained 2+ yrs, zero CVEs** → still flagged `UNMAINTAINED`,
   independently of any vulnerability.
3. **GPL in an internal-only app** → `LICENSE_ADVISORY` (not a distribution
   conflict); the *same* GPL lib in a proprietary app → `LICENSE_CONFLICT`.
4. **Same vulnerable library in two apps** → two independent findings, compound
   exposure, not deduplicated.
5. **Genuine diamond** → one finding, `num_paths=2`, both converging chains
   reported.

---

## Running it

Deterministic; requires the official dataset in `sample_data/` (or set
`SBOM_DATA_DIR`). Dependencies: `networkx`, `scikit-learn`, `pandas`, `numpy`,
`flask` (the core itself is stdlib-only).

```bash
python -m src.ingestion            # 1. load + validate the 6 data files
python -m src.findings             # 2. deterministic findings  -> reports/raw_findings.json
python -m src.ml.train             # 3. score deps (baseline)   -> reports/risk_scores.json
python -m src.report.composite     # 4. ranked report           -> reports/risk_report.json
python -m src.llm.narrative        # 5. (optional) narratives   -> reports/narratives_cache.json
python -m dashboard.app            # 6. dashboard at http://127.0.0.1:5000

python -m self_eval.evaluate       # official targets, core only
python -m tests.edge_cases         # 5 edge-case fixtures
python -m tests.test_graph         # hand-built graph unit tests
```

The dashboard reads only `reports/risk_report.json` (+ the narrative cache if
present) — no dev-only state — so it runs cleanly from a fresh clone once the
four build steps above have written the reports. **Export HTML** produces a
self-contained snapshot (`reports/risk_report.html`); print it to PDF for the
PDF deliverable. **⬦ view chain** on any finding opens an offline SVG viewer that
highlights the exact application → … → flagged-library path(s).

---

## Layout

```
src/config.py           DATA_DIR resolution (SBOM_DATA_DIR env override -> sample_data/)
src/ingestion.py        stdlib loader + schema/cross-reference validation
src/graph/              build_graph, paths_to_library (exhaustive), depth_of
src/vuln_match.py       name-match CVE policy + version-range confidence tier
src/license/engine.py   proprietary/internal-only-aware license decision table
src/findings.py         official-taxonomy findings + per-dep primary classification
src/ml/                 12 features, baseline formula, GBDT, honest holdout selection
src/report/composite.py ranked per-app report, deterministic severity, compound uplift
src/llm/narrative.py    top-N narratives, cache-first, offline template fallback
dashboard/              Flask app + zero-external-asset template + SVG chain viewer
self_eval/evaluate.py   official-target self-eval (core only, ML/LLM disabled)
tests/                  test_graph.py (unit), edge_cases.py (Phase 5 fixtures)
reports/                generated artefacts (findings, scores, report, narratives, edge_cases.md)
```
