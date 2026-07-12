"""Phase 4: LLM narrative layer — plain-English remediation for top findings.

Rules (from the project skill):
  * Called only on the TOP N ranked findings (default 10), never the full set.
  * Prompt input is STRUCTURED FINDING DATA ONLY (app, library, CVE, CVSS,
    full dependency path, license flag) — nothing free-form.
  * Every narrative is cached to reports/narratives_cache.json keyed by
    finding_id AS IT IS PRODUCED, so a crash mid-run loses nothing.
  * Cache-first: a finding with a cached narrative is never regenerated.
  * No code depends on a specific model identity responding — only on
    receiving a well-formed 2-3 sentence string.

Provider is config-driven (`.env`): `LLM_PROVIDER` selects the active
backend.  Ollama (open-source, local) is the default and only live backend.

Generation backends, tried in order per finding:
  1. Ollama REST API (active when LLM_PROVIDER=ollama; uses any local model)
  2. Deterministic template (tagged "template-fallback") — guarantees the
     demo never depends on a network call succeeding.

The deterministic core never imports this module, so wiring an LLM provider
here introduces no dependency of the core on any network or key.

Run:  python -m src.llm.narrative [N]
"""

import json
import os
import sys
import urllib.error
import urllib.request

from src.config import REPO_ROOT

REPORTS = REPORTS_DIR = REPO_ROOT / "reports"
CACHE_PATH = REPORTS / "narratives_cache.json"


def _load_dotenv():
    """Minimal .env loader (no external dep): populate os.environ with any
    KEY=VALUE lines not already set in the environment. The deterministic
    core does not use this — it is scoped to the optional narrative layer."""
    path = REPO_ROOT / ".env"
    if not path.is_file():
        return
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key, val = key.strip(), val.strip().strip('"').strip("'")
        os.environ.setdefault(key, val)


_load_dotenv()
LLM_PROVIDER = os.environ.get("LLM_PROVIDER", "ollama").strip().lower()

# Ollama config — open-source, no rate limits.
OLLAMA_BASE_URL = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434").strip().rstrip("/")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "llama3.2").strip()
OLLAMA_API_KEY = os.environ.get("OLLAMA_API_KEY", "").strip()

SYS_INSTRUCTION = (
    "You are a supply-chain security analyst. Reply with ONLY a 2-3 sentence "
    "plain-English remediation narrative in prose: what the risk is, why it "
    "matters for this application, and the concrete next step. Never repeat, "
    "quote, or list the input field names, keys, values, JSON, backticks, or "
    "markdown. Start with the application or library name."
)

PROMPT = (
    "Write the remediation narrative for this finding. Prose only, no field "
    "names or JSON.\n\nFINDING:\n{data}"
)


def _acceptable(text):
    """Guard against the model echoing the structured input instead of writing
    prose. Reject anything that isn't a clean sentence so it falls through to
    the deterministic template."""
    t = text.strip()
    if len(t) < 60 or not t[0].isalpha():
        return False
    if t.count("`") >= 1 or '":' in t[:120] or t.lstrip().startswith("*"):
        return False
    if t[-1] not in ".!?":            # truncated mid-sentence -> reject
        return False
    return True


def _load_cache():
    try:
        return json.loads(CACHE_PATH.read_text()) if CACHE_PATH.is_file() else {}
    except (OSError, json.JSONDecodeError):
        return {}


def _save_cache(cache):
    CACHE_PATH.write_text(json.dumps(cache, indent=2))


def _structured(f):
    """The exact structured payload sent to the LLM — nothing more."""
    out = {
        "application": f["app_id"], "library": f["library"],
        "version": f["version"], "finding_type": f["type"],
        "dependency_paths": f["paths"], "num_paths": f["num_paths"],
        "risk_score": f.get("risk_score"), "severity": f.get("severity"),
    }
    ev = f.get("evidence", {})
    if ev.get("cves"):
        c = max(ev["cves"], key=lambda c: c["cvss_score"])
        out.update(cve_id=c["cve_id"], cvss=c["cvss_score"],
                   patch_available=c["patch_available"],
                   fixed_version=c.get("fixed_version"))
    if ev.get("license"):
        out.update(license=ev["license"], license_note=ev.get("note"))
    if ev.get("last_updated"):
        out.update(last_updated=ev["last_updated"])
    return out


def _try_ollama(prompt):
    """Ollama via its native REST API.
    Active when LLM_PROVIDER=ollama. Open-source, no rate limits."""
    if LLM_PROVIDER != "ollama":
        return None
    url = f"{OLLAMA_BASE_URL}/api/generate"
    body = json.dumps({
        "model": OLLAMA_MODEL,
        "system": SYS_INSTRUCTION,
        "prompt": prompt,
        "stream": False,
        "options": {"temperature": 0.3, "num_predict": 512},
    }).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if OLLAMA_API_KEY:
        headers["Authorization"] = f"Bearer {OLLAMA_API_KEY}"
    try:
        req = urllib.request.Request(url, data=body, headers=headers)
        with urllib.request.urlopen(req, timeout=120) as r:
            resp = json.loads(r.read().decode("utf-8"))
        text = resp.get("response", "").strip()
        if text and _acceptable(text):
            return text
    except (urllib.error.URLError, urllib.error.HTTPError, OSError, ValueError,
            json.JSONDecodeError) as e:
        print(f"  [ollama] error: {e}")
    return None


def _template(f):
    """Deterministic offline fallback — always produces a valid narrative."""
    ev, lib = f.get("evidence", {}), f"{f['library']}@{f['version']}"
    path = " -> ".join(f["paths"][0]) if f["paths"] else f["app_id"]
    compound = (f" It is reachable via {f['num_paths']} distinct dependency "
                f"paths, compounding the exposure and remediation surface."
                if f["num_paths"] > 1 else "")
    if ev.get("cves"):
        c = max(ev["cves"], key=lambda x: x["cvss_score"])
        fix = (f"upgrade to {c['fixed_version']}" if c.get("fixed_version")
               else "no patched version is published yet, so isolate or replace the library")
        return (f"{f['app_id']} is exposed to {c['cve_id']} (CVSS "
                f"{c['cvss_score']}) through {lib} via {path}.{compound} "
                f"Recommended action: {fix} and re-scan to confirm the chain is closed.")
    if ev.get("license"):
        return (f"{lib} carries the {ev['license']} license inside "
                f"{f['app_id']}, reachable via {path}, which conflicts with "
                f"proprietary distribution.{compound} Recommended action: "
                f"replace it with a permissively-licensed alternative or "
                f"obtain legal clearance before the next release.")
    return (f"{lib} in {f['app_id']} has had no updates since "
            f"{ev.get('last_updated', 'over two years ago')} and poses "
            f"maintenance risk even without known CVEs.{compound} "
            f"Recommended action: plan a migration to an actively maintained "
            f"alternative or take ownership of security monitoring for it.")


def generate(top_n=10):
    report = json.loads((REPORTS / "risk_report.json").read_text())
    findings = sorted(
        (f for a in report["applications"] for f in a["findings"]
         if not f.get("advisory_only")),
        key=lambda f: -(f.get("risk_score") or 0))[:top_n]

    cache = _load_cache()
    stats = {"cached": 0, "ollama": 0, "template-fallback": 0}
    for f in findings:
        fid = f["finding_id"]
        if fid in cache and cache[fid].get("narrative"):
            stats["cached"] += 1
            continue
        prompt = PROMPT.format(data=json.dumps(_structured(f), indent=1))
        text, source = None, None
        # Try Ollama first, then fall back to deterministic template.
        text = _try_ollama(prompt)
        if text:
            source = "ollama"
        else:
            text, source = _template(f), "template-fallback"
        entry = {"narrative": text, "source": source,
                 "library": f["library"], "app_id": f["app_id"]}
        if source == "ollama":
            entry["model"] = OLLAMA_MODEL
        cache[fid] = entry
        _save_cache(cache)          # incremental — persist per finding
        stats[source] += 1
        tag = f"{source}:{OLLAMA_MODEL}" if source == "ollama" else source
        print(f"  {fid} [{tag}] {text[:90]}...")

    _save_cache(cache)
    print(f"narratives cached -> {CACHE_PATH}")
    print(f"  {stats}")


if __name__ == "__main__":
    generate(int(sys.argv[1]) if len(sys.argv) > 1 else 10)
