"""Phase 4: LLM narrative layer — plain-English remediation for top findings.

Rules (from the project skill):
  * Called only on the TOP N ranked findings (default 10), never the full set.
  * Prompt input is STRUCTURED FINDING DATA ONLY (app, library, CVE, CVSS,
    full dependency path, license flag) — nothing free-form.
  * Every narrative is cached to reports/narratives_cache.json keyed by
    finding_id AS IT IS PRODUCED, so a crash mid-run loses nothing.
  * Cache-first: a finding with a cached narrative is never regenerated.
  * No code depends on a specific model identity responding — only on
    receiving a well-formed 2-3 sentence string (cybersecurity prompts may
    be safety-rerouted to a different model; that is fine).

Generation backends, tried in order per finding:
  1. Anthropic Python SDK (if installed and credentials resolve)
  2. `claude -p` CLI (Claude Code, present on the dev machines)
  3. Deterministic template (tagged "template-fallback") — guarantees the
     demo never depends on a network call succeeding.

Run:  python -m src.llm.narrative [N]
"""

import json
import shutil
import subprocess
import sys

from src.config import REPO_ROOT

REPORTS = REPO_ROOT / "reports"
CACHE_PATH = REPORTS / "narratives_cache.json"

PROMPT = (
    "You are a supply-chain security analyst. Based ONLY on this structured "
    "finding, write a 2-3 sentence plain-English remediation narrative for an "
    "engineering team: what the risk is, why it matters for this application, "
    "and the concrete next step. No preamble, no markdown.\n\nFINDING:\n{data}"
)


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


def _try_sdk(prompt):
    try:
        import anthropic
    except ImportError:
        return None
    try:
        client = anthropic.Anthropic()
        resp = client.messages.create(
            model="claude-opus-4-8", max_tokens=300,
            messages=[{"role": "user", "content": prompt}])
        if resp.stop_reason == "refusal":
            return None
        text = " ".join(b.text for b in resp.content if b.type == "text").strip()
        return text or None
    except Exception:
        return None


def _try_cli(prompt):
    if not shutil.which("claude"):
        return None
    try:
        r = subprocess.run(["claude", "-p", prompt], capture_output=True,
                           text=True, timeout=120, encoding="utf-8")
        text = (r.stdout or "").strip()
        return text if r.returncode == 0 and len(text) > 40 else None
    except (OSError, subprocess.TimeoutExpired):
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
    stats = {"cached": 0, "sdk": 0, "cli": 0, "template-fallback": 0}
    for f in findings:
        fid = f["finding_id"]
        if fid in cache and cache[fid].get("narrative"):
            stats["cached"] += 1
            continue
        prompt = PROMPT.format(data=json.dumps(_structured(f), indent=1))
        text, source = None, None
        for fn, name in ((_try_sdk, "sdk"), (_try_cli, "cli")):
            text = fn(prompt)
            if text:
                source = name
                break
        if not text:
            text, source = _template(f), "template-fallback"
        cache[fid] = {"narrative": text, "source": source,
                      "library": f["library"], "app_id": f["app_id"]}
        _save_cache(cache)          # incremental — persist per finding
        stats[source] += 1
        print(f"  {fid} [{source}] {text[:90]}...")

    _save_cache(cache)
    print(f"narratives cached -> {CACHE_PATH}")
    print(f"  {stats}")


if __name__ == "__main__":
    generate(int(sys.argv[1]) if len(sys.argv) > 1 else 10)
