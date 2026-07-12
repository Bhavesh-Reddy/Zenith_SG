"""PB-10 SBOM Risk Scorer dashboard (Flask, single page, zero external assets).

Reads reports/risk_report.json (produced by `python -m src.report.composite`).
The deterministic core does not depend on this app; it only displays output.

Routes:
  /                     dashboard (filter via ?app=APP-001&type=...&q=...)
  /export/html          writes a standalone HTML snapshot to
                        reports/risk_report.html and serves it
                        (print that page to PDF for the PDF deliverable)

Narratives: if reports/narratives_cache.json exists (Phase 4), narratives
are shown for matching finding_ids; absence is handled silently.

Run:  python -m dashboard.app   (http://127.0.0.1:5000)
"""

import json

from flask import Flask, render_template, request

from src.config import REPO_ROOT

REPORTS = REPO_ROOT / "reports"
app = Flask(__name__)


def _load_report():
    path = REPORTS / "risk_report.json"
    if not path.is_file():
        return None
    return json.loads(path.read_text())


def _load_narratives():
    path = REPORTS / "narratives_cache.json"
    try:
        return json.loads(path.read_text()) if path.is_file() else {}
    except (OSError, json.JSONDecodeError):
        return {}


def _view(export=False):
    report = _load_report()
    if report is None:
        return ("<h1>No report found</h1><p>Run <code>python -m "
                "src.report.composite</code> first.</p>", 503)

    app_filter = request.args.get("app", "") if not export else ""
    type_filter = request.args.get("type", "") if not export else ""

    findings = []
    for a in report["applications"]:
        for f in a["findings"]:
            if app_filter and f["app_id"] != app_filter:
                continue
            if type_filter and f["type"] != type_filter:
                continue
            findings.append(f)
    findings.sort(key=lambda f: -(f["risk_score"] or 0))

    all_types = sorted({f["type"] for a in report["applications"]
                        for f in a["findings"]})

    # Phase 6: compact per-finding graph data for the offline SVG viewer —
    # the exact chain(s) app -> ... -> vulnerable/flagged library.
    graph_data = {
        f["finding_id"]: {
            "app_id": f["app_id"], "library": f["library"],
            "version": f["version"], "type": f["type"],
            "severity": f["severity"], "num_paths": f["num_paths"],
            "paths": f["paths"],
        } for f in findings
    }
    return render_template(
        "dashboard.html", report=report, findings=findings,
        narratives=_load_narratives(), app_filter=app_filter,
        type_filter=type_filter, all_types=all_types, export=export,
        graph_data=graph_data)


@app.route("/")
def index():
    return _view()


@app.route("/export/html")
def export_html():
    html = _view(export=True)
    if isinstance(html, tuple):
        return html
    out = REPORTS / "risk_report.html"
    out.write_text(html, encoding="utf-8")
    return html


if __name__ == "__main__":
    app.run(debug=False)
