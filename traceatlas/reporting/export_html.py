"""HTML export of a built report (dependency-free)."""

from __future__ import annotations

import html

from traceatlas.reporting.export_json import export_json


def export_html(report: dict) -> str:
    esc = html.escape
    parts = [f"<h1>{esc(report['case_title'])}</h1>",
             f"<p>Case: <code>{esc(report['case_id'])}</code></p>",
             "<h2>Findings (VERIFIED claims only)</h2><ul>"]
    for f in report["findings"]:
        parts.append(f"<li>{esc(f['statement'])} (confidence {f['confidence']:.2f})</li>")
    parts.append("</ul><h2>Open questions</h2><ul>")
    for q in report["open_questions"]:
        parts.append(f"<li>{esc(q['statement'])} — {esc(q['status'])}</li>")
    parts.append("</ul><h2>Limitations</h2><ul>")
    for l in report["limitations"]:
        parts.append(f"<li>{esc(l)}</li>")
    parts.append("</ul><pre>" + esc(export_json(report)) + "</pre>")
    return "<!doctype html><html><body>" + "".join(parts) + "</body></html>"
