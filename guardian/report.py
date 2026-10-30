"""Renders graph.json into a single self-contained HTML report."""
import json
import os

from .controls import FRAMEWORKS
from .graph import is_open

TEMPLATE = os.path.join(os.path.dirname(__file__), "report_template.html")


def render(graph, out_path=None):
    data = {k: graph.data.get(k) for k in
            ("started", "site", "assets", "wan", "summary", "layer_summaries", "agent_log", "plan", "cost_total",
             "attack_paths", "changes")}
    # findings an agent re-checked and confirmed fixed, or merged into another, drop out; graph.json keeps their history
    data["findings"] = [f for f in graph.data.get("findings") or [] if is_open(f)]
    done = graph.data.get("compliance") or {}
    data["compliance"] = [{"title": fw["title"], "counts": {s: sum(1 for c in fw["controls"] if done.get(k, {}).get(c[0], {}).get("status", "not_assessed") == s)
                                                            for s in ("met", "partial", "gap", "not_assessed")},
                           "gaps": [{"id": c, "title": t, "note": done[k][c]["note"], "findings": done[k][c]["findings"]}
                                    for c, t in fw["controls"] if done.get(k, {}).get(c, {}).get("status") == "gap"]}
                          for k, fw in FRAMEWORKS.items()] if done else []
    html = open(TEMPLATE).read().replace(
        "/*__DATA__*/null", json.dumps(data, default=str).replace("</", "<\\/"))
    out_path = out_path or os.path.join(graph.run_dir, "report.html")
    with open(out_path, "w") as f:
        f.write(html)
    return out_path
