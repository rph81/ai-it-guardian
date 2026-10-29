"""Renders graph.json into a single self-contained HTML report."""
import json
import os

TEMPLATE = os.path.join(os.path.dirname(__file__), "report_template.html")


def render(graph, out_path=None):
    data = {k: graph.data.get(k) for k in
            ("started", "site", "assets", "wan", "summary", "layer_summaries", "agent_log", "plan", "cost_total")}
    # findings an agent re-checked and confirmed fixed drop out of the report; graph.json keeps their history
    data["findings"] = [f for f in graph.data.get("findings") or [] if f.get("status") != "resolved"]
    html = open(TEMPLATE).read().replace(
        "/*__DATA__*/null", json.dumps(data, default=str).replace("</", "<\\/"))
    out_path = out_path or os.path.join(graph.run_dir, "report.html")
    with open(out_path, "w") as f:
        f.write(html)
    return out_path
