"""Renders graph.json into a single self-contained HTML report."""
import json
import os

TEMPLATE = os.path.join(os.path.dirname(__file__), "report_template.html")


def render(graph, out_path=None):
    data = {k: graph.data.get(k) for k in
            ("started", "site", "assets", "wan", "findings", "summary", "layer_summaries", "agent_log", "usage", "plan")}
    html = open(TEMPLATE).read().replace(
        "/*__DATA__*/null", json.dumps(data, default=str).replace("</", "<\\/"))
    out_path = out_path or os.path.join(graph.run_dir, "report.html")
    with open(out_path, "w") as f:
        f.write(html)
    return out_path
