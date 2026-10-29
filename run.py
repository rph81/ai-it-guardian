#!/usr/bin/env python3
"""AI IT Guardian - read-only assessment run.

  python3 run.py                 full run: collect -> agents -> report
  python3 run.py --collect-only  only the deterministic scan (no AI calls)
  python3 run.py --resume DIR    re-run agents and report on an existing scan
  python3 run.py --followup DIR  run what was asked from the console chat, then refresh the report
  python3 run.py --report DIR    re-render the HTML report only
"""
import argparse
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))


def load_env():
    path = os.path.join(HERE, ".env")
    if os.path.exists(path):
        for line in open(path):
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip().strip('"'))


def main():
    load_env()
    from guardian import collector, report
    from guardian.graph import Graph

    ap = argparse.ArgumentParser()
    ap.add_argument("--iface", default=os.environ.get("GUARDIAN_IFACE", "eth0"))
    ap.add_argument("--collect-only", action="store_true")
    ap.add_argument("--resume")
    ap.add_argument("--report")
    ap.add_argument("--followup")
    a = ap.parse_args()

    if a.report:
        print(report.render(Graph(a.report)))
        return
    if a.followup:
        if not os.environ.get("ANTHROPIC_API_KEY"):
            sys.exit("ANTHROPIC_API_KEY is not set")
        from guardian import agents
        g = Graph(a.followup)
        if agents.followups(g):
            agents.summarize(g)
            print("report:", report.render(g))
        else:
            print("nothing to follow up")
        return
    run_dir = a.resume or os.path.join(HERE, "runs", time.strftime("%Y%m%d-%H%M%S"))
    os.makedirs(run_dir, exist_ok=True)
    g = Graph(run_dir)
    if not a.resume:
        if os.geteuid() != 0:
            sys.exit("run as root (ARP and OS detection need raw sockets)")
        g.agent("collector", status="working", activity="Scanning the network")
        g.event("start", "collector", "collector", "Scanning the network")
        collector.collect(g, a.iface)
        g.agent("collector", status="done", activity=f'{len(g.data["assets"])} devices found')
        g.event("done", "collector", "collector", f'Scan finished: {len(g.data["assets"])} devices')
        g.save()
    if a.collect_only:
        print(f"scan saved in {run_dir}")
        return
    if not os.environ.get("ANTHROPIC_API_KEY"):
        sys.exit("ANTHROPIC_API_KEY is not set - put it in .env")
    from guardian import agents
    agents.run_all(g)
    agents.summarize(g)
    print("report:", report.render(g))


if __name__ == "__main__":
    main()
