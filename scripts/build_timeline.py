#!/usr/bin/env python3
"""Turn detection findings into a Markdown incident timeline (docs/generated-timeline.md)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from detect_iocs import ROOT, load_events, run_detections  # noqa: E402


def main():
    events = load_events(os.path.join(ROOT, "logs", "events.jsonl"))
    findings = run_detections(events)
    lines = ["# Auto-Generated Incident Timeline", "",
             "Produced by `scripts/build_timeline.py` from `logs/events.jsonl`.", "",
             "| Time (UTC) | Rule | Severity | Host | MITRE | Finding |", "|---|---|---|---|---|---|"]
    for f in findings:
        lines.append(f"| {f['ts'][11:19]} | {f['rule']} | {f['severity']} | {f['host']} | {f['mitre']} | {f['message']} |")
    first, last = findings[0]["ts"], findings[-1]["ts"]
    lines += ["", f"**First detection:** {first}  ", f"**Last detection:** {last}  ", f"**Total findings:** {len(findings)}"]
    out = os.path.join(ROOT, "docs", "generated-timeline.md")
    with open(out, "w") as fh:
        fh.write("\n".join(lines) + "\n")
    print(f"Timeline written to {out}")


if __name__ == "__main__":
    main()
