#!/usr/bin/env python3
"""Rule-based detection engine for the NovaTech ransomware simulation.

Each rule maps to a MITRE ATT&CK technique and returns findings with severity.
Usage: python scripts/detect_iocs.py [path/to/events.jsonl] [--json]
"""
import csv
import json
import os
import sys
from collections import defaultdict
from datetime import datetime

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOME_COUNTRIES = {"IN"}
SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def parse(ts):
    return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ")


def load_events(path):
    with open(path) as f:
        return [json.loads(line) for line in f if line.strip()]


def load_iocs():
    iocs = defaultdict(set)
    with open(os.path.join(ROOT, "iocs", "iocs.csv")) as f:
        for row in csv.DictReader(f):
            iocs[row["type"]].add(row["indicator"].replace("[.]", "."))
    return iocs


def finding(rule, sev, mitre, e, msg):
    return {"rule": rule, "severity": sev, "mitre": mitre, "ts": e["ts"], "host": e["host"],
            "user": e["user"], "message": msg}


def run_detections(events):
    iocs = load_iocs()
    out = []

    for e in events:
        d, ev = e["details"], e["event"]

        # R01 - Phishing: malicious sender/domain, or credentials posted to it
        if ev == "email_delivered" and d["sender"].split("@")[-1] in iocs["domain"]:
            out.append(finding("R01", "HIGH", "T1566.002", e, f"Phishing mail from {d['sender']}"))
        if ev in ("web_visit", "web_post"):
            dom = d["url"].split("/")[2]
            if dom in iocs["domain"]:
                label = "credentials POSTed to" if ev == "web_post" else "visited"
                out.append(finding("R01", "HIGH", "T1566.002", e, f"User {label} malicious domain {dom}"))

        # R02 - VPN login from unusual country / known-bad IP
        if ev == "vpn_login" and (d["country"] not in HOME_COUNTRIES or d["src_ip"] in iocs["ip"]):
            out.append(finding("R02", "HIGH", "T1078", e,
                               f"VPN login from {d['src_ip']} ({d['country']}) without MFA"))

        # R04 - encoded PowerShell
        if ev == "process_create" and "powershell" in d["image"].lower() and \
                any(f in d["cmdline"].lower() for f in (" -enc", " -encodedcommand")):
            out.append(finding("R04", "HIGH", "T1059.001", e,
                               f"Encoded PowerShell spawned by {d['parent']}"))

        # R05 - LSASS access
        if ev == "process_access" and d["target"].lower() == "lsass.exe" and "system32" not in d["image"].lower():
            out.append(finding("R05", "CRITICAL", "T1003.001", e,
                               f"{d['image']} accessed LSASS memory (credential dumping)"))

        # R06 - service account logon from a workstation (SMB type 3 / RDP type 10)
        if ev == "logon_success" and e["user"].startswith("svc-") and d.get("src_host", "").startswith("WS-") \
                and d["logon_type"] in (3, 10) and e["host"] in ("FS-01", "DC-01"):
            kind = "RDP" if d["logon_type"] == 10 else "SMB"
            out.append(finding("R06", "HIGH", "T1021.00" + ("1" if kind == "RDP" else "2"), e,
                               f"Service account {e['user']} {kind} logon to {e['host']} from {d['src_host']}"))

        # R07 - large egress to external IP
        if ev == "net_egress" and d["bytes"] >= 1_000_000_000:
            sev = "CRITICAL" if d["dst_ip"] in iocs["ip"] else "HIGH"
            out.append(finding("R07", sev, "T1041", e,
                               f"{d['bytes']/1e9:.1f} GB sent to {d['dst_ip']}:{d['port']}"))

        # R08 - recovery inhibition
        if ev == "process_create" and "vssadmin" in d["image"].lower() and "delete shadows" in d["cmdline"].lower():
            out.append(finding("R08", "CRITICAL", "T1490", e, "Volume shadow copies deleted"))
        if ev == "service_stop" and "backup" in d["service"].lower():
            out.append(finding("R08", "CRITICAL", "T1489", e, f"Backup service '{d['service']}' stopped"))

        # R09 - mass encryption
        if ev == "file_rename_bulk" and d["count"] >= 1000:
            out.append(finding("R09", "CRITICAL", "T1486", e,
                               f"{d['count']} files renamed to {d['new_extension']} in {d['duration_sec']}s"))
        if ev == "file_create" and d["name"].lower().startswith("readme_restore"):
            out.append(finding("R09", "CRITICAL", "T1486", e, f"Ransom note {d['name']} dropped ({d['copies']} copies)"))

    # R03 - brute force: >=5 failures within 10 minutes followed by a success (stateful)
    fails = defaultdict(list)
    for e in events:
        key = (e["user"], e["details"].get("src_host"))
        if e["event"] == "logon_failed":
            fails[key].append(parse(e["ts"]))
        elif e["event"] == "logon_success":
            recent = [x for x in fails[key] if 0 <= (parse(e["ts"]) - x).total_seconds() <= 600]
            if len(recent) >= 5:
                out.append(finding("R03", "HIGH", "T1110.001", e,
                                   f"{len(recent)} failed logons then success for {e['user']} from {key[1]}"))
                fails[key] = []

    out.sort(key=lambda f: f["ts"])
    return out


def main():
    path = next((a for a in sys.argv[1:] if not a.startswith("--")), os.path.join(ROOT, "logs", "events.jsonl"))
    if not os.path.exists(path):
        sys.exit("Log file not found. Run: python scripts/generate_logs.py")
    events = load_events(path)
    findings = run_detections(events)
    if "--json" in sys.argv:
        print(json.dumps(findings, indent=2))
        return
    print(f"Analysed {len(events)} events\n")
    for f in findings:
        print(f"[{f['severity']:<8}] {f['ts']}  {f['rule']}  {f['mitre']:<10} {f['host']:<8} {f['message']}")
    by = defaultdict(int)
    for f in findings:
        by[f["severity"]] += 1
    print("\nTotal findings:", len(findings), "|", ", ".join(f"{k}={v}" for k, v in sorted(by.items(), key=lambda x: SEV_ORDER[x[0]])))


if __name__ == "__main__":
    main()
