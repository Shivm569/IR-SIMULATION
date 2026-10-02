#!/usr/bin/env python3
"""Generate deterministic, fully synthetic logs for the NovaTech ransomware simulation.

Output: logs/events.jsonl  (one JSON object per line)
All IPs/domains/hashes are fictional (RFC 5737 ranges, .example TLD).
"""
import json
import os
import random
from datetime import datetime, timedelta

random.seed(42)  # deterministic output -> reproducible exercise
DAY = datetime(2026, 3, 10)


def t(hhmm, sec=0):
    h, m = map(int, hhmm.split(":"))
    return (DAY + timedelta(hours=h, minutes=m, seconds=sec)).strftime("%Y-%m-%dT%H:%M:%SZ")


def ev(ts, source, host, user, event, **details):
    return {"ts": ts, "source": source, "host": host, "user": user, "event": event, "details": details}


def benign_noise():
    """Normal background activity so detections are not trivially obvious."""
    users = ["amit.verma", "neha.singh", "rahul.mehta", "kavya.nair", "priya.sharma"]
    hosts = {"amit.verma": "WS-003", "neha.singh": "WS-007", "rahul.mehta": "WS-011",
             "kavya.nair": "WS-021", "priya.sharma": "WS-014"}
    out = []
    for _ in range(60):
        u = random.choice(users)
        mm = random.randint(0, 59)
        hh = random.randint(7, 17)
        kind = random.choice(["logon", "web", "vpn", "fail"])
        ts = t(f"{hh:02d}:{mm:02d}", random.randint(0, 59))
        if kind == "logon":
            out.append(ev(ts, "DC-01", hosts[u], u, "logon_success", logon_type=2, src_host=hosts[u]))
        elif kind == "web":
            out.append(ev(ts, "PROXY-01", hosts[u], u, "web_visit",
                          url=random.choice(["https://intranet.novatech.example/wiki",
                                             "https://news.example/tech",
                                             "https://mail.novatech.example/inbox"])))
        elif kind == "vpn":
            out.append(ev(ts, "VPN-GW", "VPN-GW", u, "vpn_login", src_ip="192.0.2." + str(random.randint(10, 90)),
                          country="IN", mfa=False))
        else:  # a single failed logon (typo) - must NOT trigger brute-force rule
            out.append(ev(ts, "DC-01", hosts[u], u, "logon_failed", logon_type=2, src_host=hosts[u]))
    return out


def attack():
    e = []
    e.append(ev(t("08:42"), "MAIL-GW", "MAIL-GW", "priya.sharma", "email_delivered",
                sender="invoice-update@acme-billing.example", subject="Invoice #88231 overdue"))
    e.append(ev(t("08:47"), "PROXY-01", "WS-014", "priya.sharma", "web_visit",
                url="https://secure-docs-login.example/office365"))
    e.append(ev(t("08:49"), "PROXY-01", "WS-014", "priya.sharma", "web_post",
                url="https://secure-docs-login.example/office365/login", bytes=612))
    e.append(ev(t("09:15"), "VPN-GW", "VPN-GW", "priya.sharma", "vpn_login",
                src_ip="203.0.113.45", country="RO", mfa=False))
    for i in range(6):
        e.append(ev(t("10:04", 5 + i * 7), "DC-01", "WS-014", "svc-backup", "logon_failed",
                    logon_type=3, src_host="WS-014"))
    e.append(ev(t("10:05", 10), "DC-01", "WS-014", "svc-backup", "logon_success", logon_type=3, src_host="WS-014"))
    e.append(ev(t("10:30"), "EDR-LEGACY", "WS-014", "priya.sharma", "process_create",
                image="powershell.exe", cmdline="powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA",
                parent="winword.exe"))
    e.append(ev(t("10:31"), "PROXY-01", "WS-014", "priya.sharma", "web_visit",
                url="https://cdn-update.example/nvloader.exe"))
    e.append(ev(t("10:42"), "SYSMON", "WS-014", "priya.sharma", "process_access",
                image="C:\\Users\\Public\\nvloader.exe", target="lsass.exe", access="0x1010",
                sha256="9f2b1c7e5d3a4b6f8e0a1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0dc41e"))
    e.append(ev(t("11:10"), "FS-01", "FS-01", "svc-backup", "logon_success", logon_type=3, src_host="WS-014"))
    e.append(ev(t("11:25"), "DC-01", "DC-01", "svc-backup", "logon_success", logon_type=10, src_host="WS-014"))
    e.append(ev(t("12:10"), "FW", "FS-01", "svc-backup", "net_egress", dst_ip="198.51.100.77",
                bytes=4_200_000_000, port=443))
    e.append(ev(t("13:30"), "SYSMON", "FS-01", "svc-backup", "process_create",
                image="vssadmin.exe", cmdline="vssadmin delete shadows /all /quiet", parent="cmd.exe"))
    e.append(ev(t("13:32"), "FS-01", "FS-01", "svc-backup", "service_stop", service="BackupExecAgent"))
    e.append(ev(t("13:35"), "FS-01", "FS-01", "svc-backup", "file_rename_bulk", count=18452,
                new_extension=".nvlock", duration_sec=118))
    e.append(ev(t("13:36"), "FS-01", "FS-01", "svc-backup", "file_create", name="README_RESTORE.txt", copies=37))
    e.append(ev(t("13:41"), "HELPDESK", "HELPDESK", "multiple", "user_report",
                text="Files will not open / strange .nvlock extension"))
    return e


def main():
    events = benign_noise() + attack()
    events.sort(key=lambda x: x["ts"])
    os.makedirs("logs", exist_ok=True)
    with open("logs/events.jsonl", "w") as f:
        for x in events:
            f.write(json.dumps(x) + "\n")
    print(f"Wrote {len(events)} events to logs/events.jsonl")


if __name__ == "__main__":
    main()
