# 04 – Simulated Response (Timeline & Actions)

All times UTC, **10 March 2026**. The first part is the attacker's activity reconstructed from logs
(`scripts/build_timeline.py`); the second part is what the CSIRT did.

## A. Attack Timeline (reconstructed)

| Time | Host / Source | Event | MITRE |
|---|---|---|---|
| 08:42 | MAIL-GW | Phishing e-mail "Invoice #88231" delivered to `priya.sharma` | T1566.002 |
| 08:47 | PROXY-01 | `WS-014` visits `secure-docs-login[.]example` | T1566.002 |
| 08:49 | PROXY-01 | HTTP POST (credentials submitted) to the fake login page | T1056 |
| 09:15 | VPN-GW | VPN login `priya.sharma` from `203.0.113.45` (new country, no MFA) | T1078 |
| 10:05 | DC-01 | 6 failed + 1 successful logon for `svc-backup` from `WS-014` | T1110 |
| 10:30 | WS-014 | `powershell.exe -enc ...` downloads `nvloader.exe` | T1059.001 |
| 10:42 | WS-014 | `nvloader.exe` reads `lsass.exe` memory | T1003.001 |
| 11:10 | FS-01 | `svc-backup` network logon (SMB) from `WS-014` | T1021.002 |
| 11:25 | DC-01 | `svc-backup` RDP logon from `WS-014` | T1021.001 |
| 12:10 | FW | 4.2 GB outbound from `FS-01` to `198.51.100.77` | T1041 |
| 13:30 | FS-01 | `vssadmin delete shadows /all /quiet` | T1490 |
| 13:32 | FS-01 | Backup agent service stopped | T1489 |
| 13:35 | FS-01 | 18,452 files renamed to `.nvlock` | T1486 |
| 13:36 | FS-01 | `README_RESTORE.txt` created in each share | T1486 |

## B. CSIRT Response Timeline (simulated)

| Time | Phase | Action | Owner |
|---|---|---|---|
| 13:41 | Detection | Helpdesk receives 5 calls: "files will not open". AV alert on `FS-01`. Ticket `IR-2026-0310-01` opened | Helpdesk |
| 13:48 | Triage | Analyst confirms ransom note + `.nvlock` files. Severity set **Critical** | Lead Analyst |
| 13:52 | Activation | IC activates CSIRT, bridge call opened, management informed | IC |
| 13:58 | Containment | `FS-01` quarantined via EDR/switch port (powered **on** for RAM capture) | IT Lead |
| 14:03 | Containment | `svc-backup` and `priya.sharma` disabled, sessions killed | IT Lead |
| 14:08 | Containment | `BK-01` disconnected; offline backup tapes verified untouched | IT Lead |
| 14:15 | Containment | IOCs blocked at firewall/DNS/proxy; VPN set to geo-block | Network |
| 14:30 | Analysis | Memory + disk images of `FS-01` and `WS-014` taken, hashes recorded | Forensics |
| 14:50 | Analysis | Logs pulled; `detect_iocs.py` run → attack chain reconstructed back to phishing email | Lead Analyst |
| 15:20 | Scope | `DC-01` found accessed by `svc-backup`; treated as potentially compromised | Lead Analyst |
| 15:45 | Containment | Domain-wide reset of privileged/service passwords; `krbtgt` reset #1 | IT Lead |
| 16:10 | Analysis | Exfiltration of ~4.2 GB confirmed → Legal notified (breach assessment) | IC |
| 16:30 | Eradication | Enterprise IOC sweep: 3 other phishing recipients checked, 1 clicked, no compromise | Lead Analyst |
| 17:00 | Eradication | `WS-014` reimaged; `FS-01` rebuild started on clean VM | IT Lead |
| 18:30 | Eradication | `DC-01` audit: no new accounts/GPOs; `krbtgt` reset #2 | IT Lead |
| 19:00 | Recovery | Last clean backup (9 Mar 23:00) tested in sandbox – clean | Forensics |
| 20:30 | Recovery | `FS-01` data restored; ACLs re-applied | IT Lead |
| 21:15 | Recovery | Business owners validate data; shares reopened to staff | IT + Business |
| 11 Mar 09:00 | Monitoring | 30-day heightened monitoring begins, daily threat-hunt | SOC |
| 12 Mar | Notification | Client/regulator notification drafted by Legal | Legal |
| 17 Mar | Post-incident | Blameless post-mortem workshop | IC |

## C. Response Metrics

| Metric | Value |
|---|---|
| Attacker dwell time | 4 h 15 min (09:15 → 13:30) |
| **MTTD** (mean time to detect, from impact) | 11 min |
| **MTTD** (from initial compromise) | ~5 h |
| **MTTC** (time to contain after detection) | 17 min |
| **MTTR** (time to recover service) | ~7.5 h |
| Systems rebuilt | 2 (`WS-014`, `FS-01`) |
| Data lost | 0 (RPO ≈ 14.5 h of work, mostly re-created) |
| Ransom paid | 0 |

## D. Isolation Commands (examples, run by IT Lead)

```powershell
# Windows: block all traffic except to the management subnet (via firewall) – host stays powered ON
New-NetFirewallRule -DisplayName "IR-ISOLATE-OUT" -Direction Outbound -Action Block
New-NetFirewallRule -DisplayName "IR-ISOLATE-IN"  -Direction Inbound  -Action Block

# Disable compromised AD accounts and force sign-out
Disable-ADAccount -Identity svc-backup
Disable-ADAccount -Identity priya.sharma
```

```bash
# Linux-based firewall: block the exfil IP and the VPN source
iptables -A OUTPUT -d 198.51.100.77 -j DROP
iptables -A INPUT  -s 203.0.113.45  -j DROP
```
