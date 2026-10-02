# 05 – Post-Incident Analysis

## 1. Executive Summary

On 10 March 2026 NovaTech Solutions suffered a ransomware attack that began with a phishing e-mail.
The attacker stole a Finance user's credentials, entered through a VPN without MFA, harvested a
weak service-account credential, moved laterally to the file server and domain controller, exfiltrated
~4.2 GB of data and encrypted 18,452 files. The incident was detected ~11 minutes after the encryption
began and contained in 17 more minutes. All data was restored from backups; **no ransom was paid**.
The incident was possible because of **multiple preventable control failures**.

## 2. Root Cause Analysis – "5 Whys"

1. **Why were files encrypted?** The attacker had admin-level access to `FS-01`.
2. **Why did they have it?** They stole `svc-backup` credentials from memory on `WS-014`.
3. **Why could they run credential-dumping tools?** Legacy AV only; no EDR, no LSASS protection.
4. **Why was a service account usable from a workstation?** Flat network, no logon restrictions, weak password.
5. **Why was the attacker able to start at all?** Phishing succeeded and VPN required no MFA.

**Root causes:** (a) no MFA, (b) weak/over-privileged service account, (c) no segmentation, (d) no EDR/SIEM,
(e) insufficient user awareness training, (f) backups reachable with the same credentials.

## 3. Gap Analysis – Security Setup

| # | Gap found | Evidence | Impact | Severity |
|---|---|---|---|---|
| G1 | VPN without MFA for normal users | Login from `203.0.113.45` succeeded with password only | Initial access | Critical |
| G2 | Weak, never-rotated service-account password | `svc-backup` cracked after 6 attempts | Lateral movement | Critical |
| G3 | Service account allowed interactive/RDP logon | Event 4624 type 10 on `DC-01` | Domain controller exposure | High |
| G4 | No EDR; PowerShell/LSASS activity not alerted | Alert only after encryption | 4 h undetected | Critical |
| G5 | No central logging/SIEM | Logs had to be manually collected | Slow analysis | High |
| G6 | Flat network (workstation → DC via RDP/SMB) | Lateral movement succeeded | Wide blast radius | High |
| G7 | No outbound data-loss monitoring | 4.2 GB left unnoticed | Data theft | High |
| G8 | Backups on domain, not immutable | Agent stopped by attacker | Nearly lost recovery option | High |
| G9 | Weak email filtering (no URL sandbox) | Phishing delivered to 4 users | Initial vector | Medium |
| G10 | No phishing awareness testing | User entered password | Initial vector | Medium |
| G11 | IR plan outdated & never practised | Slow first 10 minutes | Slower response | Medium |

## 4. What Went Well

* Jump-kit was ready; RAM images taken before any shutdown.
* Offline tape backups survived and enabled recovery without paying.
* Quick decision to *isolate, not power off*.
* Helpdesk escalated the pattern ("many users, same symptom") quickly.
* Clear incident commander; communication cadence kept management informed.

## 5. What Did Not Go Well

* 4 h 15 min of attacker activity went unnoticed.
* Logs scattered over hosts; manual collection cost ~40 min.
* No pre-approved contact list for legal/PR – calls made ad hoc.
* Unclear who may authorise shutting down production servers (decision delay ~5 min).

## 6. Impact Assessment

| Dimension | Impact |
|---|---|
| Operational | File server unavailable ~7.5 h; ~120 staff affected |
| Financial (estimated) | Recovery labour, downtime, legal review: ~USD 85,000 |
| Data | 4.2 GB exfiltrated (project files, some HR records) |
| Regulatory | Personal data involved → breach notification assessment required |
| Reputational | Potential client trust impact; mitigated by transparent communication |

## 7. Detection Opportunities Missed ("where could we have caught it?")

| Time | Opportunity | Control that would have caught it |
|---|---|---|
| 08:42 | Phishing mail | URL sandbox / DMARC / banner |
| 09:15 | Foreign VPN login | Geo-IP alert + MFA |
| 10:05 | Repeated failed logons | SIEM brute-force rule |
| 10:30 | Encoded PowerShell | EDR / script-block-logging alert |
| 10:42 | LSASS access | EDR / Credential Guard |
| 11:25 | Service account RDP | Logon-type anomaly rule |
| 12:10 | 4.2 GB egress | DLP / NetFlow baseline |
| 13:30 | `vssadmin delete shadows` | Command-line detection |

> The attack could have been stopped at **eight** separate points. Layered defence ("defence in depth") would have broken the chain early.
