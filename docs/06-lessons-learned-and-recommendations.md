# 06 – Lessons Learned & Recommendations

## 1. Key Lessons Learned

1. **Identity is the new perimeter.** One stolen password opened the door – MFA everywhere is non-negotiable.
2. **Service accounts are high-value targets.** Treat them as privileged: long random secrets, restricted logon, monitoring.
3. **Visibility beats speed.** A 4-hour dwell time is a monitoring failure, not an attacker-skill success.
4. **Backups must survive the attacker.** Offline / immutable copies saved the business.
5. **Practice makes response fast.** Playbooks and drills cut decision time.
6. **Assume breach.** Segmentation and least privilege limit blast radius.

## 2. Recommendations (Prioritised Roadmap)

Priority: **P1** = within 30 days, **P2** = 90 days, **P3** = 180 days.

| ID | Recommendation | Fixes gap | Priority | Owner | Effort |
|---|---|---|---|---|---|
| R1 | Enforce MFA (phishing-resistant where possible) for VPN, e-mail, admin access | G1 | P1 | IT Sec | Low |
| R2 | Replace `svc-backup` with a **gMSA / 25+ char random password**, deny interactive logon, restrict to `BK-01` only | G2, G3 | P1 | IT Infra | Low |
| R3 | Deploy EDR on all endpoints/servers with ransomware & credential-theft protection | G4 | P1 | IT Sec | Medium |
| R4 | Implement **immutable/offline backups (3-2-1-1-0 rule)** and quarterly restore tests | G8 | P1 | IT Infra | Medium |
| R5 | Stand up a SIEM (e.g. Wazuh/Elastic/Sentinel) with the rules in `detections/` | G5 | P2 | SOC | Medium |
| R6 | Network segmentation: user VLAN ↔ server VLAN firewall rules; block workstation→DC RDP/SMB | G6 | P2 | Network | High |
| R7 | Enable Credential Guard and LSASS as Protected Process Light | G4 | P2 | IT Infra | Low |
| R8 | Email security: DMARC/DKIM/SPF enforcement, URL rewriting, attachment sandbox | G9 | P2 | IT Sec | Medium |
| R9 | Monthly phishing simulations + short training; report-phish button | G10 | P2 | Security Awareness | Low |
| R10 | DLP / NetFlow alerting on large outbound transfers | G7 | P2 | Network | Medium |
| R11 | Tiered admin model + LAPS + Privileged Access Workstations | G3, G6 | P3 | IT Infra | High |
| R12 | Update IR plan, create playbooks, run **tabletop exercises twice a year** | G11 | P1 | CISO | Low |
| R13 | PowerShell hardening: Script Block Logging, Constrained Language Mode, AMSI | G4 | P2 | IT Sec | Low |
| R14 | Patch & vulnerability management SLA (critical ≤ 7 days) | General | P2 | IT Ops | Medium |
| R15 | Cyber-insurance review & retainer with an external DFIR firm | G11 | P3 | CISO | Low |

## 3. Proposed Modifications to the Security Framework

Using the **NIST Cybersecurity Framework 2.0** functions:

| NIST CSF 2.0 function | Current | Target improvements |
|---|---|---|
| **Govern** | No formal ownership | Appoint CISO, risk register, annual review |
| **Identify** | No asset inventory | CMDB, data classification, crown-jewel mapping |
| **Protect** | Passwords + AV | MFA, EDR, segmentation, hardened configs, training |
| **Detect** | None | SIEM, EDR alerts, UEBA, 24x7 monitoring or MDR |
| **Respond** | Ad hoc | Tested IR plan, playbooks, retainer |
| **Recover** | Backups (partly vulnerable) | Immutable backups, DR runbooks, RTO/RPO tests |

## 4. Success Metrics (KPIs)

| KPI | Before | Target |
|---|---|---|
| MFA coverage | ~5 % | 100 % |
| Mean time to detect (MTTD) | ~5 h | < 15 min |
| Mean time to contain (MTTC) | 17 min | < 10 min |
| Phishing click rate | unknown (est. 25 %) | < 5 % |
| Backup restore test success | never tested | 100 % quarterly |
| Endpoints with EDR | 0 % | 100 % |
| Privileged accounts with MFA | 100 % admins | 100 % incl. service accts via gMSA |

## 5. Action Tracker Template

| ID | Action | Owner | Due | Status |
|---|---|---|---|---|
| R1 | MFA rollout | IT Sec | 2026-04-15 | In progress |
| R2 | gMSA for backup | IT Infra | 2026-04-10 | Done |
| … | … | … | … | … |
