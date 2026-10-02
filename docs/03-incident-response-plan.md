# 03 – Incident Response Plan

**Primary framework:** NIST SP 800-61 Rev. 2 – *Computer Security Incident Handling Guide*
**Cross-reference:** SANS PICERL (Preparation, Identification, Containment, Eradication, Recovery, Lessons Learned)

| NIST 800-61 phase | SANS equivalent |
|---|---|
| 1. Preparation | Preparation |
| 2. Detection & Analysis | Identification |
| 3. Containment, Eradication & Recovery | Containment → Eradication → Recovery |
| 4. Post-Incident Activity | Lessons Learned |

---

## 1. Roles & Responsibilities (CSIRT)

| Role | Responsibility | Example in this exercise |
|---|---|---|
| Incident Commander (IC) | Owns decisions, approves containment | Head of IT Security |
| Lead Analyst | Technical investigation, IOC hunting | SOC Tier-2 analyst |
| Forensics Lead | Evidence collection, chain of custody | DFIR engineer |
| IT/Infra Lead | Isolates, rebuilds and restores systems | Infra manager |
| Communications Lead | Staff, customer, media statements | Corporate comms |
| Legal / Compliance | Regulatory duties, breach notification | Legal counsel |
| Management Liaison | Business impact, budget, ransom decision | COO |

## 2. Severity Levels

| Level | Definition | Response target |
|---|---|---|
| Low | Single endpoint, no data loss | Next business day |
| Medium | Malware contained, no sensitive data | < 4 h |
| High | Multiple systems, suspected data access | < 1 h |
| **Critical** | Confirmed data theft / business outage / ransomware | **Immediate (< 15 min)** |

---

## PHASE 1 – PREPARATION  (before incident)

| # | Action | Done? (state at NovaTech) |
|---|---|---|
| 1.1 | Written IR policy & contact tree (24x7) | ❌ outdated |
| 1.2 | Deploy SIEM + EDR with central logging | ❌ missing |
| 1.3 | Enforce MFA for all remote & privileged access | ❌ partial |
| 1.4 | Offline / immutable backups, tested restores | ❌ not immutable |
| 1.5 | Network segmentation | ❌ flat network |
| 1.6 | Phishing awareness + simulations | ❌ annual slides only |
| 1.7 | Jump-kit (clean laptop, forensic tools, write-blockers) | ✅ |
| 1.8 | Tabletop exercises twice a year | ❌ never |

## PHASE 2 – DETECTION & ANALYSIS  (SANS: Identification)

**Step 2.1 – Receive and log the alert.** Open a ticket `IR-2026-0310-01`, record time, reporter, symptoms.

**Step 2.2 – Triage.** Questions to answer within 15 minutes:
* Is it a true positive? (ransom note + encrypted files = yes)
* What is affected? How far has it spread?
* Is data stolen? Is the attacker still active?

**Step 2.3 – Collect evidence (order of volatility).**
1. Memory (RAM) of affected hosts → 2. network connections → 3. running processes → 4. logs → 5. disk images.

**Step 2.4 – Hunt for IOCs** (see doc 02). Run `scripts/detect_iocs.py` against collected logs; query SIEM/EDR for the same IOCs across *all* hosts.

**Step 2.5 – Determine scope & classify severity.** Scope table in doc 02 → **Critical**.

**Step 2.6 – Notify.** IC activates the CSIRT, informs management and legal.

## PHASE 3A – CONTAINMENT

*Goal: stop the spread without destroying evidence.*

| Type | Action | Detail |
|---|---|---|
| **Short-term** | Isolate `FS-01`, `WS-014`, `DC-01` via EDR network quarantine / switch port shutdown | **Do NOT power off** – keeps RAM evidence |
| Short-term | Disable accounts `priya.sharma`, `svc-backup` | Revoke sessions & VPN tokens |
| Short-term | Block IOCs at firewall/proxy/DNS | `203.0.113.45`, `198.51.100.77`, 3 domains |
| Short-term | Disconnect `BK-01` & protect remaining backups | Prevent backup encryption |
| **Long-term** | Reset passwords for *all* privileged and service accounts; rotate `krbtgt` twice | Golden-ticket risk (DC was accessed) |
| Long-term | Temporary VPN restriction (geo-block + forced MFA) | |
| Long-term | Segment critical servers behind a temporary ACL | |

## PHASE 3B – ERADICATION

| # | Action |
|---|---|
| 3B.1 | Remove persistence: scheduled tasks, services, run keys, new local/domain accounts |
| 3B.2 | Delete `nvloader.exe` and related artefacts (after imaging) |
| 3B.3 | **Rebuild** `WS-014` and `FS-01` from known-good images (do not "clean" them) |
| 3B.4 | Audit `DC-01`: new accounts, GPO changes, DCSync traces; rebuild if tampering is found |
| 3B.5 | Patch and harden: disable SMBv1, restrict PowerShell (Constrained Language Mode), apply updates |
| 3B.6 | Enterprise-wide IOC sweep to confirm no other infected hosts |

## PHASE 3C – RECOVERY

| # | Action |
|---|---|
| 3C.1 | Verify backup integrity: restore a sample to an isolated sandbox, scan for malware |
| 3C.2 | Restore `FS-01` data from the last clean backup (night of 9 March) |
| 3C.3 | Staged return to service: DC → file server → workstations (priority by business impact) |
| 3C.4 | Enhanced monitoring for 30 days (new detections, watchlist of IOCs) |
| 3C.5 | Validate: file integrity checks, business owners sign off |
| 3C.6 | Ransom policy: **do not pay** – restore from backups; Legal and law-enforcement involved |

> **Recovery objectives:** RTO (Recovery Time Objective) for `FS-01` = 24 h; RPO (Recovery Point Objective) = 24 h.

## PHASE 4 – POST-INCIDENT ACTIVITY  (SANS: Lessons Learned)

1. Hold a blameless post-mortem within 7 days (see docs 05 and 06).
2. Finalise the incident report and evidence archive.
3. Update playbooks, detection rules and policies.
4. Track recommendations to completion (owner + due date).
5. Share indicators with industry peers / ISAC where appropriate.

## 3. Communication Plan

| Audience | Message | When | Owner |
|---|---|---|---|
| Executive team | Incident summary, impact, decisions needed | Within 1 h, then every 4 h | IC |
| All staff | "Do not open files/shares, report anything odd" | Within 2 h | Comms |
| Clients | Factual notice if client data affected | As legal requires (e.g. 72 h under GDPR) | Legal + Comms |
| Regulators / police | Breach notification / report | Per law | Legal |

## 4. Evidence Handling (Chain of Custody)

* Hash every image/log (SHA-256) at acquisition.
* Record who collected it, when, from where, and where it is stored.
* Work only on copies; originals stay read-only.

## 5. Decision Points

| Decision | Options | Chosen | Reason |
|---|---|---|---|
| Shut down vs isolate | Power off / network isolate | **Isolate** | Preserve RAM, stop spread |
| Pay ransom? | Pay / not pay | **Not pay** | Clean backups exist; no guarantee of decryption; funds crime |
| Rebuild vs clean | Clean in place / reimage | **Reimage** | Cannot trust compromised OS |
