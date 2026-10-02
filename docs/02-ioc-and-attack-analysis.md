# 02 – IOC Identification & Attack Analysis

An **Indicator of Compromise (IOC)** is evidence that a system may have been breached.
Below, IOCs are grouped by type. The same data is in [`iocs/iocs.csv`](../iocs/iocs.csv) and is
detected automatically by [`scripts/detect_iocs.py`](../scripts/detect_iocs.py).

## 1. Network IOCs

| Indicator | Type | Context | Confidence |
|---|---|---|---|
| `203.0.113.45` | IP | VPN login for `priya.sharma` from unexpected country | High |
| `198.51.100.77` | IP | Receives ~4.2 GB outbound from `FS-01` (exfiltration) | High |
| `secure-docs-login[.]example` | Domain | Fake Microsoft 365 login (phishing site) | High |
| `acme-billing[.]example` | Domain | Sender domain of phishing email | High |
| `cdn-update[.]example` | Domain | Hosts PowerShell second-stage loader | High |

> *Defanging:* we write `[.]` instead of `.` so nobody clicks or resolves malicious domains by accident.

## 2. Host / Endpoint IOCs

| Indicator | Host | Meaning |
|---|---|---|
| `powershell.exe -enc <base64>` | WS-014 | Obfuscated PowerShell execution (T1059.001) |
| Non-system process opening `lsass.exe` | WS-014 | Credential dumping (T1003.001) |
| `vssadmin delete shadows /all /quiet` | FS-01 | Backup destruction (T1490) |
| Service `BackupExecAgent` stopped | FS-01 | Defence evasion before encryption |
| `nvloader.exe` in `C:\Users\Public\` | WS-014 | Fictional malware dropper |
| File extension `.nvlock` | FS-01 | Encrypted files |
| `README_RESTORE.txt` | FS-01 | Ransom note |
| SHA-256 `9f2b…c41e` (fictional) | WS-014 | Hash of `nvloader.exe` |

## 3. Account / Behavioural IOCs

* VPN login from a country the user has never used.
* 6 failed logons then 1 success for `svc-backup` from a **workstation** (service accounts should only log in from servers).
* `svc-backup` performing **interactive RDP** logon (type 10) to the domain controller – never normal.
* Mass file modification: 18,000+ renames in under 2 minutes.
* 4.2 GB outbound transfer to a previously unseen external IP (far above the normal baseline).

## 4. Source of the Attack

| Question | Answer |
|---|---|
| Who? | Financially motivated ransomware group (simulated "NOVA-LOCK") |
| From where? | External; VPN logins originate from `203.0.113.45` |
| Entry point (patient zero) | `WS-014`, user `priya.sharma` (Finance) |
| Root cause | Phishing **+** no MFA on VPN **+** weak service account password |

## 5. Method of Attack (kill chain)

| Stage (Lockheed Cyber Kill Chain) | What happened |
|---|---|
| Delivery | Phishing e-mail through MAIL-GW |
| Exploitation | User trust (social engineering) – no software vuln needed |
| Installation | `nvloader.exe` dropped to `C:\Users\Public\` |
| C2 | HTTPS beacons to `cdn-update[.]example` |
| Actions on objective | Credential dumping, exfiltration, encryption |

Detailed MITRE ATT&CK mapping: [07-mitre-attack-mapping.md](07-mitre-attack-mapping.md).

## 6. Scope Determination

Scope = *which systems, accounts and data were touched?*

| Category | Affected | Evidence |
|---|---|---|
| Accounts | `priya.sharma`, `svc-backup` (**both fully compromised**) | VPN + logon logs |
| Hosts | `WS-014`, `FS-01`, `DC-01` (accessed), `BK-01` (agent stopped) | Windows event logs |
| Data | ~4.2 GB from `FS-01` shares (`/Projects`, `/HR`) | Firewall egress log |
| Impact | 18,452 files encrypted on `FS-01` | File-activity log |
| Not affected | Other workstations, production client environment | No IOC hits (verified by sweep) |

**Severity classification:** *Critical* (confirmed data theft + business disruption).

## 7. Analysis Technique – Pivoting

1. Start from alert: ransom note on `FS-01`.
2. Pivot on user `svc-backup` → logons from `WS-014`.
3. Pivot on `WS-014` → encoded PowerShell + LSASS access.
4. Pivot on user at `WS-014` → `priya.sharma` → phishing click in proxy logs.
5. Pivot on phishing URL → all other recipients (3 more users received the mail; 1 clicked only, no credentials entered).
