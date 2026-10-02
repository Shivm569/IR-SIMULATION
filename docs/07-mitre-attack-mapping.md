# 07 – MITRE ATT&CK Mapping

| Tactic | Technique | ID | How it appeared |
|---|---|---|---|
| Initial Access | Phishing: Spearphishing Link | T1566.002 | Fake invoice e-mail |
| Initial Access / Persistence | Valid Accounts | T1078 | VPN login with stolen creds |
| Credential Access | Input Capture / Phishing for Information | T1056 / T1598 | Fake login page |
| Credential Access | Brute Force: Password Guessing | T1110.001 | 6 failures then success on `svc-backup` |
| Execution | PowerShell | T1059.001 | `powershell -enc` |
| Command & Control | Application Layer Protocol: Web | T1071.001 | HTTPS beacon to `cdn-update[.]example` |
| Credential Access | OS Credential Dumping: LSASS | T1003.001 | `nvloader.exe` reads LSASS |
| Lateral Movement | Remote Services: SMB/Windows Admin Shares | T1021.002 | `svc-backup` to `FS-01` |
| Lateral Movement | Remote Services: RDP | T1021.001 | `svc-backup` to `DC-01` |
| Collection | Data from Network Shared Drive | T1039 | `/Projects`, `/HR` |
| Exfiltration | Exfiltration Over C2 Channel | T1041 | 4.2 GB to `198.51.100.77` |
| Impact | Inhibit System Recovery | T1490 | `vssadmin delete shadows` |
| Impact | Service Stop | T1489 | Backup agent stopped |
| Impact | Data Encrypted for Impact | T1486 | `.nvlock` files |

## Coverage of Our Detections

| Technique | Detected by rule |
|---|---|
| T1566.002 | R01 |
| T1078 | R02 |
| T1110 | R03 |
| T1059.001 | R04 |
| T1003.001 | R05 |
| T1021.001/.002 | R06 |
| T1041 | R07 |
| T1490 / T1489 | R08 |
| T1486 | R09 |
