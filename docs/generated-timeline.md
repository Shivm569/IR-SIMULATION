# Auto-Generated Incident Timeline

Produced by `scripts/build_timeline.py` from `logs/events.jsonl`.

| Time (UTC) | Rule | Severity | Host | MITRE | Finding |
|---|---|---|---|---|---|
| 08:42:00 | R01 | HIGH | MAIL-GW | T1566.002 | Phishing mail from invoice-update@acme-billing.example |
| 08:47:00 | R01 | HIGH | WS-014 | T1566.002 | User visited malicious domain secure-docs-login.example |
| 08:49:00 | R01 | HIGH | WS-014 | T1566.002 | User credentials POSTed to malicious domain secure-docs-login.example |
| 09:15:00 | R02 | HIGH | VPN-GW | T1078 | VPN login from 203.0.113.45 (RO) without MFA |
| 10:05:10 | R03 | HIGH | WS-014 | T1110.001 | 6 failed logons then success for svc-backup from WS-014 |
| 10:30:00 | R04 | HIGH | WS-014 | T1059.001 | Encoded PowerShell spawned by winword.exe |
| 10:31:00 | R01 | HIGH | WS-014 | T1566.002 | User visited malicious domain cdn-update.example |
| 10:42:00 | R05 | CRITICAL | WS-014 | T1003.001 | C:\Users\Public\nvloader.exe accessed LSASS memory (credential dumping) |
| 11:10:00 | R06 | HIGH | FS-01 | T1021.002 | Service account svc-backup SMB logon to FS-01 from WS-014 |
| 11:25:00 | R06 | HIGH | DC-01 | T1021.001 | Service account svc-backup RDP logon to DC-01 from WS-014 |
| 12:10:00 | R07 | CRITICAL | FS-01 | T1041 | 4.2 GB sent to 198.51.100.77:443 |
| 13:30:00 | R08 | CRITICAL | FS-01 | T1490 | Volume shadow copies deleted |
| 13:32:00 | R08 | CRITICAL | FS-01 | T1489 | Backup service 'BackupExecAgent' stopped |
| 13:35:00 | R09 | CRITICAL | FS-01 | T1486 | 18452 files renamed to .nvlock in 118s |
| 13:36:00 | R09 | CRITICAL | FS-01 | T1486 | Ransom note README_RESTORE.txt dropped (37 copies) |

**First detection:** 2026-03-10T08:42:00Z  
**Last detection:** 2026-03-10T13:36:00Z  
**Total findings:** 15
