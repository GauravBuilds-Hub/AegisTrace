# AegisTrace MITRE ATT&CK Coverage

Configured rules: **24**
Unique mapped techniques: **22**

| Technique | Name | Category | Example Rule |
|---|---|---|---|
| T1110 | Brute Force | Authentication | AT-WIN-001 |
| T1059.001 | PowerShell | Execution | AT-PS-001 |
| T1070.001 | Clear Windows Event Logs | Defense Evasion | AT-WIN-002 |
| T1136.001 | Local Account | Persistence | AT-WIN-003 |
| T1098 | Account Manipulation | Persistence | AT-WIN-004 |
| T1543.003 | Windows Service | Persistence | AT-WIN-005 |
| T1053.005 | Scheduled Task | Persistence | AT-WIN-006 |
| T1105 | Ingress Tool Transfer | Command and Control | AT-LOL-001 |
| T1218.011 | Rundll32 | Defense Evasion | AT-LOL-002 |
| T1218.010 | Regsvr32 | Defense Evasion | AT-LOL-003 |
| T1218.005 | Mshta | Defense Evasion | AT-LOL-004 |
| T1197 | BITS Jobs | Persistence | AT-LOL-005 |
| T1490 | Inhibit System Recovery | Impact | AT-DEF-001 |
| T1087.001 | Local Account Discovery | Discovery | AT-DISC-001 |
| T1057 | Process Discovery | Discovery | AT-DISC-002 |
| T1016 | System Network Configuration Discovery | Discovery | AT-DISC-003 |
| T1082 | System Information Discovery | Discovery | AT-DISC-004 |
| T1003.001 | LSASS Memory | Credential Access | AT-CRED-001 |
| T1059.005 | Visual Basic | Execution | AT-SCRIPT-001 |
| T1059.003 | Windows Command Shell | Execution | AT-CMD-001 |
| T1060 | Registry Run Keys / Startup Folder | Persistence | AT-PERSIST-001 |
| T1021.001 | Remote Desktop Protocol | Lateral Movement | AT-NET-001 |

> This document describes configured detection mappings. Observed coverage depends on uploaded telemetry and triggered rules.