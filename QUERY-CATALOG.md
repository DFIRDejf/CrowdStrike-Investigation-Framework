# CQL Query Catalog

[← Home](README.md) · [MITRE techniques](MITRE-TECHNIQUE-INDEX.md) · [Telemetry index](TELEMETRY-INDEX.md)

**111 queries** · **14 ATT&CK tactic categories**

Find a query with **Ctrl+F**. IDs and direct links remain stable when a query title changes.

## All queries

| Query | Stable ID | Category | MITRE | Status |
|:--|:--|:--|:--|:--|
| [Reconnaissance Footprints in Browser History](01-Reconnaissance/README.md#cs-ta0043-001) | `CS-TA0043-001` | [Reconnaissance](01-Reconnaissance/README.md) | T1592 (context) | `Requires Validation` |
| [Potential Inbound Scan Touchpoints](01-Reconnaissance/README.md#cs-ta0043-002) | `CS-TA0043-002` | [Reconnaissance](01-Reconnaissance/README.md) | T1595 (context) | `Requires Validation` |
| [Host and Domain Reconnaissance Commands](01-Reconnaissance/README.md#cs-ta0043-003) | `CS-TA0043-003` | [Reconnaissance](01-Reconnaissance/README.md) | T1593 / T1046 (context) | `Requires Validation` |
| [Browser Downloads of Executables and Archives](02-Resource-Development/README.md#cs-ta0042-001) | `CS-TA0042-001` | [Resource Development](02-Resource-Development/README.md) | T1588 (context) | `Requires Validation` |
| [Penetration Testing Utility Execution](02-Resource-Development/README.md#cs-ta0042-002) | `CS-TA0042-002` | [Resource Development](02-Resource-Development/README.md) | T1588 (context) | `Requires Validation` |
| [Suspicious Browser Download URL Extensions](02-Resource-Development/README.md#cs-ta0042-003) | `CS-TA0042-003` | [Resource Development](02-Resource-Development/README.md) | T1588 (context) | `Requires Validation` |
| [Potentially Risky Browser Downloads](03-Initial-Access/README.md#cs-ta0001-001) | `CS-TA0001-001` | [Initial Access](03-Initial-Access/README.md) | T1189 / T1204 (contextual) | `Requires Validation` |
| [Failed SSO Authentication Event Inventory](03-Initial-Access/README.md#cs-ta0001-002) | `CS-TA0001-002` | [Initial Access](03-Initial-Access/README.md) | T1110 | `Requires Validation` |
| [VPN and Identity Sign-In Event Inventory](03-Initial-Access/README.md#cs-ta0001-003) | `CS-TA0001-003` | [Initial Access](03-Initial-Access/README.md) | T1133 / T1078 | `Requires Validation` |
| [Domain Interactive Logon Events](03-Initial-Access/README.md#cs-ta0001-004) | `CS-TA0001-004` | [Initial Access](03-Initial-Access/README.md) | T1078 | `Requires Validation` |
| [Remote Access Client Execution](03-Initial-Access/README.md#cs-ta0001-005) | `CS-TA0001-005` | [Initial Access](03-Initial-Access/README.md) | T1133 (context) | `Requires Validation` |
| [Script Control Detection Events](04-Execution/README.md#cs-ta0002-001) | `CS-TA0002-001` | [Execution](04-Execution/README.md) | T1059 (contextual) | `Requires Validation` |
| [Remote Command Response Events](04-Execution/README.md#cs-ta0002-002) | `CS-TA0002-002` | [Execution](04-Execution/README.md) | T1059 (contextual) | `Requires Validation` |
| [PowerShell Child Process Within One Minute](04-Execution/README.md#cs-ta0002-003) | `CS-TA0002-003` | [Execution](04-Execution/README.md) | T1059.001 | `Requires Validation` |
| [Suspicious PowerShell Interpreter Arguments](04-Execution/README.md#cs-ta0002-004) | `CS-TA0002-004` | [Execution](04-Execution/README.md) | T1059.001 | `Requires Validation` |
| [WMI Remote Process Creation Commands](04-Execution/README.md#cs-ta0002-005) | `CS-TA0002-005` | [Execution](04-Execution/README.md) | T1047 | `Requires Validation` |
| [Windows Shell and Command Interpreter Activity](04-Execution/README.md#cs-ta0002-006) | `CS-TA0002-006` | [Execution](04-Execution/README.md) | T1059.003 | `Requires Validation` |
| [Selected Offensive Tool Names in Command Lines](04-Execution/README.md#cs-ta0002-007) | `CS-TA0002-007` | [Execution](04-Execution/README.md) | T1059 / T1204 (contextual) | `Requires Validation` |
| [Shell and Packed Executable Event Inventory](04-Execution/README.md#cs-ta0002-008) | `CS-TA0002-008` | [Execution](04-Execution/README.md) | T1059 / T1027 | `Requires Validation` |
| [Command History and New Script Telemetry](04-Execution/README.md#cs-ta0002-009) | `CS-TA0002-009` | [Execution](04-Execution/README.md) | T1059 | `Requires Validation` |
| [Baseline Process and Ancestry Context](04-Execution/README.md#cs-ta0002-010) | `CS-TA0002-010` | [Execution](04-Execution/README.md) | T1059 (context) | `Requires Validation` |
| [Executable File Written After User Logon](04-Execution/README.md#cs-fa-001) | `CS-FA-001` | [Execution](04-Execution/README.md) | Investigation utility | `Requires Validation` |
| [Command History Scoped Search](04-Execution/README.md#cs-qb-002) | `CS-QB-002` | [Execution](04-Execution/README.md) | Investigation utility | `Requires Validation` |
| [Command History and Process Rollup](04-Execution/README.md#cs-qb-004) | `CS-QB-004` | [Execution](04-Execution/README.md) | Investigation utility | `Requires Validation` |
| [Encoded PowerShell Query Profiling](04-Execution/README.md#cs-cqf-004) | `CS-CQF-004` | [Execution](04-Execution/README.md) | Performance diagnostic | `Requires Validation` |
| [Local Account Creation via Net](05-Persistence/README.md#cs-ta0003-001) | `CS-TA0003-001` | [Persistence](05-Persistence/README.md) | T1136 | `Requires Validation` |
| [Scheduled Task Registration and Autorun Telemetry](05-Persistence/README.md#cs-ta0003-002) | `CS-TA0003-002` | [Persistence](05-Persistence/README.md) | T1053.005 / T1547.001 | `Requires Validation` |
| [Run Keys and Startup Artifact Telemetry](05-Persistence/README.md#cs-ta0003-003) | `CS-TA0003-003` | [Persistence](05-Persistence/README.md) | T1547.001 | `Requires Validation` |
| [Account Creation and Modification Events](05-Persistence/README.md#cs-ta0003-004) | `CS-TA0003-004` | [Persistence](05-Persistence/README.md) | T1136 / T1098 | `Requires Validation` |
| [Windows Service Creation and Reconfiguration](05-Persistence/README.md#cs-ta0003-005) | `CS-TA0003-005` | [Persistence](05-Persistence/README.md) | T1543.003 | `Requires Validation` |
| [WMI Provider Registration and Autorun Artifacts](05-Persistence/README.md#cs-ta0003-006) | `CS-TA0003-006` | [Persistence](05-Persistence/README.md) | T1546.003 / T1547.001 | `Requires Validation` |
| [Account Added to Privileged Group Event Family](06-Privilege-Escalation/README.md#cs-ta0004-001) | `CS-TA0004-001` | [Privilege Escalation](06-Privilege-Escalation/README.md) | T1098 | `Requires Validation` |
| [Windows Token Privilege Modification Events](06-Privilege-Escalation/README.md#cs-ta0004-002) | `CS-TA0004-002` | [Privilege Escalation](06-Privilege-Escalation/README.md) | T1134 | `Requires Validation` |
| [Elevation and Token Abuse Command Indicators](06-Privilege-Escalation/README.md#cs-ta0004-003) | `CS-TA0004-003` | [Privilege Escalation](06-Privilege-Escalation/README.md) | T1548 / T1134 | `Requires Validation` |
| [Local Group and Directory Account Changes](06-Privilege-Escalation/README.md#cs-ta0004-004) | `CS-TA0004-004` | [Privilege Escalation](06-Privilege-Escalation/README.md) | T1098 | `Requires Validation` |
| [Security Control Modification Commands](07-Defense-Evasion/README.md#cs-ta0005-001) | `CS-TA0005-001` | [Defense Evasion](07-Defense-Evasion/README.md) | T1562.001 / T1070 (contextual) | `Requires Validation` |
| [Sensor and Prevention Diagnostics](07-Defense-Evasion/README.md#cs-ta0005-002) | `CS-TA0005-002` | [Defense Evasion](07-Defense-Evasion/README.md) | T1562.001 (contextual) | `Requires Validation` |
| [Security Log and Trace File Deletion](07-Defense-Evasion/README.md#cs-ta0005-003) | `CS-TA0005-003` | [Defense Evasion](07-Defense-Evasion/README.md) | T1070.004 | `Requires Validation` |
| [Firewall and WFP Modification Events](07-Defense-Evasion/README.md#cs-ta0005-004) | `CS-TA0005-004` | [Defense Evasion](07-Defense-Evasion/README.md) | T1562.004 | `Requires Validation` |
| [Unsigned Modules and Suspicious File Signatures](07-Defense-Evasion/README.md#cs-ta0005-005) | `CS-TA0005-005` | [Defense Evasion](07-Defense-Evasion/README.md) | T1027 / T1036 | `Requires Validation` |
| [Sensor Anti-Tamper and Bypass Telemetry](07-Defense-Evasion/README.md#cs-ta0005-006) | `CS-TA0005-006` | [Defense Evasion](07-Defense-Evasion/README.md) | T1562.001 | `Requires Validation` |
| [Suspicious Macro and Invalid Script Events](07-Defense-Evasion/README.md#cs-ta0005-007) | `CS-TA0005-007` | [Defense Evasion](07-Defense-Evasion/README.md) | T1027 | `Requires Validation` |
| [Potential Log Clearing Commands](07-Defense-Evasion/README.md#cs-ta0005-008) | `CS-TA0005-008` | [Defense Evasion](07-Defense-Evasion/README.md) | T1070 | `Requires Validation` |
| [Credential Dumping Command-Line Indicators](08-Credential-Access/README.md#cs-ta0006-001) | `CS-TA0006-001` | [Credential Access](08-Credential-Access/README.md) | T1003 | `Requires Validation` |
| [Authentication Failure and Brute Force Event Families](08-Credential-Access/README.md#cs-ta0006-002) | `CS-TA0006-002` | [Credential Access](08-Credential-Access/README.md) | T1110 (contextual) | `Requires Validation` |
| [Credential Access Detection Event Families](08-Credential-Access/README.md#cs-ta0006-003) | `CS-TA0006-003` | [Credential Access](08-Credential-Access/README.md) | T1003 | `Requires Validation` |
| [LSASS, SAM and NTDS Dumping Commands](08-Credential-Access/README.md#cs-ta0006-004) | `CS-TA0006-004` | [Credential Access](08-Credential-Access/README.md) | T1003.001 / T1003.002 | `Requires Validation` |
| [SAM Dump and Privileged Handle Detection Events](08-Credential-Access/README.md#cs-ta0006-005) | `CS-TA0006-005` | [Credential Access](08-Credential-Access/README.md) | T1003.002 | `Requires Validation` |
| [Kerberoasting and AS-REP Tooling Footprints](08-Credential-Access/README.md#cs-ta0006-006) | `CS-TA0006-006` | [Credential Access](08-Credential-Access/README.md) | T1558.003 / T1558.004 | `Requires Validation` |
| [DCSync and Directory Replication Indicators](08-Credential-Access/README.md#cs-ta0006-007) | `CS-TA0006-007` | [Credential Access](08-Credential-Access/README.md) | T1003.006 | `Requires Validation` |
| [KRBTGT-Related Directory Events](08-Credential-Access/README.md#cs-ta0006-008) | `CS-TA0006-008` | [Credential Access](08-Credential-Access/README.md) | T1558 (context) | `Requires Validation` |
| [Credential Stores and Sensitive Files](08-Credential-Access/README.md#cs-ta0006-009) | `CS-TA0006-009` | [Credential Access](08-Credential-Access/README.md) | T1552 / T1555 | `Requires Validation` |
| [Account and Domain Enumeration Commands](09-Discovery/README.md#cs-ta0007-001) | `CS-TA0007-001` | [Discovery](09-Discovery/README.md) | T1087 / T1069 / T1018 | `Requires Validation` |
| [High Port Diversity by Destination](09-Discovery/README.md#cs-ta0007-002) | `CS-TA0007-002` | [Discovery](09-Discovery/README.md) | T1046 | `Requires Validation` |
| [WMI Query Telemetry](09-Discovery/README.md#cs-ta0007-003) | `CS-TA0007-003` | [Discovery](09-Discovery/README.md) | T1047 / T1082 | `Requires Validation` |
| [Active Directory RPC Enumeration Events](09-Discovery/README.md#cs-ta0007-004) | `CS-TA0007-004` | [Discovery](09-Discovery/README.md) | T1087 / T1482 | `Requires Validation` |
| [Shares and Network Enumeration Commands](09-Discovery/README.md#cs-ta0007-005) | `CS-TA0007-005` | [Discovery](09-Discovery/README.md) | T1135 / T1046 | `Requires Validation` |
| [Domain Controller and Trust Discovery Commands](09-Discovery/README.md#cs-ta0007-006) | `CS-TA0007-006` | [Discovery](09-Discovery/README.md) | T1018 / T1482 | `Requires Validation` |
| [File-System Artifact Event Inventory](09-Discovery/README.md#cs-fa-002) | `CS-FA-002` | [Discovery](09-Discovery/README.md) | DFIR utility | `Requires Validation` |
| [Available Fields by Event Type](09-Discovery/README.md#cs-qb-006) | `CS-QB-006` | [Discovery](09-Discovery/README.md) | Operational utility | `Requires Validation` |
| [Observed Events by Name](09-Discovery/README.md#cs-qb-007) | `CS-QB-007` | [Discovery](09-Discovery/README.md) | Operational utility | `Requires Validation` |
| [Normalize Host and User Identity Across Schemas](09-Discovery/README.md#cs-qb-008) | `CS-QB-008` | [Discovery](09-Discovery/README.md) | Operational utility | `Requires Validation` |
| [Process Correlation Key Reference](09-Discovery/README.md#cs-qb-009) | `CS-QB-009` | [Discovery](09-Discovery/README.md) | Operational utility | `Requires Validation` |
| [Discovery Command Sequence within Five Minutes](09-Discovery/README.md#cs-cqf-003) | `CS-CQF-003` | [Discovery](09-Discovery/README.md) | T1082 / T1087 (contextual) | `Requires Validation` |
| [Browser Extension Inventory by Host](09-Discovery/README.md#cs-cqf-005) | `CS-CQF-005` | [Discovery](09-Discovery/README.md) | Software inventory / attack-surface context | `Requires Validation` |
| [High-Volume SMB Connections](10-Lateral-Movement/README.md#cs-ta0008-001) | `CS-TA0008-001` | [Lateral Movement](10-Lateral-Movement/README.md) | T1021.002 | `Requires Validation` |
| [SMB Server Audit Events](10-Lateral-Movement/README.md#cs-ta0008-002) | `CS-TA0008-002` | [Lateral Movement](10-Lateral-Movement/README.md) | T1021.002 | `Requires Validation` |
| [SMB Share Open Events](10-Lateral-Movement/README.md#cs-ta0008-003) | `CS-TA0008-003` | [Lateral Movement](10-Lateral-Movement/README.md) | T1021.002 | `Requires Validation` |
| [Remote Administration Process and Network Context](10-Lateral-Movement/README.md#cs-ta0008-004) | `CS-TA0008-004` | [Lateral Movement](10-Lateral-Movement/README.md) | T1021 (contextual) | `Requires Validation` |
| [PsExec WinRM and Remote Service Command Patterns](10-Lateral-Movement/README.md#cs-ta0008-005) | `CS-TA0008-005` | [Lateral Movement](10-Lateral-Movement/README.md) | T1021 / T1569.002 | `Requires Validation` |
| [SMB Client and Server Event Family Inventory](10-Lateral-Movement/README.md#cs-ta0008-006) | `CS-TA0008-006` | [Lateral Movement](10-Lateral-Movement/README.md) | T1021.002 / T1135 | `Requires Validation` |
| [SMB Client and Server Share Activity](10-Lateral-Movement/README.md#cs-ta0008-007) | `CS-TA0008-007` | [Lateral Movement](10-Lateral-Movement/README.md) | T1021.002 | `Requires Validation` |
| [SMB Logon Brute Force Events](10-Lateral-Movement/README.md#cs-ta0008-008) | `CS-TA0008-008` | [Lateral Movement](10-Lateral-Movement/README.md) | T1110 / T1021.002 | `Requires Validation` |
| [Windows Share Creation and Permission Changes](10-Lateral-Movement/README.md#cs-ta0008-009) | `CS-TA0008-009` | [Lateral Movement](10-Lateral-Movement/README.md) | T1021.002 | `Requires Validation` |
| [Remote Shell and Session Events](10-Lateral-Movement/README.md#cs-ta0008-010) | `CS-TA0008-010` | [Lateral Movement](10-Lateral-Movement/README.md) | T1021 | `Requires Validation` |
| [Inbound SMB, RDP and WinRM Connections](10-Lateral-Movement/README.md#cs-ta0008-011) | `CS-TA0008-011` | [Lateral Movement](10-Lateral-Movement/README.md) | T1021 | `Requires Validation` |
| [Archiving and Data Transfer Utilities](11-Collection/README.md#cs-ta0009-001) | `CS-TA0009-001` | [Collection](11-Collection/README.md) | T1560 / T1005 | `Requires Validation` |
| [Sensitive File and Critical File Access Telemetry](11-Collection/README.md#cs-ta0009-002) | `CS-TA0009-002` | [Collection](11-Collection/README.md) | T1005 (contextual) | `Requires Validation` |
| [Archive File Creation Event Families](11-Collection/README.md#cs-ta0009-003) | `CS-TA0009-003` | [Collection](11-Collection/README.md) | T1560 | `Requires Validation` |
| [Potential Data Staging Paths and Compression](11-Collection/README.md#cs-ta0009-004) | `CS-TA0009-004` | [Collection](11-Collection/README.md) | T1074.001 / T1560 | `Requires Validation` |
| [File Collection with Copy Utilities](11-Collection/README.md#cs-ta0009-005) | `CS-TA0009-005` | [Collection](11-Collection/README.md) | T1005 / T1039 | `Requires Validation` |
| [Potential Data Staging in Shared Paths](11-Collection/README.md#cs-ta0009-006) | `CS-TA0009-006` | [Collection](11-Collection/README.md) | T1074.001 / T1560 | `Requires Validation` |
| [File and USN Metadata for Archives](11-Collection/README.md#cs-ta0009-007) | `CS-TA0009-007` | [Collection](11-Collection/README.md) | T1005 / T1560 | `Requires Validation` |
| [Archive Output and High-Entropy Write Events](11-Collection/README.md#cs-ta0009-008) | `CS-TA0009-008` | [Collection](11-Collection/README.md) | T1560 | `Requires Validation` |
| [Specific Archive Format Writes](11-Collection/README.md#cs-ta0009-009) | `CS-TA0009-009` | [Collection](11-Collection/README.md) | T1560 | `Requires Validation` |
| [Potential Archive Artifacts in File Metadata](11-Collection/README.md#cs-fa-003) | `CS-FA-003` | [Collection](11-Collection/README.md) | DFIR / T1560 (contextual) | `Requires Validation` |
| [DNS and Network Connections by Process](12-Command-and-Control/README.md#cs-ta0011-001) | `CS-TA0011-001` | [Command and Control](12-Command-and-Control/README.md) | T1071.001 (contextual) | `Requires Validation` |
| [Process Execution and DNS Correlation](12-Command-and-Control/README.md#cs-ta0011-002) | `CS-TA0011-002` | [Command and Control](12-Command-and-Control/README.md) | Investigation utility | `Requires Validation` |
| [DNS Queries from Investigated Endpoints](12-Command-and-Control/README.md#cs-ta0011-003) | `CS-TA0011-003` | [Command and Control](12-Command-and-Control/README.md) | T1071.004 (contextual) | `Requires Validation` |
| [Remote Access and Tunneling Utility Commands](12-Command-and-Control/README.md#cs-ta0011-004) | `CS-TA0011-004` | [Command and Control](12-Command-and-Control/README.md) | T1572 / T1219 / T1105 | `Requires Validation` |
| [DNS Request and Suspicious DNS Detection Events](12-Command-and-Control/README.md#cs-ta0011-005) | `CS-TA0011-005` | [Command and Control](12-Command-and-Control/README.md) | T1071.004 | `Requires Validation` |
| [DNS Requests by Endpoint and Process](12-Command-and-Control/README.md#cs-ta0011-006) | `CS-TA0011-006` | [Command and Control](12-Command-and-Control/README.md) | T1071.004 (context) | `Requires Validation` |
| [SSH Tunnel Creation Events](12-Command-and-Control/README.md#cs-ta0011-007) | `CS-TA0011-007` | [Command and Control](12-Command-and-Control/README.md) | T1572 | `Requires Validation` |
| [Tunneling and Remote Tool Execution](12-Command-and-Control/README.md#cs-ta0011-008) | `CS-TA0011-008` | [Command and Control](12-Command-and-Control/README.md) | T1572 / T1219 | `Requires Validation` |
| [CIDR-Based Remote IP Search](12-Command-and-Control/README.md#cs-qb-001) | `CS-QB-001` | [Command and Control](12-Command-and-Control/README.md) | Investigation utility | `Requires Validation` |
| [Process and Network Connection Correlation](12-Command-and-Control/README.md#cs-qb-003) | `CS-QB-003` | [Command and Control](12-Command-and-Control/README.md) | Investigation utility | `Requires Validation` |
| [Parameterized Process Network Pivot](12-Command-and-Control/README.md#cs-qb-005) | `CS-QB-005` | [Command and Control](12-Command-and-Control/README.md) | Investigation utility | `Requires Validation` |
| [New PowerShell DNS Domains Versus Previous Six Days](12-Command-and-Control/README.md#cs-cqf-001) | `CS-CQF-001` | [Command and Control](12-Command-and-Control/README.md) | T1059.001 / T1071.004 (contextual) | `Requires Validation` |
| [Process and DNS Events Paired by Falcon PID](12-Command-and-Control/README.md#cs-cqf-002) | `CS-CQF-002` | [Command and Control](12-Command-and-Control/README.md) | C2 pivot / investigation utility | `Requires Validation` |
| [Sensitive File Access Followed by External Connection](13-Exfiltration/README.md#cs-ta0010-001) | `CS-TA0010-001` | [Exfiltration](13-Exfiltration/README.md) | T1041 (potential) | `Requires Validation` |
| [Command-Line Upload and Transfer Indicators](13-Exfiltration/README.md#cs-ta0010-002) | `CS-TA0010-002` | [Exfiltration](13-Exfiltration/README.md) | T1048 / T1567 (contextual) | `Requires Validation` |
| [Upload-Related Falcon Event Inventory](13-Exfiltration/README.md#cs-ta0010-003) | `CS-TA0010-003` | [Exfiltration](13-Exfiltration/README.md) | T1041 (context) | `Requires Validation` |
| [FTP Command Event Telemetry](13-Exfiltration/README.md#cs-ta0010-004) | `CS-TA0010-004` | [Exfiltration](13-Exfiltration/README.md) | T1048 | `Requires Validation` |
| [SRU Network and Application Usage](13-Exfiltration/README.md#cs-ta0010-005) | `CS-TA0010-005` | [Exfiltration](13-Exfiltration/README.md) | T1041 (coverage context) | `Requires Validation` |
| [Outbound Network Destination Event Counts](13-Exfiltration/README.md#cs-ta0010-006) | `CS-TA0010-006` | [Exfiltration](13-Exfiltration/README.md) | T1041 (lead) | `Requires Validation` |
| [Transfer and Cloud Upload Command Indicators](13-Exfiltration/README.md#cs-ta0010-007) | `CS-TA0010-007` | [Exfiltration](13-Exfiltration/README.md) | T1041 / T1567 | `Requires Validation` |
| [Backup and Recovery Inhibition Commands](14-Impact/README.md#cs-ta0040-001) | `CS-TA0040-001` | [Impact](14-Impact/README.md) | T1490 | `Requires Validation` |
| [Ransomware File Rename and Entropy Events](14-Impact/README.md#cs-ta0040-002) | `CS-TA0040-002` | [Impact](14-Impact/README.md) | T1486 | `Requires Validation` |
| [Host Prevention and Containment Event Inventory](14-Impact/README.md#cs-ta0040-003) | `CS-TA0040-003` | [Impact](14-Impact/README.md) | T1489 (context) | `Requires Validation` |
| [Service and Account Disruption Events](14-Impact/README.md#cs-ta0040-004) | `CS-TA0040-004` | [Impact](14-Impact/README.md) | T1489 / T1531 | `Requires Validation` |
| [Recovery Inhibition Command Indicators](14-Impact/README.md#cs-ta0040-005) | `CS-TA0040-005` | [Impact](14-Impact/README.md) | T1490 | `Requires Validation` |
**Status:** Requires Validation = not yet tested in the target Falcon environment. Tested and Production reviewed require recorded evidence.

[← Home](README.md)
