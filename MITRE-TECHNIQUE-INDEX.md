# MITRE ATT&CK Technique Index

[← Home](README.md) · [All queries](QUERY-CATALOG.md)

**62 ATT&CK technique IDs** referenced in query metadata. Not a measure of validated detection coverage.

| Technique | Queries | Count |
|:--|:--|--:|
| `T1003` | [Credential Dumping Command-Line Indicators](08-Credential-Access/README.md#cs-ta0006-001) · [Credential Access Detection Event Families](08-Credential-Access/README.md#cs-ta0006-003) | 2 |
| `T1003.001` | [LSASS, SAM and NTDS Dumping Commands](08-Credential-Access/README.md#cs-ta0006-004) | 1 |
| `T1003.002` | [LSASS, SAM and NTDS Dumping Commands](08-Credential-Access/README.md#cs-ta0006-004) · [SAM Dump and Privileged Handle Detection Events](08-Credential-Access/README.md#cs-ta0006-005) | 2 |
| `T1003.006` | [DCSync and Directory Replication Indicators](08-Credential-Access/README.md#cs-ta0006-007) | 1 |
| `T1005` | [Archiving and Data Transfer Utilities](11-Collection/README.md#cs-ta0009-001) · [Sensitive File and Critical File Access Telemetry](11-Collection/README.md#cs-ta0009-002) · [File Collection with Copy Utilities](11-Collection/README.md#cs-ta0009-005) · [File and USN Metadata for Archives](11-Collection/README.md#cs-ta0009-007) | 4 |
| `T1018` | [Account and Domain Enumeration Commands](09-Discovery/README.md#cs-ta0007-001) · [Domain Controller and Trust Discovery Commands](09-Discovery/README.md#cs-ta0007-006) | 2 |
| `T1021` | [Remote Administration Process and Network Context](10-Lateral-Movement/README.md#cs-ta0008-004) · [PsExec WinRM and Remote Service Command Patterns](10-Lateral-Movement/README.md#cs-ta0008-005) · [Remote Shell and Session Events](10-Lateral-Movement/README.md#cs-ta0008-010) · [Inbound SMB, RDP and WinRM Connections](10-Lateral-Movement/README.md#cs-ta0008-011) | 4 |
| `T1021.002` | [High-Volume SMB Connections](10-Lateral-Movement/README.md#cs-ta0008-001) · [SMB Server Audit Events](10-Lateral-Movement/README.md#cs-ta0008-002) · [SMB Share Open Events](10-Lateral-Movement/README.md#cs-ta0008-003) · [SMB Client and Server Event Family Inventory](10-Lateral-Movement/README.md#cs-ta0008-006) · [SMB Client and Server Share Activity](10-Lateral-Movement/README.md#cs-ta0008-007) · [SMB Logon Brute Force Events](10-Lateral-Movement/README.md#cs-ta0008-008) · [Windows Share Creation and Permission Changes](10-Lateral-Movement/README.md#cs-ta0008-009) | 7 |
| `T1027` | [Shell and Packed Executable Event Inventory](04-Execution/README.md#cs-ta0002-008) · [Unsigned Modules and Suspicious File Signatures](07-Defense-Evasion/README.md#cs-ta0005-005) · [Suspicious Macro and Invalid Script Events](07-Defense-Evasion/README.md#cs-ta0005-007) | 3 |
| `T1036` | [Unsigned Modules and Suspicious File Signatures](07-Defense-Evasion/README.md#cs-ta0005-005) | 1 |
| `T1039` | [File Collection with Copy Utilities](11-Collection/README.md#cs-ta0009-005) | 1 |
| `T1041` | [Sensitive File Access Followed by External Connection](13-Exfiltration/README.md#cs-ta0010-001) · [Upload-Related Falcon Event Inventory](13-Exfiltration/README.md#cs-ta0010-003) · [SRU Network and Application Usage](13-Exfiltration/README.md#cs-ta0010-005) · [Outbound Network Destination Event Counts](13-Exfiltration/README.md#cs-ta0010-006) · [Transfer and Cloud Upload Command Indicators](13-Exfiltration/README.md#cs-ta0010-007) | 5 |
| `T1046` | [Host and Domain Reconnaissance Commands](01-Reconnaissance/README.md#cs-ta0043-003) · [High Port Diversity by Destination](09-Discovery/README.md#cs-ta0007-002) · [Shares and Network Enumeration Commands](09-Discovery/README.md#cs-ta0007-005) | 3 |
| `T1047` | [WMI Remote Process Creation Commands](04-Execution/README.md#cs-ta0002-005) · [WMI Query Telemetry](09-Discovery/README.md#cs-ta0007-003) | 2 |
| `T1048` | [Command-Line Upload and Transfer Indicators](13-Exfiltration/README.md#cs-ta0010-002) · [FTP Command Event Telemetry](13-Exfiltration/README.md#cs-ta0010-004) | 2 |
| `T1053.005` | [Scheduled Task Registration and Autorun Telemetry](05-Persistence/README.md#cs-ta0003-002) | 1 |
| `T1059` | [Script Control Detection Events](04-Execution/README.md#cs-ta0002-001) · [Remote Command Response Events](04-Execution/README.md#cs-ta0002-002) · [Selected Offensive Tool Names in Command Lines](04-Execution/README.md#cs-ta0002-007) · [Shell and Packed Executable Event Inventory](04-Execution/README.md#cs-ta0002-008) · [Command History and New Script Telemetry](04-Execution/README.md#cs-ta0002-009) · [Baseline Process and Ancestry Context](04-Execution/README.md#cs-ta0002-010) | 6 |
| `T1059.001` | [PowerShell Child Process Within One Minute](04-Execution/README.md#cs-ta0002-003) · [Suspicious PowerShell Interpreter Arguments](04-Execution/README.md#cs-ta0002-004) · [New PowerShell DNS Domains Versus Previous Six Days](21-Cool-Query-Friday/README.md#cs-cqf-001) | 3 |
| `T1059.003` | [Windows Shell and Command Interpreter Activity](04-Execution/README.md#cs-ta0002-006) | 1 |
| `T1069` | [Account and Domain Enumeration Commands](09-Discovery/README.md#cs-ta0007-001) | 1 |
| `T1070` | [Security Control Modification Commands](07-Defense-Evasion/README.md#cs-ta0005-001) · [Potential Log Clearing Commands](07-Defense-Evasion/README.md#cs-ta0005-008) | 2 |
| `T1070.004` | [Security Log and Trace File Deletion](07-Defense-Evasion/README.md#cs-ta0005-003) | 1 |
| `T1071.001` | [DNS and Network Connections by Process](12-Command-and-Control/README.md#cs-ta0011-001) | 1 |
| `T1071.004` | [DNS Queries from Investigated Endpoints](12-Command-and-Control/README.md#cs-ta0011-003) · [DNS Request and Suspicious DNS Detection Events](12-Command-and-Control/README.md#cs-ta0011-005) · [DNS Requests by Endpoint and Process](12-Command-and-Control/README.md#cs-ta0011-006) · [New PowerShell DNS Domains Versus Previous Six Days](21-Cool-Query-Friday/README.md#cs-cqf-001) | 4 |
| `T1074.001` | [Potential Data Staging Paths and Compression](11-Collection/README.md#cs-ta0009-004) · [Potential Data Staging in Shared Paths](11-Collection/README.md#cs-ta0009-006) | 2 |
| `T1078` | [VPN and Identity Sign-In Event Inventory](03-Initial-Access/README.md#cs-ta0001-003) · [Domain Interactive Logon Events](03-Initial-Access/README.md#cs-ta0001-004) | 2 |
| `T1082` | [WMI Query Telemetry](09-Discovery/README.md#cs-ta0007-003) · [Discovery Command Sequence within Five Minutes](21-Cool-Query-Friday/README.md#cs-cqf-003) | 2 |
| `T1087` | [Account and Domain Enumeration Commands](09-Discovery/README.md#cs-ta0007-001) · [Active Directory RPC Enumeration Events](09-Discovery/README.md#cs-ta0007-004) · [Discovery Command Sequence within Five Minutes](21-Cool-Query-Friday/README.md#cs-cqf-003) | 3 |
| `T1098` | [Account Creation and Modification Events](05-Persistence/README.md#cs-ta0003-004) · [Account Added to Privileged Group Event Family](06-Privilege-Escalation/README.md#cs-ta0004-001) · [Local Group and Directory Account Changes](06-Privilege-Escalation/README.md#cs-ta0004-004) | 3 |
| `T1105` | [Remote Access and Tunneling Utility Commands](12-Command-and-Control/README.md#cs-ta0011-004) | 1 |
| `T1110` | [Failed SSO Authentication Event Inventory](03-Initial-Access/README.md#cs-ta0001-002) · [Authentication Failure and Brute Force Event Families](08-Credential-Access/README.md#cs-ta0006-002) · [SMB Logon Brute Force Events](10-Lateral-Movement/README.md#cs-ta0008-008) | 3 |
| `T1133` | [VPN and Identity Sign-In Event Inventory](03-Initial-Access/README.md#cs-ta0001-003) · [Remote Access Client Execution](03-Initial-Access/README.md#cs-ta0001-005) | 2 |
| `T1134` | [Windows Token Privilege Modification Events](06-Privilege-Escalation/README.md#cs-ta0004-002) · [Elevation and Token Abuse Command Indicators](06-Privilege-Escalation/README.md#cs-ta0004-003) | 2 |
| `T1135` | [Shares and Network Enumeration Commands](09-Discovery/README.md#cs-ta0007-005) · [SMB Client and Server Event Family Inventory](10-Lateral-Movement/README.md#cs-ta0008-006) | 2 |
| `T1136` | [Local Account Creation via Net](05-Persistence/README.md#cs-ta0003-001) · [Account Creation and Modification Events](05-Persistence/README.md#cs-ta0003-004) | 2 |
| `T1189` | [Potentially Risky Browser Downloads](03-Initial-Access/README.md#cs-ta0001-001) | 1 |
| `T1204` | [Potentially Risky Browser Downloads](03-Initial-Access/README.md#cs-ta0001-001) · [Selected Offensive Tool Names in Command Lines](04-Execution/README.md#cs-ta0002-007) | 2 |
| `T1219` | [Remote Access and Tunneling Utility Commands](12-Command-and-Control/README.md#cs-ta0011-004) · [Tunneling and Remote Tool Execution](12-Command-and-Control/README.md#cs-ta0011-008) | 2 |
| `T1482` | [Active Directory RPC Enumeration Events](09-Discovery/README.md#cs-ta0007-004) · [Domain Controller and Trust Discovery Commands](09-Discovery/README.md#cs-ta0007-006) | 2 |
| `T1486` | [Ransomware File Rename and Entropy Events](14-Impact/README.md#cs-ta0040-002) | 1 |
| `T1489` | [Host Prevention and Containment Event Inventory](14-Impact/README.md#cs-ta0040-003) · [Service and Account Disruption Events](14-Impact/README.md#cs-ta0040-004) | 2 |
| `T1490` | [Backup and Recovery Inhibition Commands](14-Impact/README.md#cs-ta0040-001) · [Recovery Inhibition Command Indicators](14-Impact/README.md#cs-ta0040-005) | 2 |
| `T1531` | [Service and Account Disruption Events](14-Impact/README.md#cs-ta0040-004) | 1 |
| `T1543.003` | [Windows Service Creation and Reconfiguration](05-Persistence/README.md#cs-ta0003-005) | 1 |
| `T1546.003` | [WMI Provider Registration and Autorun Artifacts](05-Persistence/README.md#cs-ta0003-006) | 1 |
| `T1547.001` | [Scheduled Task Registration and Autorun Telemetry](05-Persistence/README.md#cs-ta0003-002) · [Run Keys and Startup Artifact Telemetry](05-Persistence/README.md#cs-ta0003-003) · [WMI Provider Registration and Autorun Artifacts](05-Persistence/README.md#cs-ta0003-006) | 3 |
| `T1548` | [Elevation and Token Abuse Command Indicators](06-Privilege-Escalation/README.md#cs-ta0004-003) | 1 |
| `T1552` | [Credential Stores and Sensitive Files](08-Credential-Access/README.md#cs-ta0006-009) | 1 |
| `T1555` | [Credential Stores and Sensitive Files](08-Credential-Access/README.md#cs-ta0006-009) | 1 |
| `T1558` | [KRBTGT-Related Directory Events](08-Credential-Access/README.md#cs-ta0006-008) | 1 |
| `T1558.003` | [Kerberoasting and AS-REP Tooling Footprints](08-Credential-Access/README.md#cs-ta0006-006) | 1 |
| `T1558.004` | [Kerberoasting and AS-REP Tooling Footprints](08-Credential-Access/README.md#cs-ta0006-006) | 1 |
| `T1560` | [Archiving and Data Transfer Utilities](11-Collection/README.md#cs-ta0009-001) · [Archive File Creation Event Families](11-Collection/README.md#cs-ta0009-003) · [Potential Data Staging Paths and Compression](11-Collection/README.md#cs-ta0009-004) · [Potential Data Staging in Shared Paths](11-Collection/README.md#cs-ta0009-006) · [File and USN Metadata for Archives](11-Collection/README.md#cs-ta0009-007) · [Archive Output and High-Entropy Write Events](11-Collection/README.md#cs-ta0009-008) · [Specific Archive Format Writes](11-Collection/README.md#cs-ta0009-009) · [Potential Archive Artifacts in File Metadata](16-Forensic-Artifacts/README.md#cs-fa-003) | 8 |
| `T1562.001` | [Security Control Modification Commands](07-Defense-Evasion/README.md#cs-ta0005-001) · [Sensor and Prevention Diagnostics](07-Defense-Evasion/README.md#cs-ta0005-002) · [Sensor Anti-Tamper and Bypass Telemetry](07-Defense-Evasion/README.md#cs-ta0005-006) | 3 |
| `T1562.004` | [Firewall and WFP Modification Events](07-Defense-Evasion/README.md#cs-ta0005-004) | 1 |
| `T1567` | [Command-Line Upload and Transfer Indicators](13-Exfiltration/README.md#cs-ta0010-002) · [Transfer and Cloud Upload Command Indicators](13-Exfiltration/README.md#cs-ta0010-007) | 2 |
| `T1569.002` | [PsExec WinRM and Remote Service Command Patterns](10-Lateral-Movement/README.md#cs-ta0008-005) | 1 |
| `T1572` | [Remote Access and Tunneling Utility Commands](12-Command-and-Control/README.md#cs-ta0011-004) · [SSH Tunnel Creation Events](12-Command-and-Control/README.md#cs-ta0011-007) · [Tunneling and Remote Tool Execution](12-Command-and-Control/README.md#cs-ta0011-008) | 3 |
| `T1588` | [Browser Downloads of Executables and Archives](02-Resource-Development/README.md#cs-ta0042-001) · [Penetration Testing Utility Execution](02-Resource-Development/README.md#cs-ta0042-002) · [Suspicious Browser Download URL Extensions](02-Resource-Development/README.md#cs-ta0042-003) | 3 |
| `T1592` | [Reconnaissance Footprints in Browser History](01-Reconnaissance/README.md#cs-ta0043-001) | 1 |
| `T1593` | [Host and Domain Reconnaissance Commands](01-Reconnaissance/README.md#cs-ta0043-003) | 1 |
| `T1595` | [Potential Inbound Scan Touchpoints](01-Reconnaissance/README.md#cs-ta0043-002) | 1 |

> Contextual mappings are included; validate each technique mapping during QA.

[← All queries](QUERY-CATALOG.md)
