# CQL Telemetry Index

[← Home](README.md) · [All queries](QUERY-CATALOG.md)

**106 explicit event names** extracted from `#event_simpleName` query filters.

Search with **Ctrl+F** for a Falcon event name. Only explicit names and simple anchored regex alternatives are indexed; complex/dynamic filters may not appear. Entries are **not verified tenant fieldsets**.

| Event | Related queries | Count |
|:--|:--|--:|
| `ActiveDirectoryAccountCreated` | [Account Creation and Modification Events](05-Persistence/README.md#cs-ta0003-004) | 1 |
| `ActiveDirectoryAccountDirectContainingGroupEntitiesUpdate` | [Account Added to Privileged Group Event Family](06-Privilege-Escalation/README.md#cs-ta0004-001) | 1 |
| `ActiveDirectoryAccountDisabled` | [Service and Account Disruption Events](14-Impact/README.md#cs-ta0040-004) | 1 |
| `ActiveDirectoryAccountFlattenedContainingGroupEntitiesUpdate` | [Account Added to Privileged Group Event Family](06-Privilege-Escalation/README.md#cs-ta0004-001) | 1 |
| `ActiveDirectoryAccountPasswordUpdate` | [KRBTGT-Related Directory Events](08-Credential-Access/README.md#cs-ta0006-008) | 1 |
| `ActiveDirectoryAuditPasswordModificationAttempt` | [KRBTGT-Related Directory Events](08-Credential-Access/README.md#cs-ta0006-008) | 1 |
| `ActiveDirectoryAuditUserModified` | [Account Creation and Modification Events](05-Persistence/README.md#cs-ta0003-004) · [Local Group and Directory Account Changes](06-Privilege-Escalation/README.md#cs-ta0004-004) · [KRBTGT-Related Directory Events](08-Credential-Access/README.md#cs-ta0006-008) | 3 |
| `ActiveDirectoryIncomingDceRpcEpmRequest` | [Active Directory RPC Enumeration Events](09-Discovery/README.md#cs-ta0007-004) | 1 |
| `ActiveDirectoryIncomingDceRpcRequest` | [DCSync and Directory Replication Indicators](08-Credential-Access/README.md#cs-ta0006-007) · [KRBTGT-Related Directory Events](08-Credential-Access/README.md#cs-ta0006-008) · [Active Directory RPC Enumeration Events](09-Discovery/README.md#cs-ta0007-004) | 3 |
| `ActiveDirectoryInteractiveDomainLogon` | [VPN and Identity Sign-In Event Inventory](03-Initial-Access/README.md#cs-ta0001-003) · [Domain Interactive Logon Events](03-Initial-Access/README.md#cs-ta0001-004) | 2 |
| `ArcFileWritten` | [Archive File Creation Event Families](11-Collection/README.md#cs-ta0009-003) · [Specific Archive Format Writes](11-Collection/README.md#cs-ta0009-009) | 2 |
| `ArchiveFileContent` | [Archive Output and High-Entropy Write Events](11-Collection/README.md#cs-ta0009-008) | 1 |
| `ArjFileWritten` | [Archive File Creation Event Families](11-Collection/README.md#cs-ta0009-003) · [Specific Archive Format Writes](11-Collection/README.md#cs-ta0009-009) | 2 |
| `AsepFileChangeDetectInfo` | [Run Keys and Startup Artifact Telemetry](05-Persistence/README.md#cs-ta0003-003) · [WMI Provider Registration and Autorun Artifacts](05-Persistence/README.md#cs-ta0003-006) | 2 |
| `AutoRunProcessInfo` | [Scheduled Task Registration and Autorun Telemetry](05-Persistence/README.md#cs-ta0003-002) | 1 |
| `BZip2FileWritten` | [Archive File Creation Event Families](11-Collection/README.md#cs-ta0009-003) · [Specific Archive Format Writes](11-Collection/README.md#cs-ta0009-009) | 2 |
| `BrowserCookieInfo` | [Credential Stores and Sensitive Files](08-Credential-Access/README.md#cs-ta0006-009) | 1 |
| `BrowserDownloadEnded` | [Browser Downloads of Executables and Archives](02-Resource-Development/README.md#cs-ta0042-001) · [Suspicious Browser Download URL Extensions](02-Resource-Development/README.md#cs-ta0042-003) · [Potentially Risky Browser Downloads](03-Initial-Access/README.md#cs-ta0001-001) · [Upload-Related Falcon Event Inventory](13-Exfiltration/README.md#cs-ta0010-003) | 4 |
| `BrowserDownloadStarted` | [Browser Downloads of Executables and Archives](02-Resource-Development/README.md#cs-ta0042-001) · [Suspicious Browser Download URL Extensions](02-Resource-Development/README.md#cs-ta0042-003) · [Potentially Risky Browser Downloads](03-Initial-Access/README.md#cs-ta0001-001) · [Upload-Related Falcon Event Inventory](13-Exfiltration/README.md#cs-ta0010-003) | 4 |
| `BrowserHistoryVisit` | [Reconnaissance Footprints in Browser History](01-Reconnaissance/README.md#cs-ta0043-001) | 1 |
| `ClassifiedSensitiveFileAccess` | [Credential Stores and Sensitive Files](08-Credential-Access/README.md#cs-ta0006-009) · [Sensitive File and Critical File Access Telemetry](11-Collection/README.md#cs-ta0009-002) · [Sensitive File Access Followed by External Connection](13-Exfiltration/README.md#cs-ta0010-001) | 3 |
| `CommandHistory` | [Command History and New Script Telemetry](04-Execution/README.md#cs-ta0002-009) · [Kerberoasting and AS-REP Tooling Footprints](08-Credential-Access/README.md#cs-ta0006-006) · [DCSync and Directory Replication Indicators](08-Credential-Access/README.md#cs-ta0006-007) · [Command History Scoped Search](17-Query-Builder-Helper/README.md#cs-qb-002) · [Command History and Process Rollup](17-Query-Builder-Helper/README.md#cs-qb-004) | 5 |
| `CriticalFileAccessed` | [Credential Stores and Sensitive Files](08-Credential-Access/README.md#cs-ta0006-009) · [Sensitive File and Critical File Access Telemetry](11-Collection/README.md#cs-ta0009-002) | 2 |
| `DetectionExcluded` | [Sensor and Prevention Diagnostics](07-Defense-Evasion/README.md#cs-ta0005-002) · [Sensor Anti-Tamper and Bypass Telemetry](07-Defense-Evasion/README.md#cs-ta0005-006) | 2 |
| `DnsRequest` | [DNS and Network Connections by Process](12-Command-and-Control/README.md#cs-ta0011-001) · [Process Execution and DNS Correlation](12-Command-and-Control/README.md#cs-ta0011-002) · [DNS Queries from Investigated Endpoints](12-Command-and-Control/README.md#cs-ta0011-003) · [DNS Request and Suspicious DNS Detection Events](12-Command-and-Control/README.md#cs-ta0011-005) · [DNS Requests by Endpoint and Process](12-Command-and-Control/README.md#cs-ta0011-006) · [Process Correlation Key Reference](17-Query-Builder-Helper/README.md#cs-qb-009) · [New PowerShell DNS Domains Versus Previous Six Days](21-Cool-Query-Friday/README.md#cs-cqf-001) · [Process and DNS Events Paired by Falcon PID](21-Cool-Query-Friday/README.md#cs-cqf-002) | 8 |
| `DriverPreventionStatus` | [Sensor and Prevention Diagnostics](07-Defense-Evasion/README.md#cs-ta0005-002) · [Sensor Anti-Tamper and Bypass Telemetry](07-Defense-Evasion/README.md#cs-ta0005-006) | 2 |
| `EAMBypassEvent` | [Sensor and Prevention Diagnostics](07-Defense-Evasion/README.md#cs-ta0005-002) · [Sensor Anti-Tamper and Bypass Telemetry](07-Defense-Evasion/README.md#cs-ta0005-006) | 2 |
| `FileCreateInfo` | [File and USN Metadata for Archives](11-Collection/README.md#cs-ta0009-007) | 1 |
| `FileDeleted` | [Security Log and Trace File Deletion](07-Defense-Evasion/README.md#cs-ta0005-003) | 1 |
| `FileInfo` | [File and USN Metadata for Archives](11-Collection/README.md#cs-ta0009-007) · [File-System Artifact Event Inventory](16-Forensic-Artifacts/README.md#cs-fa-002) · [Potential Archive Artifacts in File Metadata](16-Forensic-Artifacts/README.md#cs-fa-003) | 3 |
| `FileSignatureMismatch` | [Unsigned Modules and Suspicious File Signatures](07-Defense-Evasion/README.md#cs-ta0005-005) | 1 |
| `FileSystemOperationBlocked` | [Host Prevention and Containment Event Inventory](14-Impact/README.md#cs-ta0040-003) | 1 |
| `FileWrittenWithEntropyHigh` | [Archive Output and High-Entropy Write Events](11-Collection/README.md#cs-ta0009-008) · [Ransomware File Rename and Entropy Events](14-Impact/README.md#cs-ta0040-002) | 2 |
| `FirewallDeleteRuleIP4` | [Firewall and WFP Modification Events](07-Defense-Evasion/README.md#cs-ta0005-004) | 1 |
| `FirewallEnabled` | [Host Prevention and Containment Event Inventory](14-Impact/README.md#cs-ta0040-003) | 1 |
| `FirewallSetRuleIP4` | [Firewall and WFP Modification Events](07-Defense-Evasion/README.md#cs-ta0005-004) | 1 |
| `FtpCommand` | [FTP Command Event Telemetry](13-Exfiltration/README.md#cs-ta0010-004) | 1 |
| `GenericFileWritten` | [Archive Output and High-Entropy Write Events](11-Collection/README.md#cs-ta0009-008) | 1 |
| `GzipFileWritten` | [Archive File Creation Event Families](11-Collection/README.md#cs-ta0009-003) · [Specific Archive Format Writes](11-Collection/README.md#cs-ta0009-009) | 2 |
| `IdpTelemetryData` | [VPN and Identity Sign-In Event Inventory](03-Initial-Access/README.md#cs-ta0001-003) · [KRBTGT-Related Directory Events](08-Credential-Access/README.md#cs-ta0006-008) | 2 |
| `InstalledBrowserExtension` | [Browser Extension Inventory by Host](21-Cool-Query-Friday/README.md#cs-cqf-005) | 1 |
| `IoSessionLoggedOn` | [VPN and Identity Sign-In Event Inventory](03-Initial-Access/README.md#cs-ta0001-003) · [Domain Interactive Logon Events](03-Initial-Access/README.md#cs-ta0001-004) · [Remote Shell and Session Events](10-Lateral-Movement/README.md#cs-ta0008-010) | 3 |
| `KernelServiceStarted` | [Service and Account Disruption Events](14-Impact/README.md#cs-ta0040-004) | 1 |
| `LZipFileWritten` | [Archive File Creation Event Families](11-Collection/README.md#cs-ta0009-003) · [Specific Archive Format Writes](11-Collection/README.md#cs-ta0009-009) | 2 |
| `LfoUploadDataComplete` | [Upload-Related Falcon Event Inventory](13-Exfiltration/README.md#cs-ta0010-003) | 1 |
| `LfoUploadDataUnneeded` | [Upload-Related Falcon Event Inventory](13-Exfiltration/README.md#cs-ta0010-003) | 1 |
| `LocalWindowsUserUpdate` | [Account Creation and Modification Events](05-Persistence/README.md#cs-ta0003-004) · [Local Group and Directory Account Changes](06-Privilege-Escalation/README.md#cs-ta0004-004) | 2 |
| `MacroContentInfo` | [Suspicious Macro and Invalid Script Events](07-Defense-Evasion/README.md#cs-ta0005-007) | 1 |
| `MacroDetectInfo` | [Suspicious Macro and Invalid Script Events](07-Defense-Evasion/README.md#cs-ta0005-007) | 1 |
| `MbrOverwriteRawDetectInfo` | [Ransomware File Rename and Entropy Events](14-Impact/README.md#cs-ta0040-002) | 1 |
| `MftRecord` | [File and USN Metadata for Archives](11-Collection/README.md#cs-ta0009-007) | 1 |
| `NetShareDelete` | [Windows Share Creation and Permission Changes](10-Lateral-Movement/README.md#cs-ta0008-009) | 1 |
| `NetShareInfo` | [Windows Share Creation and Permission Changes](10-Lateral-Movement/README.md#cs-ta0008-009) | 1 |
| `NetShareSecurityModify` | [Windows Share Creation and Permission Changes](10-Lateral-Movement/README.md#cs-ta0008-009) | 1 |
| `NetworkConnectIP4` | [High Port Diversity by Destination](09-Discovery/README.md#cs-ta0007-002) · [High-Volume SMB Connections](10-Lateral-Movement/README.md#cs-ta0008-001) · [DNS and Network Connections by Process](12-Command-and-Control/README.md#cs-ta0011-001) · [Sensitive File Access Followed by External Connection](13-Exfiltration/README.md#cs-ta0010-001) · [Outbound Network Destination Event Counts](13-Exfiltration/README.md#cs-ta0010-006) · [Process and Network Connection Correlation](17-Query-Builder-Helper/README.md#cs-qb-003) · [Process Correlation Key Reference](17-Query-Builder-Helper/README.md#cs-qb-009) | 7 |
| `NetworkReceiveAcceptIP4` | [Potential Inbound Scan Touchpoints](01-Reconnaissance/README.md#cs-ta0043-002) · [Inbound SMB, RDP and WinRM Connections](10-Lateral-Movement/README.md#cs-ta0008-011) | 2 |
| `NewScriptWritten` | [Command History and New Script Telemetry](04-Execution/README.md#cs-ta0002-009) · [Kerberoasting and AS-REP Tooling Footprints](08-Credential-Access/README.md#cs-ta0006-006) · [DCSync and Directory Replication Indicators](08-Credential-Access/README.md#cs-ta0006-007) | 3 |
| `PackedExecutableWritten` | [Unsigned Modules and Suspicious File Signatures](07-Defense-Evasion/README.md#cs-ta0005-005) | 1 |
| `PeFileWritten` | [Executable File Written After User Logon](16-Forensic-Artifacts/README.md#cs-fa-001) | 1 |
| `PrefetchFile` | [File-System Artifact Event Inventory](16-Forensic-Artifacts/README.md#cs-fa-002) | 1 |
| `PrivilegedProcessHandleFromUnsignedModule` | [Windows Token Privilege Modification Events](06-Privilege-Escalation/README.md#cs-ta0004-002) · [Credential Access Detection Event Families](08-Credential-Access/README.md#cs-ta0006-003) · [SAM Dump and Privileged Handle Detection Events](08-Credential-Access/README.md#cs-ta0006-005) | 3 |
| `ProcessBlocked` | [Host Prevention and Containment Event Inventory](14-Impact/README.md#cs-ta0040-003) | 1 |
| `ProcessExecOnPackedExecutable` | [Shell and Packed Executable Event Inventory](04-Execution/README.md#cs-ta0002-008) · [Suspicious Macro and Invalid Script Events](07-Defense-Evasion/README.md#cs-ta0005-007) | 2 |
| `ProcessRollup2` | [Host and Domain Reconnaissance Commands](01-Reconnaissance/README.md#cs-ta0043-003) · [Penetration Testing Utility Execution](02-Resource-Development/README.md#cs-ta0042-002) · [Remote Access Client Execution](03-Initial-Access/README.md#cs-ta0001-005) · [Suspicious PowerShell Interpreter Arguments](04-Execution/README.md#cs-ta0002-004) · [WMI Remote Process Creation Commands](04-Execution/README.md#cs-ta0002-005) · [Windows Shell and Command Interpreter Activity](04-Execution/README.md#cs-ta0002-006) · [Selected Offensive Tool Names in Command Lines](04-Execution/README.md#cs-ta0002-007) · [Baseline Process and Ancestry Context](04-Execution/README.md#cs-ta0002-010) · [Local Account Creation via Net](05-Persistence/README.md#cs-ta0003-001) · [Windows Service Creation and Reconfiguration](05-Persistence/README.md#cs-ta0003-005) · [Elevation and Token Abuse Command Indicators](06-Privilege-Escalation/README.md#cs-ta0004-003) · [Security Control Modification Commands](07-Defense-Evasion/README.md#cs-ta0005-001) · [Potential Log Clearing Commands](07-Defense-Evasion/README.md#cs-ta0005-008) · [Credential Dumping Command-Line Indicators](08-Credential-Access/README.md#cs-ta0006-001) · [LSASS, SAM and NTDS Dumping Commands](08-Credential-Access/README.md#cs-ta0006-004) · [Account and Domain Enumeration Commands](09-Discovery/README.md#cs-ta0007-001) · [Shares and Network Enumeration Commands](09-Discovery/README.md#cs-ta0007-005) · [Domain Controller and Trust Discovery Commands](09-Discovery/README.md#cs-ta0007-006) · [Remote Administration Process and Network Context](10-Lateral-Movement/README.md#cs-ta0008-004) · [PsExec WinRM and Remote Service Command Patterns](10-Lateral-Movement/README.md#cs-ta0008-005) · [Archiving and Data Transfer Utilities](11-Collection/README.md#cs-ta0009-001) · [Potential Data Staging Paths and Compression](11-Collection/README.md#cs-ta0009-004) · [File Collection with Copy Utilities](11-Collection/README.md#cs-ta0009-005) · [Potential Data Staging in Shared Paths](11-Collection/README.md#cs-ta0009-006) · [Process Execution and DNS Correlation](12-Command-and-Control/README.md#cs-ta0011-002) · [Remote Access and Tunneling Utility Commands](12-Command-and-Control/README.md#cs-ta0011-004) · [Tunneling and Remote Tool Execution](12-Command-and-Control/README.md#cs-ta0011-008) · [Command-Line Upload and Transfer Indicators](13-Exfiltration/README.md#cs-ta0010-002) · [Transfer and Cloud Upload Command Indicators](13-Exfiltration/README.md#cs-ta0010-007) · [Backup and Recovery Inhibition Commands](14-Impact/README.md#cs-ta0040-001) · [Recovery Inhibition Command Indicators](14-Impact/README.md#cs-ta0040-005) · [Process and Network Connection Correlation](17-Query-Builder-Helper/README.md#cs-qb-003) · [Command History and Process Rollup](17-Query-Builder-Helper/README.md#cs-qb-004) · [Parameterized Process Network Pivot](17-Query-Builder-Helper/README.md#cs-qb-005) · [Available Fields by Event Type](17-Query-Builder-Helper/README.md#cs-qb-006) · [Normalize Host and User Identity Across Schemas](17-Query-Builder-Helper/README.md#cs-qb-008) · [Process Correlation Key Reference](17-Query-Builder-Helper/README.md#cs-qb-009) · [Process and DNS Events Paired by Falcon PID](21-Cool-Query-Friday/README.md#cs-cqf-002) · [Discovery Command Sequence within Five Minutes](21-Cool-Query-Friday/README.md#cs-cqf-003) · [Encoded PowerShell Query Profiling](21-Cool-Query-Friday/README.md#cs-cqf-004) | 40 |
| `ProcessTokenPrivilegesEdited` | [Windows Token Privilege Modification Events](06-Privilege-Escalation/README.md#cs-ta0004-002) | 1 |
| `ProcessTrace` | [Shell and Packed Executable Event Inventory](04-Execution/README.md#cs-ta0002-008) | 1 |
| `RansomwareRenameFile` | [Ransomware File Rename and Entropy Events](14-Impact/README.md#cs-ta0040-002) | 1 |
| `RarFileWritten` | [Archive File Creation Event Families](11-Collection/README.md#cs-ta0009-003) · [Specific Archive Format Writes](11-Collection/README.md#cs-ta0009-009) | 2 |
| `ReflectiveDllOpenProcess` | [Credential Access Detection Event Families](08-Credential-Access/README.md#cs-ta0006-003) · [SAM Dump and Privileged Handle Detection Events](08-Credential-Access/README.md#cs-ta0006-005) | 2 |
| `RegGenericInfo` | [Run Keys and Startup Artifact Telemetry](05-Persistence/README.md#cs-ta0003-003) | 1 |
| `RegistryOperationDetectInfo` | [Run Keys and Startup Artifact Telemetry](05-Persistence/README.md#cs-ta0003-003) | 1 |
| `RemoteBruteForceDetectInfo` | [Authentication Failure and Brute Force Event Families](08-Credential-Access/README.md#cs-ta0006-002) | 1 |
| `RemoteCommandResponse` | [Remote Command Response Events](04-Execution/README.md#cs-ta0002-002) · [Remote Shell and Session Events](10-Lateral-Movement/README.md#cs-ta0008-010) | 2 |
| `SAMHashDumpFromUnsignedModule` | [Credential Access Detection Event Families](08-Credential-Access/README.md#cs-ta0006-003) · [SAM Dump and Privileged Handle Detection Events](08-Credential-Access/README.md#cs-ta0006-005) | 2 |
| `SSHTunnelCreated` | [SSH Tunnel Creation Events](12-Command-and-Control/README.md#cs-ta0011-007) | 1 |
| `ScheduledTaskInfo` | [Scheduled Task Registration and Autorun Telemetry](05-Persistence/README.md#cs-ta0003-002) | 1 |
| `ScriptControlDetectInfo` | [Script Control Detection Events](04-Execution/README.md#cs-ta0002-001) · [Command History and New Script Telemetry](04-Execution/README.md#cs-ta0002-009) · [Kerberoasting and AS-REP Tooling Footprints](08-Credential-Access/README.md#cs-ta0006-006) | 3 |
| `ScriptControlDetectInvalidInfo` | [Suspicious Macro and Invalid Script Events](07-Defense-Evasion/README.md#cs-ta0005-007) | 1 |
| `SensorAntiTamperState` | [Sensor and Prevention Diagnostics](07-Defense-Evasion/README.md#cs-ta0005-002) · [Sensor Anti-Tamper and Bypass Telemetry](07-Defense-Evasion/README.md#cs-ta0005-006) | 2 |
| `SensorSelfDiagnosticTelemetry` | [Sensor and Prevention Diagnostics](07-Defense-Evasion/README.md#cs-ta0005-002) · [Sensor Anti-Tamper and Bypass Telemetry](07-Defense-Evasion/README.md#cs-ta0005-006) | 2 |
| `ShellCommandLineInfo` | [Shell and Packed Executable Event Inventory](04-Execution/README.md#cs-ta0002-008) · [Remote Shell and Session Events](10-Lateral-Movement/README.md#cs-ta0008-010) | 2 |
| `SmbClientShareClosedEtw` | [SMB Client and Server Event Family Inventory](10-Lateral-Movement/README.md#cs-ta0008-006) · [SMB Client and Server Share Activity](10-Lateral-Movement/README.md#cs-ta0008-007) | 2 |
| `SmbClientShareLogonBruteForceLowThreshold` | [Authentication Failure and Brute Force Event Families](08-Credential-Access/README.md#cs-ta0006-002) · [SMB Logon Brute Force Events](10-Lateral-Movement/README.md#cs-ta0008-008) | 2 |
| `SmbClientShareLogonBruteForceSuspected` | [Authentication Failure and Brute Force Event Families](08-Credential-Access/README.md#cs-ta0006-002) · [SMB Logon Brute Force Events](10-Lateral-Movement/README.md#cs-ta0008-008) | 2 |
| `SmbClientShareOpenedEtw` | [SMB Client and Server Event Family Inventory](10-Lateral-Movement/README.md#cs-ta0008-006) · [SMB Client and Server Share Activity](10-Lateral-Movement/README.md#cs-ta0008-007) | 2 |
| `SmbServerShareOpenedEtw` | [SMB Share Open Events](10-Lateral-Movement/README.md#cs-ta0008-003) · [SMB Client and Server Event Family Inventory](10-Lateral-Movement/README.md#cs-ta0008-006) · [SMB Client and Server Share Activity](10-Lateral-Movement/README.md#cs-ta0008-007) | 3 |
| `SmbServerV1AuditEtw` | [SMB Server Audit Events](10-Lateral-Movement/README.md#cs-ta0008-002) · [SMB Client and Server Event Family Inventory](10-Lateral-Movement/README.md#cs-ta0008-006) · [SMB Client and Server Share Activity](10-Lateral-Movement/README.md#cs-ta0008-007) | 3 |
| `SruApplicationResourceUsage` | [SRU Network and Application Usage](13-Exfiltration/README.md#cs-ta0010-005) | 1 |
| `SruNetworkDataUsage` | [SRU Network and Application Usage](13-Exfiltration/README.md#cs-ta0010-005) | 1 |
| `SsoApplicationAccessFailure` | [Failed SSO Authentication Event Inventory](03-Initial-Access/README.md#cs-ta0001-002) · [VPN and Identity Sign-In Event Inventory](03-Initial-Access/README.md#cs-ta0001-003) | 2 |
| `SsoUserLogonFailure` | [Failed SSO Authentication Event Inventory](03-Initial-Access/README.md#cs-ta0001-002) · [VPN and Identity Sign-In Event Inventory](03-Initial-Access/README.md#cs-ta0001-003) · [Authentication Failure and Brute Force Event Families](08-Credential-Access/README.md#cs-ta0006-002) | 3 |
| `SuspiciousDnsRequest` | [DNS Request and Suspicious DNS Detection Events](12-Command-and-Control/README.md#cs-ta0011-005) | 1 |
| `SystemdServiceCreated` | [Service and Account Disruption Events](14-Impact/README.md#cs-ta0040-004) | 1 |
| `TarFileWritten` | [Archive File Creation Event Families](11-Collection/README.md#cs-ta0009-003) · [Specific Archive Format Writes](11-Collection/README.md#cs-ta0009-009) | 2 |
| `USNRecord` | [Security Log and Trace File Deletion](07-Defense-Evasion/README.md#cs-ta0005-003) · [File and USN Metadata for Archives](11-Collection/README.md#cs-ta0009-007) · [File-System Artifact Event Inventory](16-Forensic-Artifacts/README.md#cs-fa-002) · [Potential Archive Artifacts in File Metadata](16-Forensic-Artifacts/README.md#cs-fa-003) | 4 |
| `UnsignedModuleLoad` | [Unsigned Modules and Suspicious File Signatures](07-Defense-Evasion/README.md#cs-ta0005-005) | 1 |
| `UserAccountAddedToGroup` | [Account Added to Privileged Group Event Family](06-Privilege-Escalation/README.md#cs-ta0004-001) | 1 |
| `UserAccountCreated` | [Account Creation and Modification Events](05-Persistence/README.md#cs-ta0003-004) | 1 |
| `UserAccountRemovedFromGroup` | [Service and Account Disruption Events](14-Impact/README.md#cs-ta0040-004) | 1 |
| `UserGroupCreated` | [Local Group and Directory Account Changes](06-Privilege-Escalation/README.md#cs-ta0004-004) | 1 |
| `UserGroupDeleted` | [Service and Account Disruption Events](14-Impact/README.md#cs-ta0040-004) | 1 |
| `UserLogon` | [Executable File Written After User Logon](16-Forensic-Artifacts/README.md#cs-fa-001) | 1 |
| `WfpFilterTamperingFilterAdded` | [Firewall and WFP Modification Events](07-Defense-Evasion/README.md#cs-ta0005-004) | 1 |
| `WmiProviderRegistrationEtw` | [WMI Provider Registration and Autorun Artifacts](05-Persistence/README.md#cs-ta0003-006) | 1 |
| `WmiQuery` | [WMI Query Telemetry](09-Discovery/README.md#cs-ta0007-003) | 1 |
| `XzFileWritten` | [Archive File Creation Event Families](11-Collection/README.md#cs-ta0009-003) · [Specific Archive Format Writes](11-Collection/README.md#cs-ta0009-009) | 2 |

Telemetry tags shown in query cards are **derived hints**, not proof of platform compatibility.

[← All queries](QUERY-CATALOG.md)
