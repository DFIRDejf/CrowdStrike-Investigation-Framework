# CQL Query Catalog

[← Framework home](README.md) · [MITRE Technique Index](MITRE-TECHNIQUE-INDEX.md)

**111 documented CQL queries** · **14 ATT&CK tactics** · **3 operational query modules**

Use **Ctrl+F** to find a query by name, technique, event name, or category. Links jump directly to the full CQL block and analyst notes.

> **Validation:** Statuses indicate documentation and review history, not guaranteed syntax correctness or detection quality.

## All queries

| Query | Category | MITRE ATT&CK | Telemetry | Status |
|:--|:--|:--|:--|:--|
| [Reconnaissance Footprints in Browser History](01-Reconnaissance/README.md#01-reconnaissance-footprints-in-browser-history) | [Reconnaissance](01-Reconnaissance/README.md) | T1592 (context) | See query | `Requires Validation` |
| [Potential Inbound Scan Touchpoints](01-Reconnaissance/README.md#02-potential-inbound-scan-touchpoints) | [Reconnaissance](01-Reconnaissance/README.md) | T1595 (context) | NetworkReceiveAcceptIP4 | `Requires Validation` |
| [Host and Domain Reconnaissance Commands](01-Reconnaissance/README.md#03-host-and-domain-reconnaissance-commands) | [Reconnaissance](01-Reconnaissance/README.md) | T1593 / T1046 (context) | ProcessRollup2 | `Requires Validation` |
| [Browser Downloads of Executables and Archives](02-Resource-Development/README.md#01-browser-downloads-of-executables-and-archives) | [Resource Development](02-Resource-Development/README.md) | T1588 (context) | See query | `Requires Validation` |
| [Penetration Testing Utility Execution](02-Resource-Development/README.md#02-penetration-testing-utility-execution) | [Resource Development](02-Resource-Development/README.md) | T1588 (context) | ProcessRollup2 | `Requires Validation` |
| [Suspicious Browser Download URL Extensions](02-Resource-Development/README.md#03-suspicious-browser-download-url-extensions) | [Resource Development](02-Resource-Development/README.md) | T1588 (context) | See query | `Requires Validation` |
| [Potentially Risky Browser Downloads](03-Initial-Access/README.md#01-potentially-risky-browser-downloads) | [Initial Access](03-Initial-Access/README.md) | T1189 / T1204 (contextual) | BrowserDownloadStarted, BrowserDownloadEnded | `Candidate` |
| [Failed SSO Authentication Event Inventory](03-Initial-Access/README.md#02-failed-sso-authentication-event-inventory) | [Initial Access](03-Initial-Access/README.md) | T1110 | See query | `Requires Validation` |
| [VPN and Identity Sign-In Event Inventory](03-Initial-Access/README.md#03-vpn-and-identity-sign-in-event-inventory) | [Initial Access](03-Initial-Access/README.md) | T1133 / T1078 | See query | `Requires Validation` |
| [Domain Interactive Logon Events](03-Initial-Access/README.md#04-domain-interactive-logon-events) | [Initial Access](03-Initial-Access/README.md) | T1078 | See query | `Requires Validation` |
| [Remote Access Client Execution](03-Initial-Access/README.md#05-remote-access-client-execution) | [Initial Access](03-Initial-Access/README.md) | T1133 (context) | ProcessRollup2 | `Requires Validation` |
| [Script Control Detection Events](04-Execution/README.md#01-script-control-detection-events) | [Execution](04-Execution/README.md) | T1059 (contextual) | ScriptControlDetectInfo | `Migration recheck` |
| [Remote Command Response Events](04-Execution/README.md#02-remote-command-response-events) | [Execution](04-Execution/README.md) | T1059 (contextual) | RemoteCommandResponse | `Migration recheck` |
| [PowerShell Child Process Within One Minute](04-Execution/README.md#03-powershell-child-process-within-one-minute) | [Execution](04-Execution/README.md) | T1059.001 | See query | `Migration recheck` |
| [Suspicious PowerShell Interpreter Arguments](04-Execution/README.md#04-suspicious-powershell-interpreter-arguments) | [Execution](04-Execution/README.md) | T1059.001 | ProcessRollup2 | `Candidate` |
| [WMI Remote Process Creation Commands](04-Execution/README.md#05-wmi-remote-process-creation-commands) | [Execution](04-Execution/README.md) | T1047 | ProcessRollup2 | `Candidate` |
| [Windows Shell and Command Interpreter Activity](04-Execution/README.md#06-windows-shell-and-command-interpreter-activity) | [Execution](04-Execution/README.md) | T1059.003 | ProcessRollup2 | `Candidate` |
| [Selected Offensive Tool Names in Command Lines](04-Execution/README.md#07-selected-offensive-tool-names-in-command-lines) | [Execution](04-Execution/README.md) | T1059 / T1204 (contextual) | ProcessRollup2 | `Candidate` |
| [Shell and Packed Executable Event Inventory](04-Execution/README.md#08-shell-and-packed-executable-event-inventory) | [Execution](04-Execution/README.md) | T1059 / T1027 | See query | `Requires Validation` |
| [Command History and New Script Telemetry](04-Execution/README.md#09-command-history-and-new-script-telemetry) | [Execution](04-Execution/README.md) | T1059 | See query | `Requires Validation` |
| [Baseline Process and Ancestry Context](04-Execution/README.md#10-baseline-process-and-ancestry-context) | [Execution](04-Execution/README.md) | T1059 (context) | ProcessRollup2 | `Requires Validation` |
| [Local Account Creation via Net](05-Persistence/README.md#01-local-account-creation-via-net) | [Persistence](05-Persistence/README.md) | T1136 | ProcessRollup2 | `Migration recheck` |
| [Scheduled Task Registration and Autorun Telemetry](05-Persistence/README.md#02-scheduled-task-registration-and-autorun-telemetry) | [Persistence](05-Persistence/README.md) | T1053.005 / T1547.001 | ScheduledTaskInfo, AutoRunProcessInfo | `Candidate` |
| [Run Keys and Startup Artifact Telemetry](05-Persistence/README.md#03-run-keys-and-startup-artifact-telemetry) | [Persistence](05-Persistence/README.md) | T1547.001 | RegGenericInfo, RegistryOperationDetectInfo, AsepFileChangeDetectInfo | `Candidate` |
| [Account Creation and Modification Events](05-Persistence/README.md#04-account-creation-and-modification-events) | [Persistence](05-Persistence/README.md) | T1136 / T1098 | See query | `Requires Validation` |
| [Windows Service Creation and Reconfiguration](05-Persistence/README.md#05-windows-service-creation-and-reconfiguration) | [Persistence](05-Persistence/README.md) | T1543.003 | ProcessRollup2 | `Requires Validation` |
| [WMI Provider Registration and Autorun Artifacts](05-Persistence/README.md#06-wmi-provider-registration-and-autorun-artifacts) | [Persistence](05-Persistence/README.md) | T1546.003 / T1547.001 | See query | `Requires Validation` |
| [Account Added to Privileged Group Event Family](06-Privilege-Escalation/README.md#01-account-added-to-privileged-group-event-family) | [Privilege Escalation](06-Privilege-Escalation/README.md) | T1098 | UserAccountAddedToGroup and AD group entity events | `Candidate` |
| [Windows Token Privilege Modification Events](06-Privilege-Escalation/README.md#02-windows-token-privilege-modification-events) | [Privilege Escalation](06-Privilege-Escalation/README.md) | T1134 | See query | `Requires Validation` |
| [Elevation and Token Abuse Command Indicators](06-Privilege-Escalation/README.md#03-elevation-and-token-abuse-command-indicators) | [Privilege Escalation](06-Privilege-Escalation/README.md) | T1548 / T1134 | ProcessRollup2 | `Requires Validation` |
| [Local Group and Directory Account Changes](06-Privilege-Escalation/README.md#04-local-group-and-directory-account-changes) | [Privilege Escalation](06-Privilege-Escalation/README.md) | T1098 | See query | `Requires Validation` |
| [Security Control Modification Commands](07-Defense-Evasion/README.md#01-security-control-modification-commands) | [Defense Evasion](07-Defense-Evasion/README.md) | T1562.001 / T1070 (contextual) | ProcessRollup2 | `Candidate` |
| [Sensor and Prevention Diagnostics](07-Defense-Evasion/README.md#02-sensor-and-prevention-diagnostics) | [Defense Evasion](07-Defense-Evasion/README.md) | T1562.001 (contextual) | SensorAntiTamperState and related events | `Candidate` |
| [Security Log and Trace File Deletion](07-Defense-Evasion/README.md#03-security-log-and-trace-file-deletion) | [Defense Evasion](07-Defense-Evasion/README.md) | T1070.004 | See query | `Requires Validation` |
| [Firewall and WFP Modification Events](07-Defense-Evasion/README.md#04-firewall-and-wfp-modification-events) | [Defense Evasion](07-Defense-Evasion/README.md) | T1562.004 | See query | `Requires Validation` |
| [Unsigned Modules and Suspicious File Signatures](07-Defense-Evasion/README.md#05-unsigned-modules-and-suspicious-file-signatures) | [Defense Evasion](07-Defense-Evasion/README.md) | T1027 / T1036 | See query | `Requires Validation` |
| [Sensor Anti-Tamper and Bypass Telemetry](07-Defense-Evasion/README.md#06-sensor-anti-tamper-and-bypass-telemetry) | [Defense Evasion](07-Defense-Evasion/README.md) | T1562.001 | See query | `Requires Validation` |
| [Suspicious Macro and Invalid Script Events](07-Defense-Evasion/README.md#07-suspicious-macro-and-invalid-script-events) | [Defense Evasion](07-Defense-Evasion/README.md) | T1027 | See query | `Requires Validation` |
| [Potential Log Clearing Commands](07-Defense-Evasion/README.md#08-potential-log-clearing-commands) | [Defense Evasion](07-Defense-Evasion/README.md) | T1070 | ProcessRollup2 | `Requires Validation` |
| [Credential Dumping Command-Line Indicators](08-Credential-Access/README.md#01-credential-dumping-command-line-indicators) | [Credential Access](08-Credential-Access/README.md) | T1003 | ProcessRollup2 | `Candidate` |
| [Authentication Failure and Brute Force Event Families](08-Credential-Access/README.md#02-authentication-failure-and-brute-force-event-families) | [Credential Access](08-Credential-Access/README.md) | T1110 (contextual) | Brute force detection and SSO failure event families | `Candidate` |
| [Credential Access Detection Event Families](08-Credential-Access/README.md#03-credential-access-detection-event-families) | [Credential Access](08-Credential-Access/README.md) | T1003 | Credential dumping-related detection events | `Candidate` |
| [LSASS, SAM and NTDS Dumping Commands](08-Credential-Access/README.md#04-lsass-sam-and-ntds-dumping-commands) | [Credential Access](08-Credential-Access/README.md) | T1003.001 / T1003.002 | ProcessRollup2 | `Requires Validation` |
| [SAM Dump and Privileged Handle Detection Events](08-Credential-Access/README.md#05-sam-dump-and-privileged-handle-detection-events) | [Credential Access](08-Credential-Access/README.md) | T1003.002 | See query | `Requires Validation` |
| [Kerberoasting and AS-REP Tooling Footprints](08-Credential-Access/README.md#06-kerberoasting-and-as-rep-tooling-footprints) | [Credential Access](08-Credential-Access/README.md) | T1558.003 / T1558.004 | See query | `Requires Validation` |
| [DCSync and Directory Replication Indicators](08-Credential-Access/README.md#07-dcsync-and-directory-replication-indicators) | [Credential Access](08-Credential-Access/README.md) | T1003.006 | See query | `Requires Validation` |
| [KRBTGT-Related Directory Events](08-Credential-Access/README.md#08-krbtgt-related-directory-events) | [Credential Access](08-Credential-Access/README.md) | T1558 (context) | See query | `Requires Validation` |
| [Credential Stores and Sensitive Files](08-Credential-Access/README.md#09-credential-stores-and-sensitive-files) | [Credential Access](08-Credential-Access/README.md) | T1552 / T1555 | See query | `Requires Validation` |
| [Account and Domain Enumeration Commands](09-Discovery/README.md#01-account-and-domain-enumeration-commands) | [Discovery](09-Discovery/README.md) | T1087 / T1069 / T1018 | ProcessRollup2 | `Candidate` |
| [High Port Diversity by Destination](09-Discovery/README.md#02-high-port-diversity-by-destination) | [Discovery](09-Discovery/README.md) | T1046 | NetworkConnectIP4 | `Candidate` |
| [WMI Query Telemetry](09-Discovery/README.md#03-wmi-query-telemetry) | [Discovery](09-Discovery/README.md) | T1047 / T1082 | See query | `Requires Validation` |
| [Active Directory RPC Enumeration Events](09-Discovery/README.md#04-active-directory-rpc-enumeration-events) | [Discovery](09-Discovery/README.md) | T1087 / T1482 | See query | `Requires Validation` |
| [Shares and Network Enumeration Commands](09-Discovery/README.md#05-shares-and-network-enumeration-commands) | [Discovery](09-Discovery/README.md) | T1135 / T1046 | ProcessRollup2 | `Requires Validation` |
| [Domain Controller and Trust Discovery Commands](09-Discovery/README.md#06-domain-controller-and-trust-discovery-commands) | [Discovery](09-Discovery/README.md) | T1018 / T1482 | ProcessRollup2 | `Requires Validation` |
| [High-Volume SMB Connections](10-Lateral-Movement/README.md#01-high-volume-smb-connections) | [Lateral Movement](10-Lateral-Movement/README.md) | T1021.002 | See query | `Migration recheck` |
| [SMB Server Audit Events](10-Lateral-Movement/README.md#02-smb-server-audit-events) | [Lateral Movement](10-Lateral-Movement/README.md) | T1021.002 | SmbServerV1AuditEtw | `Migration recheck` |
| [SMB Share Open Events](10-Lateral-Movement/README.md#03-smb-share-open-events) | [Lateral Movement](10-Lateral-Movement/README.md) | T1021.002 | SmbServerShareOpenedEtw | `Migration recheck` |
| [Remote Administration Process and Network Context](10-Lateral-Movement/README.md#04-remote-administration-process-and-network-context) | [Lateral Movement](10-Lateral-Movement/README.md) | T1021 (contextual) | ProcessRollup2 | `Migration recheck` |
| [PsExec WinRM and Remote Service Command Patterns](10-Lateral-Movement/README.md#05-psexec-winrm-and-remote-service-command-patterns) | [Lateral Movement](10-Lateral-Movement/README.md) | T1021 / T1569.002 | ProcessRollup2 | `Candidate` |
| [SMB Client and Server Event Family Inventory](10-Lateral-Movement/README.md#06-smb-client-and-server-event-family-inventory) | [Lateral Movement](10-Lateral-Movement/README.md) | T1021.002 / T1135 | SMB ETW events | `Candidate` |
| [SMB Client and Server Share Activity](10-Lateral-Movement/README.md#07-smb-client-and-server-share-activity) | [Lateral Movement](10-Lateral-Movement/README.md) | T1021.002 | See query | `Requires Validation` |
| [SMB Logon Brute Force Events](10-Lateral-Movement/README.md#08-smb-logon-brute-force-events) | [Lateral Movement](10-Lateral-Movement/README.md) | T1110 / T1021.002 | See query | `Requires Validation` |
| [Windows Share Creation and Permission Changes](10-Lateral-Movement/README.md#09-windows-share-creation-and-permission-changes) | [Lateral Movement](10-Lateral-Movement/README.md) | T1021.002 | See query | `Requires Validation` |
| [Remote Shell and Session Events](10-Lateral-Movement/README.md#10-remote-shell-and-session-events) | [Lateral Movement](10-Lateral-Movement/README.md) | T1021 | See query | `Requires Validation` |
| [Inbound SMB, RDP and WinRM Connections](10-Lateral-Movement/README.md#11-inbound-smb-rdp-and-winrm-connections) | [Lateral Movement](10-Lateral-Movement/README.md) | T1021 | NetworkReceiveAcceptIP4 | `Requires Validation` |
| [Archiving and Data Transfer Utilities](11-Collection/README.md#01-archiving-and-data-transfer-utilities) | [Collection](11-Collection/README.md) | T1560 / T1005 | ProcessRollup2 | `Migration recheck` |
| [Sensitive File and Critical File Access Telemetry](11-Collection/README.md#02-sensitive-file-and-critical-file-access-telemetry) | [Collection](11-Collection/README.md) | T1005 (contextual) | ClassifiedSensitiveFileAccess, CriticalFileAccessed | `Candidate` |
| [Archive File Creation Event Families](11-Collection/README.md#03-archive-file-creation-event-families) | [Collection](11-Collection/README.md) | T1560 | Archive-format file write events | `Candidate` |
| [Potential Data Staging Paths and Compression](11-Collection/README.md#04-potential-data-staging-paths-and-compression) | [Collection](11-Collection/README.md) | T1074.001 / T1560 | ProcessRollup2 | `Candidate` |
| [File Collection with Copy Utilities](11-Collection/README.md#05-file-collection-with-copy-utilities) | [Collection](11-Collection/README.md) | T1005 / T1039 | ProcessRollup2 | `Requires Validation` |
| [Potential Data Staging in Shared Paths](11-Collection/README.md#06-potential-data-staging-in-shared-paths) | [Collection](11-Collection/README.md) | T1074.001 / T1560 | ProcessRollup2 | `Requires Validation` |
| [File and USN Metadata for Archives](11-Collection/README.md#07-file-and-usn-metadata-for-archives) | [Collection](11-Collection/README.md) | T1005 / T1560 | See query | `Requires Validation` |
| [Archive Output and High-Entropy Write Events](11-Collection/README.md#08-archive-output-and-high-entropy-write-events) | [Collection](11-Collection/README.md) | T1560 | See query | `Requires Validation` |
| [Specific Archive Format Writes](11-Collection/README.md#09-specific-archive-format-writes) | [Collection](11-Collection/README.md) | T1560 | See query | `Requires Validation` |
| [DNS and Network Connections by Process](12-Command-and-Control/README.md#01-dns-and-network-connections-by-process) | [Command and Control](12-Command-and-Control/README.md) | T1071.001 (contextual) | Multiple events | `Migration recheck` |
| [Process Execution and DNS Correlation](12-Command-and-Control/README.md#02-process-execution-and-dns-correlation) | [Command and Control](12-Command-and-Control/README.md) | Investigation utility | Multiple events | `Migration recheck` |
| [DNS Queries from Investigated Endpoints](12-Command-and-Control/README.md#03-dns-queries-from-investigated-endpoints) | [Command and Control](12-Command-and-Control/README.md) | T1071.004 (contextual) | DnsRequest | `Candidate` |
| [Remote Access and Tunneling Utility Commands](12-Command-and-Control/README.md#04-remote-access-and-tunneling-utility-commands) | [Command and Control](12-Command-and-Control/README.md) | T1572 / T1219 / T1105 | ProcessRollup2 | `Candidate` |
| [DNS Request and Suspicious DNS Detection Events](12-Command-and-Control/README.md#05-dns-request-and-suspicious-dns-detection-events) | [Command and Control](12-Command-and-Control/README.md) | T1071.004 | See query | `Requires Validation` |
| [DNS Requests by Endpoint and Process](12-Command-and-Control/README.md#06-dns-requests-by-endpoint-and-process) | [Command and Control](12-Command-and-Control/README.md) | T1071.004 (context) | DnsRequest | `Requires Validation` |
| [SSH Tunnel Creation Events](12-Command-and-Control/README.md#07-ssh-tunnel-creation-events) | [Command and Control](12-Command-and-Control/README.md) | T1572 | See query | `Requires Validation` |
| [Tunneling and Remote Tool Execution](12-Command-and-Control/README.md#08-tunneling-and-remote-tool-execution) | [Command and Control](12-Command-and-Control/README.md) | T1572 / T1219 | ProcessRollup2 | `Requires Validation` |
| [Sensitive File Access Followed by External Connection](13-Exfiltration/README.md#01-sensitive-file-access-followed-by-external-connection) | [Exfiltration](13-Exfiltration/README.md) | T1041 (potential) | Multiple events | `Migration recheck` |
| [Command-Line Upload and Transfer Indicators](13-Exfiltration/README.md#02-command-line-upload-and-transfer-indicators) | [Exfiltration](13-Exfiltration/README.md) | T1048 / T1567 (contextual) | ProcessRollup2 | `Candidate` |
| [Upload-Related Falcon Event Inventory](13-Exfiltration/README.md#03-upload-related-falcon-event-inventory) | [Exfiltration](13-Exfiltration/README.md) | T1041 (context) | See query | `Requires Validation` |
| [FTP Command Event Telemetry](13-Exfiltration/README.md#04-ftp-command-event-telemetry) | [Exfiltration](13-Exfiltration/README.md) | T1048 | See query | `Requires Validation` |
| [SRU Network and Application Usage](13-Exfiltration/README.md#05-sru-network-and-application-usage) | [Exfiltration](13-Exfiltration/README.md) | T1041 (coverage context) | See query | `Requires Validation` |
| [Outbound Network Destination Event Counts](13-Exfiltration/README.md#06-outbound-network-destination-event-counts) | [Exfiltration](13-Exfiltration/README.md) | T1041 (lead) | NetworkConnectIP4 | `Requires Validation` |
| [Transfer and Cloud Upload Command Indicators](13-Exfiltration/README.md#07-transfer-and-cloud-upload-command-indicators) | [Exfiltration](13-Exfiltration/README.md) | T1041 / T1567 | ProcessRollup2 | `Requires Validation` |
| [Backup and Recovery Inhibition Commands](14-Impact/README.md#01-backup-and-recovery-inhibition-commands) | [Impact](14-Impact/README.md) | T1490 | ProcessRollup2 | `Candidate` |
| [Ransomware File Rename and Entropy Events](14-Impact/README.md#02-ransomware-file-rename-and-entropy-events) | [Impact](14-Impact/README.md) | T1486 | See query | `Requires Validation` |
| [Host Prevention and Containment Event Inventory](14-Impact/README.md#03-host-prevention-and-containment-event-inventory) | [Impact](14-Impact/README.md) | T1489 (context) | See query | `Requires Validation` |
| [Service and Account Disruption Events](14-Impact/README.md#04-service-and-account-disruption-events) | [Impact](14-Impact/README.md) | T1489 / T1531 | See query | `Requires Validation` |
| [Recovery Inhibition Command Indicators](14-Impact/README.md#05-recovery-inhibition-command-indicators) | [Impact](14-Impact/README.md) | T1490 | ProcessRollup2 | `Requires Validation` |
| [Executable File Written After User Logon](16-Forensic-Artifacts/README.md#01-executable-file-written-after-user-logon) | [Forensic Artifacts](16-Forensic-Artifacts/README.md) | Investigation utility | Multiple events | `Migration recheck` |
| [File-System Artifact Event Inventory](16-Forensic-Artifacts/README.md#02-file-system-artifact-event-inventory) | [Forensic Artifacts](16-Forensic-Artifacts/README.md) | DFIR utility | FileInfo, USNRecord, PrefetchFile | `Candidate` |
| [Potential Archive Artifacts in File Metadata](16-Forensic-Artifacts/README.md#03-potential-archive-artifacts-in-file-metadata) | [Forensic Artifacts](16-Forensic-Artifacts/README.md) | DFIR / T1560 (contextual) | FileInfo, USNRecord | `Candidate` |
| [CIDR-Based Remote IP Search](17-Query-Builder-Helper/README.md#01-cidr-based-remote-ip-search) | [Query Builder Helper](17-Query-Builder-Helper/README.md) | Investigation utility | See query | `Migration recheck` |
| [Command History Scoped Search](17-Query-Builder-Helper/README.md#02-command-history-scoped-search) | [Query Builder Helper](17-Query-Builder-Helper/README.md) | Investigation utility | CommandHistory | `Migration recheck` |
| [Process and Network Connection Correlation](17-Query-Builder-Helper/README.md#03-process-and-network-connection-correlation) | [Query Builder Helper](17-Query-Builder-Helper/README.md) | Investigation utility | Multiple events | `Migration recheck` |
| [Command History and Process Rollup](17-Query-Builder-Helper/README.md#04-command-history-and-process-rollup) | [Query Builder Helper](17-Query-Builder-Helper/README.md) | Investigation utility | Multiple events | `Migration recheck` |
| [Parameterized Process Network Pivot](17-Query-Builder-Helper/README.md#05-parameterized-process-network-pivot) | [Query Builder Helper](17-Query-Builder-Helper/README.md) | Investigation utility | See query | `Migration recheck` |
| [Available Fields by Event Type](17-Query-Builder-Helper/README.md#06-available-fields-by-event-type) | [Query Builder Helper](17-Query-Builder-Helper/README.md) | Operational utility | ProcessRollup2 | `Candidate` |
| [Observed Events by Name](17-Query-Builder-Helper/README.md#07-observed-events-by-name) | [Query Builder Helper](17-Query-Builder-Helper/README.md) | Operational utility | All accessible event types | `Candidate` |
| [Normalize Host and User Identity Across Schemas](17-Query-Builder-Helper/README.md#08-normalize-host-and-user-identity-across-schemas) | [Query Builder Helper](17-Query-Builder-Helper/README.md) | Operational utility | ProcessRollup2 + alternate schemas | `Candidate` |
| [Process Correlation Key Reference](17-Query-Builder-Helper/README.md#09-process-correlation-key-reference) | [Query Builder Helper](17-Query-Builder-Helper/README.md) | Operational utility | ProcessRollup2, NetworkConnectIP4, DnsRequest | `Candidate` |
| [New PowerShell DNS Domains Versus Previous Six Days](21-Cool-Query-Friday/README.md#01-new-powershell-dns-domains-versus-previous-six-days) | [Cool Query Friday](21-Cool-Query-Friday/README.md) | T1059.001 / T1071.004 (contextual) | DnsRequest | `Community candidate` |
| [Process and DNS Events Paired by Falcon PID](21-Cool-Query-Friday/README.md#02-process-and-dns-events-paired-by-falcon-pid) | [Cool Query Friday](21-Cool-Query-Friday/README.md) | C2 pivot / investigation utility | ProcessRollup2, DnsRequest | `Community candidate` |
| [Discovery Command Sequence within Five Minutes](21-Cool-Query-Friday/README.md#03-discovery-command-sequence-within-five-minutes) | [Cool Query Friday](21-Cool-Query-Friday/README.md) | T1082 / T1087 (contextual) | ProcessRollup2 | `Community candidate` |
| [Encoded PowerShell Query Profiling](21-Cool-Query-Friday/README.md#04-encoded-powershell-query-profiling) | [Cool Query Friday](21-Cool-Query-Friday/README.md) | Performance diagnostic | ProcessRollup2 | `Community candidate` |
| [Browser Extension Inventory by Host](21-Cool-Query-Friday/README.md#05-browser-extension-inventory-by-host) | [Cool Query Friday](21-Cool-Query-Friday/README.md) | Software inventory / attack-surface context | InstalledBrowserExtension (license/sensor dependent) | `Community candidate` |

---

**Validation states:** `Migration recheck` · `Candidate` · `Community candidate` · `Requires Validation`. See [Detection Engineering](22-Detection-Engineering/README.md) for promotion criteria.

[← Framework home](README.md)
