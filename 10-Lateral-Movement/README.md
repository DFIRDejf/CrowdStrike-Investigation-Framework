[← Framework home](../README.md)

# Lateral Movement

**CrowdStrike Falcon / NG-SIEM**  ·  **CQL**  ·  `TA0008`  ·  **6 queries**

Investigate SMB use, remote administration, and movement between endpoints.

---

## Query library

| Hunt | Status |
|---|---|
| [01. High-Volume SMB Connections](#01-high-volume-smb-connections) | `Migration recheck` |
| [02. SMB Server Audit Events](#02-smb-server-audit-events) | `Migration recheck` |
| [03. SMB Share Open Events](#03-smb-share-open-events) | `Migration recheck` |
| [04. Remote Administration Process and Network Context](#04-remote-administration-process-and-network-context) | `Migration recheck` |
| [05. PsExec WinRM and Remote Service Command Patterns](#05-psexec-winrm-and-remote-service-command-patterns) | `Candidate` |
| [06. SMB Client and Server Event Family Inventory](#06-smb-client-and-server-event-family-inventory) | `Candidate` |

---

### 01. High-Volume SMB Connections

Identifies endpoints establishing at least 50 observed connections to the same remote address over TCP/445. This is a volume-based hunting lead, not proof of lateral movement.

**MITRE:** T1021.002\

<details>
<summary><strong>If you want to see more details</strong></summary>

```cql
#event_simpleName="NetworkConnectIP4"
RemotePort=445
| groupBy([aid, ComputerName, RemoteAddressIP4], function=([count(as=connections), collect([UserName, LocalAddressIP4])]), limit=max)
| connections >= 50
| sort(connections, order=desc)
```

**False positives:** Backups, management agents, and file servers can generate high SMB volumes. Tune the threshold to the search interval.

**Analyst pivot:** Scope by host, user and narrow time window; pivot to process tree and nearby evidence before concluding malicious activity.

</details>

### 02. SMB Server Audit Events

Filters SMB server telemetry for investigation-scoped host, user, and local IP indicators.

**MITRE:** T1021.002\

<details>
<summary><strong>If you want to see more details</strong></summary>

```cql
#event_simpleName=SmbServerV1AuditEtw
| (
 ComputerName=/^(HOST_A|HOST_B|SERVER_A|SERVER_B)$/i
 OR UserName=/^(USER_ID|analyst@example.com)$/i
 OR LocalIP=/^(192\.0\.2\.10|192\.0\.2\.11)$/i
 OR @rawstring=/(USER_ID|analyst@example\.com|HOST_A|HOST_B)/i
)
```

**False positives:** Replace illustrative indicators before execution. Raw-string fallback is broad and should be used only if parsed fields are unavailable.

**Analyst pivot:** Scope by host, user and narrow time window; pivot to process tree and nearby evidence before concluding malicious activity.

</details>

### 03. SMB Share Open Events

Filters SMB server telemetry for investigation-scoped host, user, and local IP indicators.

**MITRE:** T1021.002\

<details>
<summary><strong>If you want to see more details</strong></summary>

```cql
#event_simpleName=SmbServerShareOpenedEtw
| (
 ComputerName=/^(HOST_A|HOST_B|SERVER_A|SERVER_B)$/i
 OR UserName=/^(USER_ID|analyst@example.com)$/i
 OR LocalIP=/^(192\.0\.2\.10|192\.0\.2\.11)$/i
 OR @rawstring=/(USER_ID|analyst@example\.com|HOST_A|HOST_B)/i
)
```

**False positives:** Replace illustrative indicators before execution. Raw-string fallback is broad and should be used only if parsed fields are unavailable.

**Analyst pivot:** Scope by host, user and narrow time window; pivot to process tree and nearby evidence before concluding malicious activity.

</details>

### 04. Remote Administration Process and Network Context

Links selected remote administration processes to network activity and provides pivot links.

**MITRE:** T1021 (contextual)\

<details>
<summary><strong>If you want to see more details</strong></summary>

```cql
defineTable(query={NetworkConnectIP4}, include=[ContextProcessId, RemoteAddressIP4], name="Network")
| #event_simpleName=ProcessRollup2 FileName=/(mstsc|wmic|psexec|powershell|^cmd|pwsh|copy|ssh)/
| match(file="Network", field=[TargetProcessId], column=ContextProcessId)
| ExecutionChain:=format(format="%s\n\t└ %s (%s)", field=[ParentBaseFileName, FileName, RawProcessId])
| format("[Virus Total](https://www.virustotal.com/gui/file/%s)", field=[SHA256HashData], as="VT")
| format("[Graph Explorer](https://falcon.crowdstrike.com/graphs/process-explorer/graph?id=pid:%s:%s)", field=[aid, TargetProcessId], as="Graph Explorer")
| format("[Indicator Graph](https://falcon.crowdstrike.com/intelligence/graph?indicators=ip%%3A%%27%s%%27%%2Chash%%3A%%27%s%%27)",field=[RemoteAddressIP4, SHA256HashData],as="Indicator Graph")
| format("[Remote Access Graph](https://falcon.crowdstrike.com//investigate/remote-access-graph?timeRange=last30Days&userName=%s)", field=["UserName"], as="Remote Access Graph")
| groupBy([aid,TargetProcessId, ComputerName, UserName, ExecutionChain, RemoteAddressIP4, "Graph Explorer", "Indicator Graph", "Remote Access Graph", VT], function=[])
```

**False positives:** External pivot links may require tenant URL adjustments. The UserName argument is quoted as a literal in the submitted query.

**Analyst pivot:** Scope by host, user and narrow time window; pivot to process tree and nearby evidence before concluding malicious activity.

</details>

### 05. PsExec WinRM and Remote Service Command Patterns

Searches process command lines for remote execution and remote management patterns.

**MITRE:** T1021 / T1569.002\  ·  **Telemetry:** ProcessRollup2

<details>
<summary><strong>If you want to see more details</strong></summary>

```cql
#event_simpleName=ProcessRollup2 event_platform=Win
| CommandLine=/(psexec|winrs|invoke-command|enter-pssession|new-pssession|\\\\[^ ]+\\(admin\$|c\$)|sc\.exe\s+\\\\)/i
| select([@timestamp, aid, ComputerName, UserName, ParentBaseFileName, FileName, CommandLine])
| sort(@timestamp, order=desc, limit=1000)
```

**False positives:** Authorized remote maintenance, automation and incident response.

**Analyst pivot:** Use authenticated session evidence, source/destination hosts and admin approvals.

*Origin: OneNote-derived adaptation\*

</details>

### 06. SMB Client and Server Event Family Inventory

Inventories SMB client/server share opening and closing activity before adding narrower filters.

**MITRE:** T1021.002 / T1135\  ·  **Telemetry:** SMB ETW events

<details>
<summary><strong>If you want to see more details</strong></summary>

```cql
#event_simpleName=/^(SmbClientShareOpenedEtw|SmbServerShareOpenedEtw|SmbClientShareClosedEtw|SmbServerV1AuditEtw)$/
| groupBy([#event_simpleName, ComputerName], function=[count(as=SMBEvents)], limit=1000)
| sort(SMBEvents, order=desc, limit=1000)
```

**False positives:** File servers, normal share access, backup jobs.

**Analyst pivot:** Use fieldset() per event; add share/path/user fields only after confirming schema.

*Origin: OneNote-derived adaptation\*

</details>

---

`Migration recheck` = original supplied query was previously tested, but this publication copy needs validation. `Candidate` / `Community candidate` = not validated in the target Falcon environment.

[← Back to framework](../README.md)
