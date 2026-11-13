[← Home](../README.md) · [All queries](../QUERY-CATALOG.md)

# Lateral Movement

**CrowdStrike Falcon / NG-SIEM**  ·  **CQL**  ·  `TA0008`  ·  **11 queries**

Investigate SMB use, remote administration, and movement between endpoints.

---

## Query library

| Hunt | ID | MITRE | Status |
|:--|:--|:--|:--|
| [01. High-Volume SMB Connections](#cs-ta0008-001) | `CS-TA0008-001` | T1021.002 | `Requires Validation` |
| [02. SMB Server Audit Events](#cs-ta0008-002) | `CS-TA0008-002` | T1021.002 | `Requires Validation` |
| [03. SMB Share Open Events](#cs-ta0008-003) | `CS-TA0008-003` | T1021.002 | `Requires Validation` |
| [04. Remote Administration Process and Network Context](#cs-ta0008-004) | `CS-TA0008-004` | T1021 (contextual) | `Requires Validation` |
| [05. PsExec WinRM and Remote Service Command Patterns](#cs-ta0008-005) | `CS-TA0008-005` | T1021 / T1569.002 | `Requires Validation` |
| [06. SMB Client and Server Event Family Inventory](#cs-ta0008-006) | `CS-TA0008-006` | T1021.002 / T1135 | `Requires Validation` |
| [07. SMB Client and Server Share Activity](#cs-ta0008-007) | `CS-TA0008-007` | T1021.002 | `Requires Validation` |
| [08. SMB Logon Brute Force Events](#cs-ta0008-008) | `CS-TA0008-008` | T1110 / T1021.002 | `Requires Validation` |
| [09. Windows Share Creation and Permission Changes](#cs-ta0008-009) | `CS-TA0008-009` | T1021.002 | `Requires Validation` |
| [10. Remote Shell and Session Events](#cs-ta0008-010) | `CS-TA0008-010` | T1021 | `Requires Validation` |
| [11. Inbound SMB, RDP and WinRM Connections](#cs-ta0008-011) | `CS-TA0008-011` | T1021 | `Requires Validation` |

---

<a name="cs-ta0008-001"></a>

### 01. High-Volume SMB Connections

Identifies endpoints establishing at least 50 observed connections to the same remote address over TCP/445. This is a volume-based hunting lead, not proof of lateral movement.

**Query ID:** `CS-TA0008-001` · **Platform:** `Not scoped` · **Tags:** `Network`

**MITRE:** T1021.002 · **Status:** `Requires Validation`

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

```cql
#event_simpleName="NetworkConnectIP4"
RemotePort=445
| groupBy([aid, ComputerName, RemoteAddressIP4], function=([count(as=connections), collect([UserName, LocalAddressIP4])]), limit=max)
| connections >= 50
| sort(connections, order=desc)
```

</details>

<a name="cs-ta0008-002"></a>

### 02. SMB Server Audit Events

Filters SMB server telemetry for investigation-scoped host, user, and local IP indicators.

**Query ID:** `CS-TA0008-002` · **Platform:** `Not scoped` · **Tags:** `SMB`

**MITRE:** T1021.002 · **Status:** `Requires Validation`

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

```cql
#event_simpleName=SmbServerV1AuditEtw
| (
 ComputerName=/^(HOST_A|HOST_B|SERVER_A|SERVER_B)$/i
 OR UserName=/^(USER_ID|analyst@example.com)$/i
 OR LocalIP=/^(192\.0\.2\.10|192\.0\.2\.11)$/i
 OR @rawstring=/(USER_ID|analyst@example\.com|HOST_A|HOST_B)/i
)
```

</details>

<a name="cs-ta0008-003"></a>

### 03. SMB Share Open Events

Filters SMB server telemetry for investigation-scoped host, user, and local IP indicators.

**Query ID:** `CS-TA0008-003` · **Platform:** `Not scoped` · **Tags:** `SMB`

**MITRE:** T1021.002 · **Status:** `Requires Validation`

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

```cql
#event_simpleName=SmbServerShareOpenedEtw
| (
 ComputerName=/^(HOST_A|HOST_B|SERVER_A|SERVER_B)$/i
 OR UserName=/^(USER_ID|analyst@example.com)$/i
 OR LocalIP=/^(192\.0\.2\.10|192\.0\.2\.11)$/i
 OR @rawstring=/(USER_ID|analyst@example\.com|HOST_A|HOST_B)/i
)
```

</details>

<a name="cs-ta0008-004"></a>

### 04. Remote Administration Process and Network Context

Links selected remote administration processes to network activity and provides pivot links.

**Query ID:** `CS-TA0008-004` · **Platform:** `Not scoped` · **Tags:** `Process`

**MITRE:** T1021 (contextual) · **Status:** `Requires Validation`

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

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

</details>

<a name="cs-ta0008-005"></a>

### 05. PsExec WinRM and Remote Service Command Patterns

Searches process command lines for remote execution and remote management patterns.

**Query ID:** `CS-TA0008-005` · **Platform:** `Windows` · **Tags:** `Process`

**MITRE:** T1021 / T1569.002 · **Status:** `Requires Validation`

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

```cql
#event_simpleName=ProcessRollup2 event_platform=Win
| CommandLine=/(psexec|winrs|invoke-command|enter-pssession|new-pssession|\\\\[^ ]+\\(admin\$|c\$)|sc\.exe\s+\\\\)/i
| select([@timestamp, aid, ComputerName, UserName, ParentBaseFileName, FileName, CommandLine])
| sort(@timestamp, order=desc, limit=1000)
```

</details>

<a name="cs-ta0008-006"></a>

### 06. SMB Client and Server Event Family Inventory

Inventories SMB client/server share opening and closing activity before adding narrower filters.

**Query ID:** `CS-TA0008-006` · **Platform:** `Not scoped` · **Tags:** `SMB`

**MITRE:** T1021.002 / T1135 · **Status:** `Requires Validation`

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

```cql
#event_simpleName=/^(SmbClientShareOpenedEtw|SmbServerShareOpenedEtw|SmbClientShareClosedEtw|SmbServerV1AuditEtw)$/
| groupBy([#event_simpleName, ComputerName], function=[count(as=SMBEvents)], limit=1000)
| sort(SMBEvents, order=desc, limit=1000)
```

</details>

<a name="cs-ta0008-007"></a>

### 07. SMB Client and Server Share Activity

Collects SMB client/server share opened or closed events.

**Query ID:** `CS-TA0008-007` · **Platform:** `Not scoped` · **Tags:** `SMB`

**MITRE:** T1021.002 · **Status:** `Requires Validation`

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

```cql
#event_simpleName=/^(SmbClientShareOpenedEtw|SmbServerShareOpenedEtw|SmbClientShareClosedEtw|SmbServerV1AuditEtw)$/
| select([@timestamp, #event_simpleName, ComputerName, UserName, @rawstring, aid])
| sort(@timestamp, order=asc, limit=10000)
```

</details>

<a name="cs-ta0008-008"></a>

### 08. SMB Logon Brute Force Events

Surfaces SMB share authentication brute-force detections.

**Query ID:** `CS-TA0008-008` · **Platform:** `Not scoped` · **Tags:** `Identity`, `SMB`

**MITRE:** T1110 / T1021.002 · **Status:** `Requires Validation`

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

```cql
#event_simpleName=/^(SmbClientShareLogonBruteForceLowThreshold|SmbClientShareLogonBruteForceSuspected)$/
| select([@timestamp, #event_simpleName, ComputerName, UserName, @rawstring, aid])
| sort(@timestamp, order=asc, limit=10000)
```

</details>

<a name="cs-ta0008-009"></a>

### 09. Windows Share Creation and Permission Changes

Investigates new network shares and changed share permissions.

**Query ID:** `CS-TA0008-009` · **Platform:** `Not scoped` · **Tags:** `SMB`

**MITRE:** T1021.002 · **Status:** `Requires Validation`

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

```cql
#event_simpleName=/^(NetShareInfo|NetShareSecurityModify|NetShareDelete)$/
| select([@timestamp, #event_simpleName, ComputerName, UserName, @rawstring, aid])
| sort(@timestamp, order=asc, limit=10000)
```

</details>

<a name="cs-ta0008-010"></a>

### 10. Remote Shell and Session Events

Collects remote command, interactive session and shell command activity.

**Query ID:** `CS-TA0008-010` · **Platform:** `Not scoped` · **Tags:** `Process`

**MITRE:** T1021 · **Status:** `Requires Validation`

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

```cql
#event_simpleName=/^(RemoteCommandResponse|IoSessionLoggedOn|ShellCommandLineInfo)$/
| select([@timestamp, #event_simpleName, ComputerName, UserName, @rawstring, aid])
| sort(@timestamp, order=asc, limit=10000)
```

</details>

<a name="cs-ta0008-011"></a>

### 11. Inbound SMB, RDP and WinRM Connections

Identifies accepts on common Windows remote access service ports.

**Query ID:** `CS-TA0008-011` · **Platform:** `Not scoped` · **Tags:** `Network`

**MITRE:** T1021 · **Status:** `Requires Validation`

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

```cql
#event_simpleName=NetworkReceiveAcceptIP4
| LocalPort=/(445|3389|5985|5986|135)/
| select([@timestamp, ComputerName, LocalAddressIP4, LocalPort, RemoteAddressIP4, RemotePort, ContextBaseFileName, ContextProcessId, aid])
| sort(@timestamp, order=asc, limit=10000)
```

</details>

---

`Requires Validation` = not yet tenant-validated · `Tested` = exact-version tested · `Production reviewed` = peer-reviewed with evidence.

[← Home](../README.md) · [All queries](../QUERY-CATALOG.md)
