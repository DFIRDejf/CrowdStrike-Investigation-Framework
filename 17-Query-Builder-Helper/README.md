[← Home](../README.md) · [All queries](../QUERY-CATALOG.md)

# Query Builder Helper

**CrowdStrike Falcon / NG-SIEM**  ·  **CQL**  ·  `Operational`  ·  **9 queries**

Reusable pivots, field-inspection patterns, and parameterized investigations.

---

## Query library

| Hunt | ID | MITRE | Status |
|:--|:--|:--|:--|
| [01. CIDR-Based Remote IP Search](#cs-qb-001) | `CS-QB-001` | Investigation utility | `Requires Validation` |
| [02. Command History Scoped Search](#cs-qb-002) | `CS-QB-002` | Investigation utility | `Requires Validation` |
| [03. Process and Network Connection Correlation](#cs-qb-003) | `CS-QB-003` | Investigation utility | `Requires Validation` |
| [04. Command History and Process Rollup](#cs-qb-004) | `CS-QB-004` | Investigation utility | `Requires Validation` |
| [05. Parameterized Process Network Pivot](#cs-qb-005) | `CS-QB-005` | Investigation utility | `Requires Validation` |
| [06. Available Fields by Event Type](#cs-qb-006) | `CS-QB-006` | Operational utility | `Requires Validation` |
| [07. Observed Events by Name](#cs-qb-007) | `CS-QB-007` | Operational utility | `Requires Validation` |
| [08. Normalize Host and User Identity Across Schemas](#cs-qb-008) | `CS-QB-008` | Operational utility | `Requires Validation` |
| [09. Process Correlation Key Reference](#cs-qb-009) | `CS-QB-009` | Operational utility | `Requires Validation` |

---

<a name="cs-qb-001"></a>

### 01. CIDR-Based Remote IP Search

Finds events whose RemoteIP field falls within a selected subnet.

**Query ID:** `CS-QB-001` · **Platform:** `Not scoped` · **Tags:** `See query`

**MITRE:** Investigation utility · **Status:** `Requires Validation`

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

```cql
#event_simpleName=*
| cidr("RemoteIP", subnet="203.0.113.0/24")
```

**False positives:** The subnet is an RFC 5737 documentation example; replace it before use. `RemoteIP` may not exist in every event family. Broad wildcard searches are costly.

**Analyst pivot:** Scope by host, user and narrow time window; pivot to process tree and nearby evidence before concluding malicious activity.

</details>

<a name="cs-qb-002"></a>

### 02. Command History Scoped Search

Retrieves command history for investigation-scoped hosts and identities and sorts by command sequence.

**Query ID:** `CS-QB-002` · **Platform:** `Not scoped` · **Tags:** `Process`

**MITRE:** Investigation utility · **Status:** `Requires Validation`

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

```cql
#event_simpleName=CommandHistory
| (
 ComputerName=/^(HOST_A|HOST_B)$/i
 OR UserName=/^(USER_ID|analyst@example.com)$/i
 OR LocalIP=/^(192\.0\.2\.10|192\.0\.2\.11)$/i
 OR @rawstring=/(USER_ID|analyst@example\.com|HOST_A|HOST_B)/i
)
| select([@timestamp,CommandHistory,CommandSequence])
| sort(CommandSequence, order=asc, limit=10000)
```

**False positives:** Sequence order is not necessarily global chronological order across multiple hosts.

**Analyst pivot:** Scope by host, user and narrow time window; pivot to process tree and nearby evidence before concluding malicious activity.

</details>

<a name="cs-qb-003"></a>

### 03. Process and Network Connection Correlation

Associates process execution and network connection events using process identifiers and formats an execution chain.

**Query ID:** `CS-QB-003` · **Platform:** `Not scoped` · **Tags:** `Network`, `Process`

**MITRE:** Investigation utility · **Status:** `Requires Validation`

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

```cql
defineTable(query={#event_simpleName=NetworkConnectIP4 RemoteAddressIP4=*}, include=[ContextTimeStamp, ContextProcessId, RemoteAddressIP4, RemotePort], name="NetConnIP4")
| #event_simpleName=ProcessRollup2
| match(file=NetConnIP4, field=[TargetProcessId], column=ContextProcessId)
| ContextTimeStamp := ContextTimeStamp*1000
| ProcessStartTime := ProcessStartTime*1000
| formatTime(format="%Y/%m/%d %H:%M:%S %Z", field=ContextTimeStamp, as="NetConnectTime")
| formatTime(format="%Y/%m/%d %H:%M:%S %Z", field=ProcessStartTime, as="ProcStartTime")
| case{
GrandParentBaseFileName!=* | GrandParentBaseFileName:="Unknown";
*;
}
| format(format="%s -> %s -> %s", field=[GrandParentBaseFileName, ParentBaseFileName, FileName], as=ExecutionChain)
| groupBy([NetConnectTime, ComputerName, UserName, RemoteAddressIP4, RemotePort, ProcStartTime, ExecutionChain, CommandLine])
```

**False positives:** Match keys are process identifiers; review host scoping to avoid collisions and verify timestamp units.

**Analyst pivot:** Scope by host, user and narrow time window; pivot to process tree and nearby evidence before concluding malicious activity.

</details>

<a name="cs-qb-004"></a>

### 04. Command History and Process Rollup

Combines CommandHistory and ProcessRollup2 events, expands command separators, and displays execution context.

**Query ID:** `CS-QB-004` · **Platform:** `Windows` · **Tags:** `Process`

**MITRE:** Investigation utility · **Status:** `Requires Validation`

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

```cql
setTimeInterval(start="7d")
| defineTable(query={#event_simpleName=CommandHistory}, include=[CommandHistory, TargetProcessId], name=CMD_History)
| #event_simpleName=ProcessRollup2 event_platform=Win
| match(file=CMD_History, field=[TargetProcessId])
| in(field=CommandHistory, values=?{CommandHistory=*}, ignoreCase=true)
| CommandHistorySplit:=splitString(by="¶", field=CommandHistory)
| concatArray(CommandHistorySplit, separator="\n", as=CommandHistoryClean)
| ExecutionChain:=format(format="%s\n\t└ %s (%s)", field=[ParentBaseFileName, FileName, RawProcessId])
| groupBy([aid, TargetProcessId, ProcessStartTime, ComputerName, UserName, UserSid, ExecutionChain, CommandHistoryClean], limit=max)
| ProcessStartTime:=ProcessStartTime*1000
| ProcessStartTime:=formatTime(format="%F %T.%L %Z", field=ProcessStartTime)
```

**False positives:** Duplicate variants were consolidated. A submitted variant omitted the splitString step and would reference an undefined field.

**Analyst pivot:** Scope by host, user and narrow time window; pivot to process tree and nearby evidence before concluding malicious activity.

</details>

<a name="cs-qb-005"></a>

### 05. Parameterized Process Network Pivot

Provides process/network correlation with analyst parameters and external reputation links.

**Query ID:** `CS-QB-005` · **Platform:** `Not scoped` · **Tags:** `Process`

**MITRE:** Investigation utility · **Status:** `Requires Validation`

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

```cql
defineTable(query={NetworkConnectIP4}, include=[ContextProcessId, RemoteAddressIP4], name="Network")
| #event_simpleName="ProcessRollup2"
| match(file="Network", field=[TargetProcessId], column=ContextProcessId)
| ParentProcessId=?Parent_Process_ID
ParentBaseFileName=?File
UserName=?User
ComputerName=?Computer
TargetProcessId=?Child_Process_ID
| ProcessStartTime:=ProcessStartTime*1000 | ProcessStartTime:=formatTime("%Y-%m-%dT%H:%M:%S.%L",field=ProcessStartTime, timezone="UTC")
| case{
ExecutionChain:=format(format="%s\n\t└ %s (%s)\n\t\t└%s", field=[ParentBaseFileName, FileName, RawProcessId, CommandLine]);
}
| format("[VT Hash reputation](https://www.virustotal.com/gui/file/%s)", field=[SHA256HashData], as="VTHashInfo")
| format("[VT IP reputation](https://www.virustotal.com/gui/ip-address/%s)", field=[RemoteAddressIP4], as="VTIPInfo")
| format("[Abuse IPDB IP reputation](https://www.abuseipdb.com/check/%s)", field=[RemoteAddressIP4], as="IPDBInfo")
| format("[Graph Explorer](https://falcon.crowdstrike.com/graphs/process-explorer/graph?id=pid:%s:%s)", field=[aid, TargetProcessId], as="Graph Explorer")
| format("[Indicator Graph](https://falcon.crowdstrike.com/intelligence/graph?indicators=ip%%3A%%27%s%%27%%2Chash%%3A%%27%s%%27)",field=[RemoteAddressIP4, SHA256HashData],as="Indicator Graph")
| format("[Remote Access Graph](https://falcon.crowdstrike.com//investigate/remote-access-graph?timeRange=last30Days&userName=%s)", field=["UserName"], as="Remote Access Graph")
| groupBy([aid,ParentProcessId,TargetProcessId, ComputerName, UserName, ExecutionChain, RemoteAddressIP4, "Graph Explorer", "Indicator Graph", "Remote Access Graph","VTHashInfo","VTIPInfo","IPDBInfo"], function=[])
| sort(ProcessStartTime, order=asc, limit=max)
```

**False positives:** The final sort references ProcessStartTime after groupBy without retaining it in grouping fields; validate expected output.

**Analyst pivot:** Scope by host, user and narrow time window; pivot to process tree and nearby evidence before concluding malicious activity.

</details>

<a name="cs-qb-006"></a>

### 06. Available Fields by Event Type

Lists fields seen in the query result; ideal for fieldset exploration before writing a high-complexity hunt.

**Query ID:** `CS-QB-006` · **Platform:** `Not scoped` · **Tags:** `Process`

**MITRE:** Operational utility · **Status:** `Requires Validation`

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

```cql
#event_simpleName=ProcessRollup2
| fieldset()
```

**False positives:** No false-positive concept: this is a schema-inspection query.

**Analyst pivot:** Replace ProcessRollup2 with your selected event and inspect returned fields.

</details>

<a name="cs-qb-007"></a>

### 07. Observed Events by Name

Counts available event types in a narrow time window to guide query design.

**Query ID:** `CS-QB-007` · **Platform:** `Not scoped` · **Tags:** `See query`

**MITRE:** Operational utility · **Status:** `Requires Validation`

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

```cql
#event_simpleName=*
| groupBy([#event_simpleName], function=[count(as=EventCount)], limit=1000)
| sort(EventCount, order=desc, limit=1000)
```

**False positives:** Wide search can be expensive.

**Analyst pivot:** Use the time picker to constrain to a short range and a specific repository where possible.

</details>

<a name="cs-qb-008"></a>

### 08. Normalize Host and User Identity Across Schemas

Demonstrates field coalescing for datasets that use different identity keys.

**Query ID:** `CS-QB-008` · **Platform:** `Not scoped` · **Tags:** `Process`

**MITRE:** Operational utility · **Status:** `Requires Validation`

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

```cql
#event_simpleName=ProcessRollup2
| coalesce([ComputerName, host.hostname], as=InvestigationHost)
| coalesce([UserName, user.name], as=InvestigationUser)
| select([@timestamp, InvestigationHost, InvestigationUser, FileName, CommandLine, aid])
```

**False positives:** Coalescing missing fields returns no substitute; verify schema before use.

**Analyst pivot:** Remove alternate fields not present in your environment if necessary.

</details>

<a name="cs-qb-009"></a>

### 09. Process Correlation Key Reference

Provides raw correlation keys for constructing process-to-network, process-to-DNS and process-to-file pivots.

**Query ID:** `CS-QB-009` · **Platform:** `Not scoped` · **Tags:** `DNS`, `Network`, `Process`

**MITRE:** Operational utility · **Status:** `Requires Validation`

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

```cql
#event_simpleName=/^(ProcessRollup2|NetworkConnectIP4|DnsRequest)$/
| select([@timestamp, #event_simpleName, aid, ComputerName, TargetProcessId, ContextProcessId, FileName, ContextBaseFileName])
| sort(@timestamp, order=asc, limit=1000)
```

**False positives:** No detection verdict: key exploration only.

**Analyst pivot:** Join ContextProcessId to TargetProcessId AND scope by aid to avoid cross-host collisions.

</details>

---

`Requires Validation` = not yet tenant-validated · `Tested` = exact-version tested · `Production reviewed` = peer-reviewed with evidence.

[← Home](../README.md) · [All queries](../QUERY-CATALOG.md)
