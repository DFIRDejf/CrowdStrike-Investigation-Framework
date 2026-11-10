[← Home](../README.md) · [All queries](../QUERY-CATALOG.md)

# Query Builder Helper

**CrowdStrike Falcon / NG-SIEM**  ·  **CQL**  ·  `Operational`  ·  **9 queries**

Reusable pivots, field-inspection patterns, and parameterized investigations.

---

## Query library

| Hunt | MITRE | Status |
|:--|:--|:--|
| [01. CIDR-Based Remote IP Search](#01-cidr-based-remote-ip-search) | Investigation utility | `Migration recheck` |
| [02. Command History Scoped Search](#02-command-history-scoped-search) | Investigation utility | `Migration recheck` |
| [03. Process and Network Connection Correlation](#03-process-and-network-connection-correlation) | Investigation utility | `Migration recheck` |
| [04. Command History and Process Rollup](#04-command-history-and-process-rollup) | Investigation utility | `Migration recheck` |
| [05. Parameterized Process Network Pivot](#05-parameterized-process-network-pivot) | Investigation utility | `Migration recheck` |
| [06. Available Fields by Event Type](#06-available-fields-by-event-type) | Operational utility\ | `Candidate` |
| [07. Observed Events by Name](#07-observed-events-by-name) | Operational utility\ | `Candidate` |
| [08. Normalize Host and User Identity Across Schemas](#08-normalize-host-and-user-identity-across-schemas) | Operational utility\ | `Candidate` |
| [09. Process Correlation Key Reference](#09-process-correlation-key-reference) | Operational utility\ | `Candidate` |

---

### 01. CIDR-Based Remote IP Search

Finds events whose RemoteIP field falls within a selected subnet.

**MITRE:** Investigation utility

<details>
<summary><strong>If you want to see more details</strong></summary>

```cql
#event_simpleName=*
| cidr("RemoteIP", subnet="203.0.113.0/24")
```

**False positives:** The subnet is an RFC 5737 documentation example; replace it before use. `RemoteIP` may not exist in every event family. Broad wildcard searches are costly.

**Analyst pivot:** Scope by host, user and narrow time window; pivot to process tree and nearby evidence before concluding malicious activity.

</details>

### 02. Command History Scoped Search

Retrieves command history for investigation-scoped hosts and identities and sorts by command sequence.

**MITRE:** Investigation utility

<details>
<summary><strong>If you want to see more details</strong></summary>

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

### 03. Process and Network Connection Correlation

Associates process execution and network connection events using process identifiers and formats an execution chain.

**MITRE:** Investigation utility

<details>
<summary><strong>If you want to see more details</strong></summary>

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

### 04. Command History and Process Rollup

Combines CommandHistory and ProcessRollup2 events, expands command separators, and displays execution context.

**MITRE:** Investigation utility

<details>
<summary><strong>If you want to see more details</strong></summary>

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

### 05. Parameterized Process Network Pivot

Provides process/network correlation with analyst parameters and external reputation links.

**MITRE:** Investigation utility

<details>
<summary><strong>If you want to see more details</strong></summary>

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

### 06. Available Fields by Event Type

Lists fields seen in the query result; ideal for fieldset exploration before writing a high-complexity hunt.

**MITRE:** Operational utility  ·  **Telemetry:** ProcessRollup2

<details>
<summary><strong>If you want to see more details</strong></summary>

```cql
#event_simpleName=ProcessRollup2
| fieldset()
```

**False positives:** No false-positive concept: this is a schema-inspection query.

**Analyst pivot:** Replace ProcessRollup2 with your selected event and inspect returned fields.

*Origin: OneNote-derived adaptation*

</details>

### 07. Observed Events by Name

Counts available event types in a narrow time window to guide query design.

**MITRE:** Operational utility  ·  **Telemetry:** All accessible event types

<details>
<summary><strong>If you want to see more details</strong></summary>

```cql
#event_simpleName=*
| groupBy([#event_simpleName], function=[count(as=EventCount)], limit=1000)
| sort(EventCount, order=desc, limit=1000)
```

**False positives:** Wide search can be expensive.

**Analyst pivot:** Use the time picker to constrain to a short range and a specific repository where possible.

*Origin: OneNote-derived adaptation*

</details>

### 08. Normalize Host and User Identity Across Schemas

Demonstrates field coalescing for datasets that use different identity keys.

**MITRE:** Operational utility  ·  **Telemetry:** ProcessRollup2 + alternate schemas

<details>
<summary><strong>If you want to see more details</strong></summary>

```cql
#event_simpleName=ProcessRollup2
| coalesce([ComputerName, host.hostname], as=InvestigationHost)
| coalesce([UserName, user.name], as=InvestigationUser)
| select([@timestamp, InvestigationHost, InvestigationUser, FileName, CommandLine, aid])
```

**False positives:** Coalescing missing fields returns no substitute; verify schema before use.

**Analyst pivot:** Remove alternate fields not present in your environment if necessary.

*Origin: OneNote-derived adaptation*

</details>

### 09. Process Correlation Key Reference

Provides raw correlation keys for constructing process-to-network, process-to-DNS and process-to-file pivots.

**MITRE:** Operational utility  ·  **Telemetry:** ProcessRollup2, NetworkConnectIP4, DnsRequest

<details>
<summary><strong>If you want to see more details</strong></summary>

```cql
#event_simpleName=/^(ProcessRollup2|NetworkConnectIP4|DnsRequest)$/
| select([@timestamp, #event_simpleName, aid, ComputerName, TargetProcessId, ContextProcessId, FileName, ContextBaseFileName])
| sort(@timestamp, order=asc, limit=1000)
```

**False positives:** No detection verdict: key exploration only.

**Analyst pivot:** Join ContextProcessId to TargetProcessId AND scope by aid to avoid cross-host collisions.

*Origin: OneNote-derived adaptation*

</details>

---

`Migration recheck` = original supplied query was previously tested, but this publication copy needs validation. `Candidate` / `Community candidate` = not validated in the target Falcon environment.

[← Home](../README.md) · [All queries](../QUERY-CATALOG.md)
