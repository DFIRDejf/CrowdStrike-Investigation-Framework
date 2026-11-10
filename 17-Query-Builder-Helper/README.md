# Query Builder Helper — CrowdStrike CQL

> **9 CQL entries** | CrowdStrike Falcon / NG-SIEM | MITRE: Operational (not a MITRE tactic)

Reusable search scaffolds, correlation pivots, investigation parameters and field-inspection utilities.

> **Validation notice:** Entries marked *User-reported validated source* were provided as working queries, but publication copies were sanitized and must be re-tested. Entries marked *Candidate* and *Community-derived* have **not** been tested in this environment.

## Query Index

1. [CIDR-Based Remote IP Search](#01-cidr-based-remote-ip-search)
2. [Command History Scoped Search](#02-command-history-scoped-search)
3. [Process and Network Connection Correlation](#03-process-and-network-connection-correlation)
4. [Command History and Process Rollup](#04-command-history-and-process-rollup)
5. [Parameterized Process Network Pivot](#05-parameterized-process-network-pivot)
6. [Available Fields by Event Type](#06-available-fields-by-event-type)
7. [Observed Events by Name](#07-observed-events-by-name)
8. [Normalize Host and User Identity Across Schemas](#08-normalize-host-and-user-identity-across-schemas)
9. [Process Correlation Key Reference](#09-process-correlation-key-reference)

---

## 01. CIDR-Based Remote IP Search

**Description:** Finds events whose RemoteIP field falls within a selected subnet.

**MITRE ATT&CK:** Investigation utility\
**Origin:** Previously supplied CQL — sanitized migration copy\
**Validation:** User-reported validated source; revalidate sanitized copy\
**Required telemetry:** See event filters in query

<details>
<summary><strong>If you want to see more details</strong></summary>

### Hunting Query (CQL)

```cql
#event_simpleName=*
| cidr("RemoteIP", subnet="203.0.113.0/24")
```

### False Positive Considerations

The subnet is an RFC 5737 documentation example; replace it before use. `RemoteIP` may not exist in every event family. Broad wildcard searches are costly.

### Investigation Guidance

Scope by host, user and narrow time window; pivot to process tree and nearby evidence before concluding malicious activity.

</details>

---

## 02. Command History Scoped Search

**Description:** Retrieves command history for investigation-scoped hosts and identities and sorts by command sequence.

**MITRE ATT&CK:** Investigation utility\
**Origin:** Previously supplied CQL — sanitized migration copy\
**Validation:** User-reported validated source; revalidate sanitized copy\
**Required telemetry:** See event filters in query

<details>
<summary><strong>If you want to see more details</strong></summary>

### Hunting Query (CQL)

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

### False Positive Considerations

Sequence order is not necessarily global chronological order across multiple hosts.

### Investigation Guidance

Scope by host, user and narrow time window; pivot to process tree and nearby evidence before concluding malicious activity.

</details>

---

## 03. Process and Network Connection Correlation

**Description:** Associates process execution and network connection events using process identifiers and formats an execution chain.

**MITRE ATT&CK:** Investigation utility\
**Origin:** Previously supplied CQL — sanitized migration copy\
**Validation:** User-reported validated source; revalidate sanitized copy\
**Required telemetry:** See event filters in query

<details>
<summary><strong>If you want to see more details</strong></summary>

### Hunting Query (CQL)

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

### False Positive Considerations

Match keys are process identifiers; review host scoping to avoid collisions and verify timestamp units.

### Investigation Guidance

Scope by host, user and narrow time window; pivot to process tree and nearby evidence before concluding malicious activity.

</details>

---

## 04. Command History and Process Rollup

**Description:** Combines CommandHistory and ProcessRollup2 events, expands command separators, and displays execution context.

**MITRE ATT&CK:** Investigation utility\
**Origin:** Previously supplied CQL — sanitized migration copy\
**Validation:** User-reported validated source; revalidate sanitized copy\
**Required telemetry:** See event filters in query

<details>
<summary><strong>If you want to see more details</strong></summary>

### Hunting Query (CQL)

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

### False Positive Considerations

Duplicate variants were consolidated. A submitted variant omitted the splitString step and would reference an undefined field.

### Investigation Guidance

Scope by host, user and narrow time window; pivot to process tree and nearby evidence before concluding malicious activity.

</details>

---

## 05. Parameterized Process Network Pivot

**Description:** Provides process/network correlation with analyst parameters and external reputation links.

**MITRE ATT&CK:** Investigation utility\
**Origin:** Previously supplied CQL — sanitized migration copy\
**Validation:** User-reported validated source; revalidate sanitized copy\
**Required telemetry:** See event filters in query

<details>
<summary><strong>If you want to see more details</strong></summary>

### Hunting Query (CQL)

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

### False Positive Considerations

The final sort references ProcessStartTime after groupBy without retaining it in grouping fields; validate expected output.

### Investigation Guidance

Scope by host, user and narrow time window; pivot to process tree and nearby evidence before concluding malicious activity.

</details>

---

## 06. Available Fields by Event Type

**Description:** Lists fields seen in the query result; ideal for fieldset exploration before writing a high-complexity hunt.

**MITRE ATT&CK:** Operational utility\
**Origin:** OneNote-derived adaptation\
**Validation:** Candidate — requires validation in Falcon\
**Required telemetry:** ProcessRollup2

<details>
<summary><strong>If you want to see more details</strong></summary>

### Hunting Query (CQL)

```cql
#event_simpleName=ProcessRollup2
| fieldset()
```

### False Positive Considerations

No false-positive concept: this is a schema-inspection query.

### Investigation Guidance

Replace ProcessRollup2 with your selected event and inspect returned fields.

</details>

---

## 07. Observed Events by Name

**Description:** Counts available event types in a narrow time window to guide query design.

**MITRE ATT&CK:** Operational utility\
**Origin:** OneNote-derived adaptation\
**Validation:** Candidate — requires validation in Falcon\
**Required telemetry:** All accessible event types

<details>
<summary><strong>If you want to see more details</strong></summary>

### Hunting Query (CQL)

```cql
#event_simpleName=*
| groupBy([#event_simpleName], function=[count(as=EventCount)], limit=1000)
| sort(EventCount, order=desc, limit=1000)
```

### False Positive Considerations

Wide search can be expensive.

### Investigation Guidance

Use the time picker to constrain to a short range and a specific repository where possible.

</details>

---

## 08. Normalize Host and User Identity Across Schemas

**Description:** Demonstrates field coalescing for datasets that use different identity keys.

**MITRE ATT&CK:** Operational utility\
**Origin:** OneNote-derived adaptation\
**Validation:** Candidate — requires validation in Falcon\
**Required telemetry:** ProcessRollup2 + alternate schemas

<details>
<summary><strong>If you want to see more details</strong></summary>

### Hunting Query (CQL)

```cql
#event_simpleName=ProcessRollup2
| coalesce([ComputerName, host.hostname], as=InvestigationHost)
| coalesce([UserName, user.name], as=InvestigationUser)
| select([@timestamp, InvestigationHost, InvestigationUser, FileName, CommandLine, aid])
```

### False Positive Considerations

Coalescing missing fields returns no substitute; verify schema before use.

### Investigation Guidance

Remove alternate fields not present in your environment if necessary.

</details>

---

## 09. Process Correlation Key Reference

**Description:** Provides raw correlation keys for constructing process-to-network, process-to-DNS and process-to-file pivots.

**MITRE ATT&CK:** Operational utility\
**Origin:** OneNote-derived adaptation\
**Validation:** Candidate — requires validation in Falcon\
**Required telemetry:** ProcessRollup2, NetworkConnectIP4, DnsRequest

<details>
<summary><strong>If you want to see more details</strong></summary>

### Hunting Query (CQL)

```cql
#event_simpleName=/^(ProcessRollup2|NetworkConnectIP4|DnsRequest)$/
| select([@timestamp, #event_simpleName, aid, ComputerName, TargetProcessId, ContextProcessId, FileName, ContextBaseFileName])
| sort(@timestamp, order=asc, limit=1000)
```

### False Positive Considerations

No detection verdict: key exploration only.

### Investigation Guidance

Join ContextProcessId to TargetProcessId AND scope by aid to avoid cross-host collisions.

</details>

---
