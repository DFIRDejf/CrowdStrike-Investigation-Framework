[← Home](../README.md) · [All queries](../QUERY-CATALOG.md)

# Command and Control

**CrowdStrike Falcon / NG-SIEM**  ·  **CQL**  ·  `TA0011`  ·  **13 queries**

Correlate process, DNS, and network activity linked to potential C2.

---

## Query library

| Hunt | ID | MITRE | Status |
|:--|:--|:--|:--|
| [01. DNS and Network Connections by Process](#cs-ta0011-001) | `CS-TA0011-001` | T1071.001 (contextual) | `Requires Validation` |
| [02. Process Execution and DNS Correlation](#cs-ta0011-002) | `CS-TA0011-002` | Investigation utility | `Requires Validation` |
| [03. DNS Queries from Investigated Endpoints](#cs-ta0011-003) | `CS-TA0011-003` | T1071.004 (contextual) | `Requires Validation` |
| [04. Remote Access and Tunneling Utility Commands](#cs-ta0011-004) | `CS-TA0011-004` | T1572 / T1219 / T1105 | `Requires Validation` |
| [05. DNS Request and Suspicious DNS Detection Events](#cs-ta0011-005) | `CS-TA0011-005` | T1071.004 | `Requires Validation` |
| [06. DNS Requests by Endpoint and Process](#cs-ta0011-006) | `CS-TA0011-006` | T1071.004 (context) | `Requires Validation` |
| [07. SSH Tunnel Creation Events](#cs-ta0011-007) | `CS-TA0011-007` | T1572 | `Requires Validation` |
| [08. Tunneling and Remote Tool Execution](#cs-ta0011-008) | `CS-TA0011-008` | T1572 / T1219 | `Requires Validation` |

| [09. CIDR-Based Remote IP Search](#cs-qb-001) | `CS-QB-001` | Investigation utility | `Requires Validation` |
| [10. Process and Network Connection Correlation](#cs-qb-003) | `CS-QB-003` | Investigation utility | `Requires Validation` |
| [11. Parameterized Process Network Pivot](#cs-qb-005) | `CS-QB-005` | Investigation utility | `Requires Validation` |
| [12. New PowerShell DNS Domains Versus Previous Six Days](#cs-cqf-001) | `CS-CQF-001` | T1059.001 / T1071.004 (contextual) | `Requires Validation` |
| [13. Process and DNS Events Paired by Falcon PID](#cs-cqf-002) | `CS-CQF-002` | C2 pivot / investigation utility | `Requires Validation` |
---

<a name="cs-ta0011-001"></a>

### 01. DNS and Network Connections by Process

Matches DNS requests to network connection events by ContextProcessId and exposes interactive search parameters.

**Query ID:** `CS-TA0011-001` · **Platform:** `Not scoped` · **Tags:** `DNS`, `Network`

**MITRE:** T1071.001 (contextual) · **Status:** `Requires Validation`

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

```cql
defineTable(query={#event_simpleName=DnsRequest | wildcard(field=DomainName, pattern=?DomainName, ignoreCase=true)}, include=[ContextProcessId,DomainName], name=_DNSRequests)
| #event_simpleName=NetworkConnectIP4 RemotePort<49152 RemoteAddressIP4=?External_IPv4 LocalAddressIP4=?LAN_IPv4 RemotePort=?External_Port
| wildcard(field=ComputerName, pattern=?ComputerName, ignoreCase=true)
| match(file=_DNSRequests, field=[ContextProcessId])
| groupBy([aid], function=collect([ComputerName, LocalAddressIP4, DomainName, RemoteAddressIP4, RemotePort]))
```

</details>

<a name="cs-ta0011-002"></a>

### 02. Process Execution and DNS Correlation

Links DNS requests to process executions and creates a process-explorer hyperlink.

**Query ID:** `CS-TA0011-002` · **Platform:** `Not scoped` · **Tags:** `DNS`, `Process`

**MITRE:** Investigation utility · **Status:** `Requires Validation`

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

```cql
setTimeInterval(start="7d")
| defineTable(query={#event_simpleName=DnsRequest | DomainName=~wildcard(?DomainName, ignoreCase=true)}, include=[DomainName,ContextProcessId], name=DnsRequest)
| #event_simpleName=ProcessRollup2
| UserName=~wildcard(?UserName, ignoreCase=true)
| FileName=~wildcard(?FileName, ignoreCase=true)
| ParentBaseFileName=~wildcard(?ParentBaseFileName, ignoreCase=true)
| ComputerName=~wildcard(?ComputerName, ignoreCase=true)
| match(file=DnsRequest, field=[TargetProcessId], column=ContextProcessId)
| ExecutionChain:=format(format="%s\n\t└ %s (%s)", field=[ParentBaseFileName, FileName, RawProcessId])
| groupBy([aid,TargetProcessId, ComputerName, UserName, ExecutionChain, DomainName, CommandLine], function=[])
| format("[Graph Explorer](https://falcon.crowdstrike.com/graphs/process-explorer/graph?id=pid:%s:%s)", field=[aid, TargetProcessId], as="Graph Explorer")
```

</details>

<a name="cs-ta0011-003"></a>

### 03. DNS Queries from Investigated Endpoints

Provides a compact DNS telemetry starting point for domain, process and destination investigation.

**Query ID:** `CS-TA0011-003` · **Platform:** `Windows` · **Tags:** `DNS`

**MITRE:** T1071.004 (contextual) · **Status:** `Requires Validation`

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

```cql
#event_simpleName=DnsRequest event_platform=Win
| DomainName=*
| select([@timestamp, ComputerName, DomainName, ContextBaseFileName, ContextProcessId, aid])
| sort(@timestamp, order=desc, limit=1000)
```

</details>

<a name="cs-ta0011-004"></a>

### 04. Remote Access and Tunneling Utility Commands

Looks for potential tunneling flags and remote control tool names in process command lines.

**Query ID:** `CS-TA0011-004` · **Platform:** `Windows` · **Tags:** `Process`

**MITRE:** T1572 / T1219 / T1105 · **Status:** `Requires Validation`

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

```cql
#event_simpleName=ProcessRollup2 event_platform=Win
| CommandLine=/(ssh\s+(-L|-R|-D)|plink|chisel|ngrok|cloudflared|socat|rustdesk|anydesk)/i
| select([@timestamp, ComputerName, UserName, ParentBaseFileName, FileName, CommandLine, aid])
| sort(@timestamp, order=desc, limit=1000)
```

</details>

<a name="cs-ta0011-005"></a>

### 05. DNS Request and Suspicious DNS Detection Events

Surfaces suspicious DNS detections and DNS requests for investigation.

**Query ID:** `CS-TA0011-005` · **Platform:** `Not scoped` · **Tags:** `DNS`

**MITRE:** T1071.004 · **Status:** `Requires Validation`

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

```cql
#event_simpleName=/^(SuspiciousDnsRequest|DnsRequest)$/
| @rawstring=/(dns|query|tunnel|\.top|\.xyz)/i
| select([@timestamp, #event_simpleName, ComputerName, UserName, @rawstring, aid])
| sort(@timestamp, order=asc, limit=10000)
```

</details>

<a name="cs-ta0011-006"></a>

### 06. DNS Requests by Endpoint and Process

Shows DNS resolution and available process correlation fields.

**Query ID:** `CS-TA0011-006` · **Platform:** `Not scoped` · **Tags:** `DNS`

**MITRE:** T1071.004 (context) · **Status:** `Requires Validation`

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

```cql
#event_simpleName=DnsRequest
| select([@timestamp, ComputerName, DomainName, RequestType, QueryStatus, FirstIP4Record, ContextBaseFileName, ContextProcessId, aid])
| sort(@timestamp, order=asc, limit=10000)
```

</details>

<a name="cs-ta0011-007"></a>

### 07. SSH Tunnel Creation Events

Lists SSH tunnel creation telemetry for follow-up.

**Query ID:** `CS-TA0011-007` · **Platform:** `Not scoped` · **Tags:** `Network`

**MITRE:** T1572 · **Status:** `Requires Validation`

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

```cql
#event_simpleName=/^(SSHTunnelCreated)$/
| select([@timestamp, #event_simpleName, ComputerName, UserName, @rawstring, aid])
| sort(@timestamp, order=asc, limit=10000)
```

</details>

<a name="cs-ta0011-008"></a>

### 08. Tunneling and Remote Tool Execution

Hunts for command lines involving SSH port forwarding and tunneling utilities.

**Query ID:** `CS-TA0011-008` · **Platform:** `Not scoped` · **Tags:** `Process`

**MITRE:** T1572 / T1219 · **Status:** `Requires Validation`

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

```cql
#event_simpleName=ProcessRollup2
| CommandLine=/ssh\s+(-L|-R|-D)|plink|chisel|ngrok|cloudflared|socat|rustdesk|anydesk|curl|wget|certutil\s+.*urlcache/i
| select([@timestamp, ComputerName, UserName, ParentBaseFileName, ImageFileName, CommandLine, TargetProcessId, aid])
| sort(@timestamp, order=asc, limit=10000)
```

</details>

<a name="cs-qb-001"></a>

### 09. CIDR-Based Remote IP Search

Finds events whose RemoteIP field falls within a selected subnet.

**Query ID:** `CS-QB-001` · **Platform:** `Not scoped` · **Tags:** `See query`

**MITRE:** Investigation utility · **Status:** `Requires Validation`

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

```cql
#event_simpleName=*
| cidr("RemoteIP", subnet="203.0.113.0/24")
```

</details>

<a name="cs-qb-003"></a>

### 10. Process and Network Connection Correlation

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

</details>

<a name="cs-qb-005"></a>

### 11. Parameterized Process Network Pivot

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

</details>

<a name="cs-cqf-001"></a>

### 12. New PowerShell DNS Domains Versus Previous Six Days

Compares current PowerShell DNS resolutions against a historical baseline using a small lookup table.

**Query ID:** `CS-CQF-001` · **Platform:** `Windows` · **Tags:** `DNS`

**MITRE:** T1059.001 / T1071.004 (contextual) · **Status:** `Requires Validation`

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

```cql
setTimeInterval(start="1d")
| defineTable(
    start=7d,
    end=1d,
    query={#event_simpleName=DnsRequest event_platform=Win ContextBaseFileName=powershell.exe | DomainName=*},
    include=[DomainName],
    name="PreviousPowerShellDomains")
| #event_simpleName=DnsRequest event_platform=Win ContextBaseFileName=powershell.exe
| DomainName=*
| !match(file="PreviousPowerShellDomains", field=[DomainName], strict=true)
| groupBy([ComputerName, DomainName], function=[count(as=Observations)], limit=1000)
```

</details>

<a name="cs-cqf-002"></a>

### 13. Process and DNS Events Paired by Falcon PID

Uses a two-pass filter to retain process and DNS records sharing aid and Falcon process identity.

**Query ID:** `CS-CQF-002` · **Platform:** `Not scoped` · **Tags:** `DNS`, `Process`

**MITRE:** C2 pivot / investigation utility · **Status:** `Requires Validation`

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

```cql
#event_simpleName=/^(ProcessRollup2|DnsRequest)$/
| case {
    #event_simpleName=ProcessRollup2 | FalconPID:=TargetProcessId;
    #event_simpleName=DnsRequest | FalconPID:=ContextProcessId;
  }
| FalconPID=*
| selfJoinFilter(field=[aid, FalconPID], where=[{#event_simpleName=ProcessRollup2}, {#event_simpleName=DnsRequest}], prefilter=true)
| groupBy([aid, FalconPID], function=[collect([ComputerName, FileName, DomainName, CommandLine])], limit=1000)
```

</details>

---

`Requires Validation` = not yet tenant-validated · `Tested` = exact-version tested · `Production reviewed` = peer-reviewed with evidence.

[← Home](../README.md) · [All queries](../QUERY-CATALOG.md)
