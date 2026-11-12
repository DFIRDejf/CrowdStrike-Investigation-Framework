[← Home](../README.md) · [All queries](../QUERY-CATALOG.md)

# Command and Control

**CrowdStrike Falcon / NG-SIEM**  ·  **CQL**  ·  `TA0011`  ·  **8 queries**

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

**False positives:** Supply the search parameters. The lookup keys on process ID alone. Include the agent ID in the match before using results across hosts. A shared process does not prove that a DNS request led to a connection.

**Analyst pivot:** Scope by host, user and narrow time window; pivot to process tree and nearby evidence before concluding malicious activity.

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

**False positives:** Validate tenant-specific Graph Explorer URLs. The lookup keys on process ID alone. Include the agent ID in the match before using results across hosts.

**Analyst pivot:** Scope by host, user and narrow time window; pivot to process tree and nearby evidence before concluding malicious activity.

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

**False positives:** Browsers and operating system services produce high DNS volume.

**Analyst pivot:** Filter targeted hosts and unusual processes before expanding scope.

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

**False positives:** Approved remote administration, developer tunnels and support software.

**Analyst pivot:** Validate business approval and correlate outbound network events.

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

**False positives:** Legitimate DNS activity and benign use of the listed TLDs.

**Validation:** Confirm event fields and semantic coverage in Falcon. [DO WERYFIKACJI W ŚRODOWISKU]

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

**False positives:** Any normal DNS lookup; pair with process and network observations.

**Validation:** Confirm event fields and semantic coverage in Falcon. [DO WERYFIKACJI W ŚRODOWISKU]

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

**False positives:** Approved port forwarding and development tunnels.

**Validation:** Confirm event fields and semantic coverage in Falcon. [DO WERYFIKACJI W ŚRODOWISKU]

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

**False positives:** Authorized support, development tunnels and package retrieval.

**Validation:** Confirm event fields and semantic coverage in Falcon. [DO WERYFIKACJI W ŚRODOWISKU]

</details>


---

`Requires Validation` = not yet tenant-validated · `Tested` = exact-version tested · `Production reviewed` = peer-reviewed with evidence.

[← Home](../README.md) · [All queries](../QUERY-CATALOG.md)
