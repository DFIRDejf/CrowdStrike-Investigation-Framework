[← Framework home](../README.md)

# Command and Control

**CrowdStrike Falcon / NG-SIEM**  ·  **CQL**  ·  `TA0011`  ·  **4 queries**

Correlate process, DNS, and network activity linked to potential C2.

---

## Query library

| Hunt | Status |
|---|---|
| [01. DNS and Network Connections by Process](#01-dns-and-network-connections-by-process) | `Migration recheck` |
| [02. Process Execution and DNS Correlation](#02-process-execution-and-dns-correlation) | `Migration recheck` |
| [03. DNS Queries from Investigated Endpoints](#03-dns-queries-from-investigated-endpoints) | `Candidate` |
| [04. Remote Access and Tunneling Utility Commands](#04-remote-access-and-tunneling-utility-commands) | `Candidate` |

---

### 01. DNS and Network Connections by Process

Matches DNS requests to network connection events by ContextProcessId and exposes interactive search parameters.

**MITRE:** T1071.001 (contextual)\

<details>
<summary><strong>If you want to see more details</strong></summary>

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

### 02. Process Execution and DNS Correlation

Links DNS requests to process executions and creates a process-explorer hyperlink.

**MITRE:** Investigation utility\

<details>
<summary><strong>If you want to see more details</strong></summary>

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

### 03. DNS Queries from Investigated Endpoints

Provides a compact DNS telemetry starting point for domain, process and destination investigation.

**MITRE:** T1071.004 (contextual)\  ·  **Telemetry:** DnsRequest

<details>
<summary><strong>If you want to see more details</strong></summary>

```cql
#event_simpleName=DnsRequest event_platform=Win
| DomainName=*
| select([@timestamp, ComputerName, DomainName, ContextBaseFileName, ContextProcessId, aid])
| sort(@timestamp, order=desc, limit=1000)
```

**False positives:** Browsers and operating system services produce high DNS volume.

**Analyst pivot:** Filter targeted hosts and unusual processes before expanding scope.

*Origin: OneNote-derived adaptation\*

</details>

### 04. Remote Access and Tunneling Utility Commands

Looks for potential tunneling flags and remote control tool names in process command lines.

**MITRE:** T1572 / T1219 / T1105\  ·  **Telemetry:** ProcessRollup2

<details>
<summary><strong>If you want to see more details</strong></summary>

```cql
#event_simpleName=ProcessRollup2 event_platform=Win
| CommandLine=/(ssh\s+(-L|-R|-D)|plink|chisel|ngrok|cloudflared|socat|rustdesk|anydesk)/i
| select([@timestamp, ComputerName, UserName, ParentBaseFileName, FileName, CommandLine, aid])
| sort(@timestamp, order=desc, limit=1000)
```

**False positives:** Approved remote administration, developer tunnels and support software.

**Analyst pivot:** Validate business approval and correlate outbound network events.

*Origin: OneNote-derived adaptation\*

</details>

---

`Migration recheck` = original supplied query was previously tested, but this publication copy needs validation. `Candidate` / `Community candidate` = not validated in the target Falcon environment.

[← Back to framework](../README.md)
