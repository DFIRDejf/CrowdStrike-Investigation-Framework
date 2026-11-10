# Command and Control — CrowdStrike CQL

> **4 CQL entries** | CrowdStrike Falcon / NG-SIEM | MITRE: TA0011

Investigate DNS, external network activity, and remote access or tunneling behaviors.

> **Validation notice:** Entries marked *User-reported validated source* were provided as working queries, but publication copies were sanitized and must be re-tested. Entries marked *Candidate* and *Community-derived* have **not** been tested in this environment.

## Query Index

1. [DNS and Network Connections by Process](#01-dns-and-network-connections-by-process)
2. [Process Execution and DNS Correlation](#02-process-execution-and-dns-correlation)
3. [DNS Queries from Investigated Endpoints](#03-dns-queries-from-investigated-endpoints)
4. [Remote Access and Tunneling Utility Commands](#04-remote-access-and-tunneling-utility-commands)

---

## 01. DNS and Network Connections by Process

**Description:** Matches DNS requests to network connection events by ContextProcessId and exposes interactive search parameters.

**MITRE ATT&CK:** T1071.001 (contextual)\
**Origin:** Previously supplied CQL — sanitized migration copy\
**Validation:** User-reported validated source; revalidate sanitized copy\
**Required telemetry:** See event filters in query

<details>
<summary><strong>If you want to see more details</strong></summary>

### Hunting Query (CQL)

```cql
defineTable(query={#event_simpleName=DnsRequest | wildcard(field=DomainName, pattern=?DomainName, ignoreCase=true)}, include=[ContextProcessId,DomainName], name=_DNSRequests)
| #event_simpleName=NetworkConnectIP4 RemotePort<49152 RemoteAddressIP4=?External_IPv4 LocalAddressIP4=?LAN_IPv4 RemotePort=?External_Port
| wildcard(field=ComputerName, pattern=?ComputerName, ignoreCase=true)
| match(file=_DNSRequests, field=[ContextProcessId])
| groupBy([aid], function=collect([ComputerName, LocalAddressIP4, DomainName, RemoteAddressIP4, RemotePort]))
```

### False Positive Considerations

Supply the search parameters. The lookup keys on process ID alone. Include the agent ID in the match before using results across hosts. A shared process does not prove that a DNS request led to a connection.

### Investigation Guidance

Scope by host, user and narrow time window; pivot to process tree and nearby evidence before concluding malicious activity.

</details>

---

## 02. Process Execution and DNS Correlation

**Description:** Links DNS requests to process executions and creates a process-explorer hyperlink.

**MITRE ATT&CK:** Investigation utility\
**Origin:** Previously supplied CQL — sanitized migration copy\
**Validation:** User-reported validated source; revalidate sanitized copy\
**Required telemetry:** See event filters in query

<details>
<summary><strong>If you want to see more details</strong></summary>

### Hunting Query (CQL)

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

### False Positive Considerations

Validate tenant-specific Graph Explorer URLs. The lookup keys on process ID alone. Include the agent ID in the match before using results across hosts.

### Investigation Guidance

Scope by host, user and narrow time window; pivot to process tree and nearby evidence before concluding malicious activity.

</details>

---

## 03. DNS Queries from Investigated Endpoints

**Description:** Provides a compact DNS telemetry starting point for domain, process and destination investigation.

**MITRE ATT&CK:** T1071.004 (contextual)\
**Origin:** OneNote-derived adaptation\
**Validation:** Candidate — requires validation in Falcon\
**Required telemetry:** DnsRequest

<details>
<summary><strong>If you want to see more details</strong></summary>

### Hunting Query (CQL)

```cql
#event_simpleName=DnsRequest event_platform=Win
| DomainName=*
| select([@timestamp, ComputerName, DomainName, ContextBaseFileName, ContextProcessId, aid])
| sort(@timestamp, order=desc, limit=1000)
```

### False Positive Considerations

Browsers and operating system services produce high DNS volume.

### Investigation Guidance

Filter targeted hosts and unusual processes before expanding scope.

</details>

---

## 04. Remote Access and Tunneling Utility Commands

**Description:** Looks for potential tunneling flags and remote control tool names in process command lines.

**MITRE ATT&CK:** T1572 / T1219 / T1105\
**Origin:** OneNote-derived adaptation\
**Validation:** Candidate — requires validation in Falcon\
**Required telemetry:** ProcessRollup2

<details>
<summary><strong>If you want to see more details</strong></summary>

### Hunting Query (CQL)

```cql
#event_simpleName=ProcessRollup2 event_platform=Win
| CommandLine=/(ssh\s+(-L|-R|-D)|plink|chisel|ngrok|cloudflared|socat|rustdesk|anydesk)/i
| select([@timestamp, ComputerName, UserName, ParentBaseFileName, FileName, CommandLine, aid])
| sort(@timestamp, order=desc, limit=1000)
```

### False Positive Considerations

Approved remote administration, developer tunnels and support software.

### Investigation Guidance

Validate business approval and correlate outbound network events.

</details>

---
