[← Home](../README.md) · [All queries](../QUERY-CATALOG.md)

# Discovery

**CrowdStrike Falcon / NG-SIEM**  ·  **CQL**  ·  `TA0007`  ·  **6 queries**

Identify host, network, and Active Directory enumeration.

---

## Query library

| Hunt | MITRE | Status |
|:--|:--|:--|
| [01. Account and Domain Enumeration Commands](#01-account-and-domain-enumeration-commands) | T1087 / T1069 / T1018\ | `Candidate` |
| [02. High Port Diversity by Destination](#02-high-port-diversity-by-destination) | T1046\ | `Candidate` |
| [03. WMI Query Telemetry](#03-wmi-query-telemetry) | T1047 / T1082 | `Requires Validation` |
| [04. Active Directory RPC Enumeration Events](#04-active-directory-rpc-enumeration-events) | T1087 / T1482 | `Requires Validation` |
| [05. Shares and Network Enumeration Commands](#05-shares-and-network-enumeration-commands) | T1135 / T1046 | `Requires Validation` |
| [06. Domain Controller and Trust Discovery Commands](#06-domain-controller-and-trust-discovery-commands) | T1018 / T1482 | `Requires Validation` |

---

### 01. Account and Domain Enumeration Commands

Finds common Windows identity and domain enumeration commands.

**MITRE:** T1087 / T1069 / T1018  ·  **Telemetry:** ProcessRollup2

<details>
<summary><strong>If you want to see more details</strong></summary>

```cql
#event_simpleName=ProcessRollup2 event_platform=Win
| CommandLine=/(whoami\s+\/all|net\s+(user|group|localgroup|view)|nltest\s|dsquery\s|adfind|ldapsearch|setspn\s|systeminfo)/i
| select([@timestamp, aid, ComputerName, UserName, ParentBaseFileName, FileName, CommandLine])
| sort(@timestamp, order=desc, limit=1000)
```

**False positives:** Helpdesk, inventory, domain administrators and diagnostic scripts.

**Analyst pivot:** Correlate a burst of commands under one process chain and identity.

*Origin: OneNote-derived adaptation*

</details>

### 02. High Port Diversity by Destination

Identifies hosts that connect to many distinct remote ports on a destination; may indicate scanning or administration.

**MITRE:** T1046  ·  **Telemetry:** NetworkConnectIP4

<details>
<summary><strong>If you want to see more details</strong></summary>

```cql
#event_simpleName=NetworkConnectIP4 event_platform=Win
| RemoteAddressIP4=*
| groupBy([aid, ComputerName, RemoteAddressIP4], function=[count(RemotePort, distinct=true, as=DistinctPorts), count(as=Connections)], limit=10000)
| DistinctPorts>=20
| sort(DistinctPorts, order=desc, limit=1000)
```

**False positives:** Vulnerability scanning, service discovery and monitoring.

**Analyst pivot:** Tune port threshold against approved scanners and time window.

*Origin: OneNote-derived adaptation*

</details>

### 03. WMI Query Telemetry

Surfaces WMI queries used to inspect endpoint or system details.

**MITRE:** T1047 / T1082  ·  **Source:** `CS Queries.one`  ·  **Status:** `Requires Validation`

<details>
<summary><strong>If you want to see more details</strong></summary>

```cql
#event_simpleName=/^(WmiQuery)$/
| select([@timestamp, #event_simpleName, ComputerName, UserName, @rawstring, aid])
| sort(@timestamp, order=asc, limit=10000)
```

**False positives:** Enterprise inventory and device management.

**Validation:** Confirm fieldsets and event semantics in the target tenant. [DO WERYFIKACJI W ŚRODOWISKU]

</details>

### 04. Active Directory RPC Enumeration Events

Collects AD RPC request types that may assist domain discovery.

**MITRE:** T1087 / T1482  ·  **Source:** `CS Queries.one`  ·  **Status:** `Requires Validation`

<details>
<summary><strong>If you want to see more details</strong></summary>

```cql
#event_simpleName=/^(ActiveDirectoryIncomingDceRpcRequest|ActiveDirectoryIncomingDceRpcEpmRequest)$/
| select([@timestamp, #event_simpleName, ComputerName, UserName, @rawstring, aid])
| sort(@timestamp, order=asc, limit=10000)
```

**False positives:** Normal directory lookups; request method must be validated.

**Validation:** Confirm fieldsets and event semantics in the target tenant. [DO WERYFIKACJI W ŚRODOWISKU]

</details>

### 05. Shares and Network Enumeration Commands

Searches for commands enumerating network resources and SMB shares.

**MITRE:** T1135 / T1046  ·  **Source:** `CS Queries.one`  ·  **Status:** `Requires Validation`

<details>
<summary><strong>If you want to see more details</strong></summary>

```cql
#event_simpleName=ProcessRollup2
| CommandLine=/net\s+view|net\s+use|Get-SmbShare|Get-SmbSession|nmap|Test-NetConnection|portscan|arp\s+-a/i
| select([@timestamp, ComputerName, UserName, ParentBaseFileName, ImageFileName, CommandLine, TargetProcessId, aid])
| sort(@timestamp, order=asc, limit=10000)
```

**False positives:** Authorized infrastructure troubleshooting.

**Validation:** Confirm fieldsets and event semantics in the target tenant. [DO WERYFIKACJI W ŚRODOWISKU]

</details>

### 06. Domain Controller and Trust Discovery Commands

Finds command-line discovery of DCs and domain trust relationships.

**MITRE:** T1018 / T1482  ·  **Source:** `CS Queries.one`  ·  **Status:** `Requires Validation`

<details>
<summary><strong>If you want to see more details</strong></summary>

```cql
#event_simpleName=ProcessRollup2
| CommandLine=/nltest|dsquery|Get-ADDomainController|Get-ADTrust|netdom\s+trust|setspn\s+-T/i
| select([@timestamp, ComputerName, UserName, ParentBaseFileName, ImageFileName, CommandLine, TargetProcessId, aid])
| sort(@timestamp, order=asc, limit=10000)
```

**False positives:** Routine Active Directory administration.

**Validation:** Confirm fieldsets and event semantics in the target tenant. [DO WERYFIKACJI W ŚRODOWISKU]

</details>


---

`Migration recheck` = original supplied query was previously tested, but this publication copy needs validation. `Candidate` / `Community candidate` = not validated in the target Falcon environment.

[← Home](../README.md) · [All queries](../QUERY-CATALOG.md)
