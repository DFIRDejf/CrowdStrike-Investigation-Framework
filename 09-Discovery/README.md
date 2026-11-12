[← Home](../README.md) · [All queries](../QUERY-CATALOG.md)

# Discovery

**CrowdStrike Falcon / NG-SIEM**  ·  **CQL**  ·  `TA0007`  ·  **6 queries**

Identify host, network, and Active Directory enumeration.

---

## Query library

| Hunt | ID | MITRE | Status |
|:--|:--|:--|:--|
| [01. Account and Domain Enumeration Commands](#cs-ta0007-001) | `CS-TA0007-001` | T1087 / T1069 / T1018 | `Requires Validation` |
| [02. High Port Diversity by Destination](#cs-ta0007-002) | `CS-TA0007-002` | T1046 | `Requires Validation` |
| [03. WMI Query Telemetry](#cs-ta0007-003) | `CS-TA0007-003` | T1047 / T1082 | `Requires Validation` |
| [04. Active Directory RPC Enumeration Events](#cs-ta0007-004) | `CS-TA0007-004` | T1087 / T1482 | `Requires Validation` |
| [05. Shares and Network Enumeration Commands](#cs-ta0007-005) | `CS-TA0007-005` | T1135 / T1046 | `Requires Validation` |
| [06. Domain Controller and Trust Discovery Commands](#cs-ta0007-006) | `CS-TA0007-006` | T1018 / T1482 | `Requires Validation` |

---

<a name="cs-ta0007-001"></a>

### 01. Account and Domain Enumeration Commands

Finds common Windows identity and domain enumeration commands.

**Query ID:** `CS-TA0007-001` · **Platform:** `Windows` · **Tags:** `Process`

**MITRE:** T1087 / T1069 / T1018 · **Status:** `Requires Validation`

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

```cql
#event_simpleName=ProcessRollup2 event_platform=Win
| CommandLine=/(whoami\s+\/all|net\s+(user|group|localgroup|view)|nltest\s|dsquery\s|adfind|ldapsearch|setspn\s|systeminfo)/i
| select([@timestamp, aid, ComputerName, UserName, ParentBaseFileName, FileName, CommandLine])
| sort(@timestamp, order=desc, limit=1000)
```

**False positives:** Helpdesk, inventory, domain administrators and diagnostic scripts.

**Analyst pivot:** Correlate a burst of commands under one process chain and identity.

</details>

<a name="cs-ta0007-002"></a>

### 02. High Port Diversity by Destination

Identifies hosts that connect to many distinct remote ports on a destination; may indicate scanning or administration.

**Query ID:** `CS-TA0007-002` · **Platform:** `Windows` · **Tags:** `Network`

**MITRE:** T1046 · **Status:** `Requires Validation`

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

```cql
#event_simpleName=NetworkConnectIP4 event_platform=Win
| RemoteAddressIP4=*
| groupBy([aid, ComputerName, RemoteAddressIP4], function=[count(RemotePort, distinct=true, as=DistinctPorts), count(as=Connections)], limit=10000)
| DistinctPorts>=20
| sort(DistinctPorts, order=desc, limit=1000)
```

**False positives:** Vulnerability scanning, service discovery and monitoring.

**Analyst pivot:** Tune port threshold against approved scanners and time window.

</details>

<a name="cs-ta0007-003"></a>

### 03. WMI Query Telemetry

Surfaces WMI queries used to inspect endpoint or system details.

**Query ID:** `CS-TA0007-003` · **Platform:** `Not scoped` · **Tags:** `WMI`

**MITRE:** T1047 / T1082 · **Status:** `Requires Validation`

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

```cql
#event_simpleName=/^(WmiQuery)$/
| select([@timestamp, #event_simpleName, ComputerName, UserName, @rawstring, aid])
| sort(@timestamp, order=asc, limit=10000)
```

**False positives:** Enterprise inventory and device management.

**Validation:** Confirm fieldsets and event semantics in the target tenant. [DO WERYFIKACJI W ŚRODOWISKU]

</details>

<a name="cs-ta0007-004"></a>

### 04. Active Directory RPC Enumeration Events

Collects AD RPC request types that may assist domain discovery.

**Query ID:** `CS-TA0007-004` · **Platform:** `Not scoped` · **Tags:** `Identity`

**MITRE:** T1087 / T1482 · **Status:** `Requires Validation`

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

```cql
#event_simpleName=/^(ActiveDirectoryIncomingDceRpcRequest|ActiveDirectoryIncomingDceRpcEpmRequest)$/
| select([@timestamp, #event_simpleName, ComputerName, UserName, @rawstring, aid])
| sort(@timestamp, order=asc, limit=10000)
```

**False positives:** Normal directory lookups; request method must be validated.

**Validation:** Confirm fieldsets and event semantics in the target tenant. [DO WERYFIKACJI W ŚRODOWISKU]

</details>

<a name="cs-ta0007-005"></a>

### 05. Shares and Network Enumeration Commands

Searches for commands enumerating network resources and SMB shares.

**Query ID:** `CS-TA0007-005` · **Platform:** `Not scoped` · **Tags:** `Process`

**MITRE:** T1135 / T1046 · **Status:** `Requires Validation`

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

```cql
#event_simpleName=ProcessRollup2
| CommandLine=/net\s+view|net\s+use|Get-SmbShare|Get-SmbSession|nmap|Test-NetConnection|portscan|arp\s+-a/i
| select([@timestamp, ComputerName, UserName, ParentBaseFileName, ImageFileName, CommandLine, TargetProcessId, aid])
| sort(@timestamp, order=asc, limit=10000)
```

**False positives:** Authorized infrastructure troubleshooting.

**Validation:** Confirm fieldsets and event semantics in the target tenant. [DO WERYFIKACJI W ŚRODOWISKU]

</details>

<a name="cs-ta0007-006"></a>

### 06. Domain Controller and Trust Discovery Commands

Finds command-line discovery of DCs and domain trust relationships.

**Query ID:** `CS-TA0007-006` · **Platform:** `Not scoped` · **Tags:** `Process`

**MITRE:** T1018 / T1482 · **Status:** `Requires Validation`

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

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

`Requires Validation` = not yet tenant-validated · `Tested` = exact-version tested · `Production reviewed` = peer-reviewed with evidence.

[← Home](../README.md) · [All queries](../QUERY-CATALOG.md)
