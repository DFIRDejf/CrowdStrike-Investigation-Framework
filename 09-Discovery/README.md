[← Home](../README.md) · [All queries](../QUERY-CATALOG.md)

# Discovery

**CrowdStrike Falcon / NG-SIEM**  ·  **CQL**  ·  `TA0007`  ·  **13 queries**

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
| [07. File-System Artifact Event Inventory](#cs-fa-002) | `CS-FA-002` | DFIR utility | `Requires Validation` |
| [08. Available Fields by Event Type](#cs-qb-006) | `CS-QB-006` | Operational utility | `Requires Validation` |
| [09. Observed Events by Name](#cs-qb-007) | `CS-QB-007` | Operational utility | `Requires Validation` |
| [10. Normalize Host and User Identity Across Schemas](#cs-qb-008) | `CS-QB-008` | Operational utility | `Requires Validation` |
| [11. Process Correlation Key Reference](#cs-qb-009) | `CS-QB-009` | Operational utility | `Requires Validation` |
| [12. Discovery Command Sequence within Five Minutes](#cs-cqf-003) | `CS-CQF-003` | T1082 / T1087 (contextual) | `Requires Validation` |
| [13. Browser Extension Inventory by Host](#cs-cqf-005) | `CS-CQF-005` | Software inventory / attack-surface context | `Requires Validation` |
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

</details>

---

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

</details>

---

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

</details>

---

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

</details>

---

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

</details>

---

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

</details>

---

<a name="cs-fa-002"></a>

### 07. File-System Artifact Event Inventory

Inventories file system artifact events to establish coverage before content-based hunting.

**Query ID:** `CS-FA-002` · **Platform:** `Not scoped` · **Tags:** `File`

**MITRE:** DFIR utility · **Status:** `Requires Validation`

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

```cql
#event_simpleName=/^(FileInfo|USNRecord|PrefetchFile)$/
| groupBy([#event_simpleName, ComputerName], function=[count(as=Events)], limit=1000)
| sort(Events, order=desc, limit=1000)
```

</details>

---

<a name="cs-qb-006"></a>

### 08. Available Fields by Event Type

Lists fields seen in the query result; ideal for fieldset exploration before writing a high-complexity hunt.

**Query ID:** `CS-QB-006` · **Platform:** `Not scoped` · **Tags:** `Process`

**MITRE:** Operational utility · **Status:** `Requires Validation`

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

```cql
#event_simpleName=ProcessRollup2
| fieldset()
```

</details>

---

<a name="cs-qb-007"></a>

### 09. Observed Events by Name

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

</details>

---

<a name="cs-qb-008"></a>

### 10. Normalize Host and User Identity Across Schemas

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

</details>

---

<a name="cs-qb-009"></a>

### 11. Process Correlation Key Reference

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

</details>

---

<a name="cs-cqf-003"></a>

### 12. Discovery Command Sequence within Five Minutes

Correlates discovery process executions on the same Falcon agent within a five-minute interval.

**Query ID:** `CS-CQF-003` · **Platform:** `Windows` · **Tags:** `Process`

**MITRE:** T1082 / T1087 (contextual) · **Status:** `Requires Validation`

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

```cql
correlate(
  whoami: {#event_simpleName=ProcessRollup2 event_platform=Win FileName="whoami.exe"} include:[aid, ComputerName, FileName],
  net: {#event_simpleName=ProcessRollup2 event_platform=Win FileName="net.exe"} include:[aid, ComputerName, FileName],
  systeminfo: {#event_simpleName=ProcessRollup2 event_platform=Win FileName="systeminfo.exe"} include:[aid, ComputerName, FileName],
  globalConstraints=[aid],
  sequence=false,
  within=5m
)
```

</details>

---

<a name="cs-cqf-005"></a>

### 13. Browser Extension Inventory by Host

Provides a basic browser extension activity count where the InstalledBrowserExtension event is available.

**Query ID:** `CS-CQF-005` · **Platform:** `Not scoped` · **Tags:** `Browser`

**MITRE:** Software inventory / attack-surface context · **Status:** `Requires Validation`

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

```cql
#event_simpleName=InstalledBrowserExtension
| groupBy([ComputerName], function=[count(as=ExtensionEvents)], limit=1000)
| sort(ExtensionEvents, order=desc, limit=1000)
```

</details>

---

`Requires Validation` = not yet tenant-validated · `Tested` = exact-version tested · `Production reviewed` = peer-reviewed with evidence.

[← Home](../README.md) · [All queries](../QUERY-CATALOG.md)
