[← Home](../README.md) · [All queries](../QUERY-CATALOG.md)

# Reconnaissance

**CrowdStrike Falcon / NG-SIEM**  ·  **CQL**  ·  `TA0043`  ·  **3 queries**

Investigate pre-compromise information gathering when relevant telemetry is available.

---

## Query library

| Hunt | ID | MITRE | Status |
|:--|:--|:--|:--|
| [01. Reconnaissance Footprints in Browser History](#cs-ta0043-001) | `CS-TA0043-001` | T1592 | `Production reviewed` |
| [02. Potential Inbound Scan Touchpoints](#cs-ta0043-002) | `CS-TA0043-002` | T1595 | `Production reviewed` |
| [03. Host and Domain Reconnaissance Commands](#cs-ta0043-003) | `CS-TA0043-003` | T1593 / T1046 | `Production reviewed` |

---

<a name="cs-ta0043-001"></a>

### 01. Reconnaissance Footprints in Browser History

Surfaces browser activity involving public reconnaissance services.

**Query ID:** `CS-TA0043-001` · **Platform:** `Not scoped` · **Tags:** `Browser`

**MITRE:** T1592 · **Status:** `Production reviewed`

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

```cql
#event_simpleName=/^(BrowserHistoryVisit)$/
| @rawstring=/(whois|shodan|censys|crt\.sh|dnsdumpster)/i
| select([@timestamp, #event_simpleName, ComputerName, UserName, @rawstring, aid])
| sort(@timestamp, order=asc, limit=10000)
```

**False positives:** Research and security-team browsing; browser history alone cannot prove pre-compromise reconnaissance.

</details>

<a name="cs-ta0043-002"></a>

### 02. Potential Inbound Scan Touchpoints

Provides inbound network telemetry for investigating scanning hypotheses.

**Query ID:** `CS-TA0043-002` · **Platform:** `Not scoped` · **Tags:** `Network`

**MITRE:** T1595 · **Status:** `Production reviewed`

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

```cql
#event_simpleName=NetworkReceiveAcceptIP4
| RemoteAddressIP4=*
| select([@timestamp, ComputerName, LocalAddressIP4, LocalPort, RemoteAddressIP4, RemotePort, ContextBaseFileName, ContextProcessId, aid])
| sort(@timestamp, order=asc, limit=10000)
```

</details>

<a name="cs-ta0043-003"></a>

### 03. Host and Domain Reconnaissance Commands

Locates endpoint execution of network and domain research utilities.

**Query ID:** `CS-TA0043-003` · **Platform:** `Not scoped` · **Tags:** `Process`

**MITRE:** T1593 / T1046 · **Status:** `Production reviewed`

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

```cql
#event_simpleName=ProcessRollup2
| CommandLine=/nmap|masscan|rustscan|nslookup|whois|dig\s|test-netconnection/i
| select([@timestamp, ComputerName, UserName, ParentBaseFileName, ImageFileName, CommandLine, TargetProcessId, aid])
| sort(@timestamp, order=asc, limit=10000)
```

</details>

[← Home](../README.md) · [All queries](../QUERY-CATALOG.md)
