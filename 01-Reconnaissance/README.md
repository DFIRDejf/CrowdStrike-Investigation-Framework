[← Home](../README.md) · [All queries](../QUERY-CATALOG.md)

# Reconnaissance

**CrowdStrike Falcon / NG-SIEM**  ·  **CQL**  ·  `TA0043`  ·  **3 queries**

Investigate pre-compromise information gathering when relevant telemetry is available.

---

## Query library

| Hunt | MITRE | Status |
|:--|:--|:--|
| [01. Reconnaissance Footprints in Browser History](#01-reconnaissance-footprints-in-browser-history) | T1592 (context) | `Requires Validation` |
| [02. Potential Inbound Scan Touchpoints](#02-potential-inbound-scan-touchpoints) | T1595 (context) | `Requires Validation` |
| [03. Host and Domain Reconnaissance Commands](#03-host-and-domain-reconnaissance-commands) | T1593 / T1046 (context) | `Requires Validation` |

---

### 01. Reconnaissance Footprints in Browser History

Surfaces browser activity involving public reconnaissance services.

**MITRE:** T1592 (context)  ·  **Source:** `CS Queries.one`  ·  **Status:** `Requires Validation`

<details>
<summary><strong>If you want to see more details</strong></summary>

```cql
#event_simpleName=/^(BrowserHistoryVisit)$/
| @rawstring=/(whois|shodan|censys|crt\.sh|dnsdumpster)/i
| select([@timestamp, #event_simpleName, ComputerName, UserName, @rawstring, aid])
| sort(@timestamp, order=asc, limit=10000)
```

**False positives:** Research and security-team browsing; browser history alone cannot prove pre-compromise reconnaissance.

**Validation:** Confirm event and field availability and expected semantics in Falcon. [DO WERYFIKACJI W ŚRODOWISKU]

</details>

### 02. Potential Inbound Scan Touchpoints

Provides inbound network telemetry for investigating scanning hypotheses.

**MITRE:** T1595 (context)  ·  **Source:** `CS Queries.one`  ·  **Status:** `Requires Validation`

<details>
<summary><strong>If you want to see more details</strong></summary>

```cql
#event_simpleName=NetworkReceiveAcceptIP4
| RemoteAddressIP4=*
| select([@timestamp, ComputerName, LocalAddressIP4, LocalPort, RemoteAddressIP4, RemotePort, ContextBaseFileName, ContextProcessId, aid])
| sort(@timestamp, order=asc, limit=10000)
```

**False positives:** Accept events do not measure all unsuccessful probes or establish adversary intent.

**Validation:** Confirm event and field availability and expected semantics in Falcon. [DO WERYFIKACJI W ŚRODOWISKU]

</details>

### 03. Host and Domain Reconnaissance Commands

Locates endpoint execution of network and domain research utilities.

**MITRE:** T1593 / T1046 (context)  ·  **Source:** `CS Queries.one`  ·  **Status:** `Requires Validation`

<details>
<summary><strong>If you want to see more details</strong></summary>

```cql
#event_simpleName=ProcessRollup2
| CommandLine=/nmap|masscan|rustscan|nslookup|whois|dig\s|test-netconnection/i
| select([@timestamp, ComputerName, UserName, ParentBaseFileName, ImageFileName, CommandLine, TargetProcessId, aid])
| sort(@timestamp, order=asc, limit=10000)
```

**False positives:** Expected support diagnostics and authorized vulnerability scanning.

**Validation:** Confirm event and field availability and expected semantics in Falcon. [DO WERYFIKACJI W ŚRODOWISKU]

</details>

[← Home](../README.md) · [All queries](../QUERY-CATALOG.md)
