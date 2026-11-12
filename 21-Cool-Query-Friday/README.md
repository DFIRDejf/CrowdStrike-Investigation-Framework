[← Home](../README.md) · [All queries](../QUERY-CATALOG.md)

# Cool Query Friday

**CrowdStrike Falcon / NG-SIEM**  ·  **CQL**  ·  `Community`  ·  **5 queries**

Curated community-inspired query patterns with source attribution.

---

## Query library

| Hunt | ID | MITRE | Status |
|:--|:--|:--|:--|
| [01. New PowerShell DNS Domains Versus Previous Six Days](#cs-cqf-001) | `CS-CQF-001` | T1059.001 / T1071.004 (contextual) | `Requires Validation` |
| [02. Process and DNS Events Paired by Falcon PID](#cs-cqf-002) | `CS-CQF-002` | C2 pivot / investigation utility | `Requires Validation` |
| [03. Discovery Command Sequence within Five Minutes](#cs-cqf-003) | `CS-CQF-003` | T1082 / T1087 (contextual) | `Requires Validation` |
| [04. Encoded PowerShell Query Profiling](#cs-cqf-004) | `CS-CQF-004` | Performance diagnostic | `Requires Validation` |
| [05. Browser Extension Inventory by Host](#cs-cqf-005) | `CS-CQF-005` | Software inventory / attack-surface context | `Requires Validation` |

---

<a name="cs-cqf-001"></a>

### 01. New PowerShell DNS Domains Versus Previous Six Days

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

**False positives:** New domains may be legitimate. Use allowlists and domain age/reputation.

**Analyst pivot:** Compare full-domain and registrable-domain baselines. Inspired by 2024-09-27 CQF.

</details>

<a name="cs-cqf-002"></a>

### 02. Process and DNS Events Paired by Falcon PID

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

**False positives:** Two-pass search can be expensive. selfJoinFilter is probabilistic: confirm candidate matches.

**Analyst pivot:** Correlate process ID with aid and inspect raw events. Inspired by 2023-09-20 CQF.

</details>

<a name="cs-cqf-003"></a>

### 03. Discovery Command Sequence within Five Minutes

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

**False positives:** Admin scripts and security checks often use these commands.

**Analyst pivot:** Change `sequence` to true when the event order itself matters; monitor correlate costs.

</details>

<a name="cs-cqf-004"></a>

### 04. Encoded PowerShell Query Profiling

Profiles a constrained search in order to find expensive operations and prefilter inefficiencies.

**Query ID:** `CS-CQF-004` · **Platform:** `Windows` · **Tags:** `Process`

**MITRE:** Performance diagnostic · **Status:** `Requires Validation`

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

```cql
#event_simpleName=ProcessRollup2 event_platform=Win
| FileName=/^(powershell|pwsh)\.exe$/i
| CommandLine=/(\-enc\s|encodedcommand)/i
| groupBy([ComputerName], function=[count(as=Matches)], limit=1000)
| explain:asTable()
```

**False positives:** Not a detection rule; profiling is for ad-hoc analysis only.

**Analyst pivot:** Run on a fixed short time range and compare Work/performance statistics.

</details>

<a name="cs-cqf-005"></a>

### 05. Browser Extension Inventory by Host

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

**False positives:** Event coverage varies by sensor version and license; inventory counts are not extension counts.

**Analyst pivot:** Use fieldset() to identify extension IDs, names and browsers before building a real inventory.

</details>

---

`Requires Validation` = not yet tenant-validated · `Tested` = exact-version tested · `Production reviewed` = peer-reviewed with evidence.

[← Home](../README.md) · [All queries](../QUERY-CATALOG.md)
