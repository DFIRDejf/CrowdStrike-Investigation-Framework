[← Home](../README.md) · [All queries](../QUERY-CATALOG.md)

# Cool Query Friday

**CrowdStrike Falcon / NG-SIEM**  ·  **CQL**  ·  `Community`  ·  **5 queries**

Curated community-inspired query patterns with source attribution.

---

## Query library

| Hunt | MITRE | Status |
|:--|:--|:--|
| [01. New PowerShell DNS Domains Versus Previous Six Days](#01-new-powershell-dns-domains-versus-previous-six-days) | T1059.001 / T1071.004 (contextual) | `Community candidate` |
| [02. Process and DNS Events Paired by Falcon PID](#02-process-and-dns-events-paired-by-falcon-pid) | C2 pivot / investigation utility | `Community candidate` |
| [03. Discovery Command Sequence within Five Minutes](#03-discovery-command-sequence-within-five-minutes) | T1082 / T1087 (contextual) | `Community candidate` |
| [04. Encoded PowerShell Query Profiling](#04-encoded-powershell-query-profiling) | Performance diagnostic | `Community candidate` |
| [05. Browser Extension Inventory by Host](#05-browser-extension-inventory-by-host) | Software inventory / attack-surface context | `Community candidate` |

---

### 01. New PowerShell DNS Domains Versus Previous Six Days

Compares current PowerShell DNS resolutions against a historical baseline using a small lookup table.

**MITRE:** T1059.001 / T1071.004 (contextual)  ·  **Telemetry:** DnsRequest

<details>
<summary><strong>If you want to see more details</strong></summary>

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

*Origin: CQF 2024-09-27 — adapted concept (https://www.reddit.com/r/crowdstrike/comments/1fqokic/)*

</details>

### 02. Process and DNS Events Paired by Falcon PID

Uses a two-pass filter to retain process and DNS records sharing aid and Falcon process identity.

**MITRE:** C2 pivot / investigation utility  ·  **Telemetry:** ProcessRollup2, DnsRequest

<details>
<summary><strong>If you want to see more details</strong></summary>

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

*Origin: CQF 2023-09-20 — adapted concept (https://www.reddit.com/r/crowdstrike/comments/16soii4/)*

</details>

### 03. Discovery Command Sequence within Five Minutes

Correlates discovery process executions on the same Falcon agent within a five-minute interval.

**MITRE:** T1082 / T1087 (contextual)  ·  **Telemetry:** ProcessRollup2

<details>
<summary><strong>If you want to see more details</strong></summary>

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

*Origin: CQF 2026-03-11 — adapted concept (https://www.reddit.com/r/crowdstrike/comments/1rquf4q/)*

</details>

### 04. Encoded PowerShell Query Profiling

Profiles a constrained search in order to find expensive operations and prefilter inefficiencies.

**MITRE:** Performance diagnostic  ·  **Telemetry:** ProcessRollup2

<details>
<summary><strong>If you want to see more details</strong></summary>

```cql
#event_simpleName=ProcessRollup2 event_platform=Win
| FileName=/^(powershell|pwsh)\.exe$/i
| CommandLine=/(\-enc\s|encodedcommand)/i
| groupBy([ComputerName], function=[count(as=Matches)], limit=1000)
| explain:asTable()
```

**False positives:** Not a detection rule; profiling is for ad-hoc analysis only.

**Analyst pivot:** Run on a fixed short time range and compare Work/performance statistics.

*Origin: CQF 2026-03-20 — adapted concept (https://www.reddit.com/r/crowdstrike/comments/1ryw8kr/)*

</details>

### 05. Browser Extension Inventory by Host

Provides a basic browser extension activity count where the InstalledBrowserExtension event is available.

**MITRE:** Software inventory / attack-surface context  ·  **Telemetry:** InstalledBrowserExtension (license/sensor dependent)

<details>
<summary><strong>If you want to see more details</strong></summary>

```cql
#event_simpleName=InstalledBrowserExtension
| groupBy([ComputerName], function=[count(as=ExtensionEvents)], limit=1000)
| sort(ExtensionEvents, order=desc, limit=1000)
```

**False positives:** Event coverage varies by sensor version and license; inventory counts are not extension counts.

**Analyst pivot:** Use fieldset() to identify extension IDs, names and browsers before building a real inventory.

*Origin: CQF 2024-06-21 — adapted concept (https://www.reddit.com/r/crowdstrike/comments/1dl3bo5/)*

</details>

---

`Migration recheck` = original supplied query was previously tested, but this publication copy needs validation. `Candidate` / `Community candidate` = not validated in the target Falcon environment.

[← Home](../README.md) · [All queries](../QUERY-CATALOG.md)
