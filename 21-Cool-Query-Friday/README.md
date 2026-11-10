# Cool Query Friday — Curated Adaptations — CrowdStrike CQL

> **5 CQL entries** | CrowdStrike Falcon / NG-SIEM | MITRE: Community research (not a MITRE tactic)

Original, adapted CQL examples derived from ideas discussed by the CrowdStrike community, with source attribution and explicit validation gates.

> **Validation notice:** Entries marked *User-reported validated source* were provided as working queries, but publication copies were sanitized and must be re-tested. Entries marked *Candidate* and *Community-derived* have **not** been tested in this environment.

## Query Index

1. [New PowerShell DNS Domains Versus Previous Six Days](#01-new-powershell-dns-domains-versus-previous-six-days)
2. [Process and DNS Events Paired by Falcon PID](#02-process-and-dns-events-paired-by-falcon-pid)
3. [Discovery Command Sequence within Five Minutes](#03-discovery-command-sequence-within-five-minutes)
4. [Encoded PowerShell Query Profiling](#04-encoded-powershell-query-profiling)
5. [Browser Extension Inventory by Host](#05-browser-extension-inventory-by-host)

---

## 01. New PowerShell DNS Domains Versus Previous Six Days

**Description:** Compares current PowerShell DNS resolutions against a historical baseline using a small lookup table.

**MITRE ATT&CK:** T1059.001 / T1071.004 (contextual)\
**Origin:** CQF 2024-09-27 — adapted concept (https://www.reddit.com/r/crowdstrike/comments/1fqokic/)\
**Validation:** Community-derived candidate — untested in user environment\
**Required telemetry:** DnsRequest

<details>
<summary><strong>If you want to see more details</strong></summary>

### Hunting Query (CQL)

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

### False Positive Considerations

New domains may be legitimate. Use allowlists and domain age/reputation.

### Investigation Guidance

Compare full-domain and registrable-domain baselines. Inspired by 2024-09-27 CQF.

</details>

---

## 02. Process and DNS Events Paired by Falcon PID

**Description:** Uses a two-pass filter to retain process and DNS records sharing aid and Falcon process identity.

**MITRE ATT&CK:** C2 pivot / investigation utility\
**Origin:** CQF 2023-09-20 — adapted concept (https://www.reddit.com/r/crowdstrike/comments/16soii4/)\
**Validation:** Community-derived candidate — untested in user environment\
**Required telemetry:** ProcessRollup2, DnsRequest

<details>
<summary><strong>If you want to see more details</strong></summary>

### Hunting Query (CQL)

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

### False Positive Considerations

Two-pass search can be expensive. selfJoinFilter is probabilistic: confirm candidate matches.

### Investigation Guidance

Correlate process ID with aid and inspect raw events. Inspired by 2023-09-20 CQF.

</details>

---

## 03. Discovery Command Sequence within Five Minutes

**Description:** Correlates discovery process executions on the same Falcon agent within a five-minute interval.

**MITRE ATT&CK:** T1082 / T1087 (contextual)\
**Origin:** CQF 2026-03-11 — adapted concept (https://www.reddit.com/r/crowdstrike/comments/1rquf4q/)\
**Validation:** Community-derived candidate — untested in user environment\
**Required telemetry:** ProcessRollup2

<details>
<summary><strong>If you want to see more details</strong></summary>

### Hunting Query (CQL)

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

### False Positive Considerations

Admin scripts and security checks often use these commands.

### Investigation Guidance

Change `sequence` to true when the event order itself matters; monitor correlate costs.

</details>

---

## 04. Encoded PowerShell Query Profiling

**Description:** Profiles a constrained search in order to find expensive operations and prefilter inefficiencies.

**MITRE ATT&CK:** Performance diagnostic\
**Origin:** CQF 2026-03-20 — adapted concept (https://www.reddit.com/r/crowdstrike/comments/1ryw8kr/)\
**Validation:** Community-derived candidate — untested in user environment\
**Required telemetry:** ProcessRollup2

<details>
<summary><strong>If you want to see more details</strong></summary>

### Hunting Query (CQL)

```cql
#event_simpleName=ProcessRollup2 event_platform=Win
| FileName=/^(powershell|pwsh)\.exe$/i
| CommandLine=/(\-enc\s|encodedcommand)/i
| groupBy([ComputerName], function=[count(as=Matches)], limit=1000)
| explain:asTable()
```

### False Positive Considerations

Not a detection rule; profiling is for ad-hoc analysis only.

### Investigation Guidance

Run on a fixed short time range and compare Work/performance statistics.

</details>

---

## 05. Browser Extension Inventory by Host

**Description:** Provides a basic browser extension activity count where the InstalledBrowserExtension event is available.

**MITRE ATT&CK:** Software inventory / attack-surface context\
**Origin:** CQF 2024-06-21 — adapted concept (https://www.reddit.com/r/crowdstrike/comments/1dl3bo5/)\
**Validation:** Community-derived candidate — untested in user environment\
**Required telemetry:** InstalledBrowserExtension (license/sensor dependent)

<details>
<summary><strong>If you want to see more details</strong></summary>

### Hunting Query (CQL)

```cql
#event_simpleName=InstalledBrowserExtension
| groupBy([ComputerName], function=[count(as=ExtensionEvents)], limit=1000)
| sort(ExtensionEvents, order=desc, limit=1000)
```

### False Positive Considerations

Event coverage varies by sensor version and license; inventory counts are not extension counts.

### Investigation Guidance

Use fieldset() to identify extension IDs, names and browsers before building a real inventory.

</details>

---
