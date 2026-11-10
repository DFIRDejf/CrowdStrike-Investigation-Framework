# Defense Evasion (Legacy Folder Name) — CrowdStrike CQL

> **2 CQL entries** | CrowdStrike Falcon / NG-SIEM | MITRE: Review MITRE technique IDs

Investigate suspicious changes to security controls and evidence-evasion behaviors. This folder name is retained for compatibility with the existing repository.

> **Validation notice:** Entries marked *User-reported validated source* were provided as working queries, but publication copies were sanitized and must be re-tested. Entries marked *Candidate* and *Community-derived* have **not** been tested in this environment.

## Query Index

1. [Security Control Modification Commands](#01-security-control-modification-commands)
2. [Sensor and Prevention Diagnostics](#02-sensor-and-prevention-diagnostics)

---

## 01. Security Control Modification Commands

**Description:** Looks for command-line attempts to alter Defender settings, relevant services or event logging.

**MITRE ATT&CK:** T1562.001 / T1070 (contextual)\
**Origin:** OneNote-derived adaptation\
**Validation:** Candidate — requires validation in Falcon\
**Required telemetry:** ProcessRollup2

<details>
<summary><strong>If you want to see more details</strong></summary>

### Hunting Query (CQL)

```cql
#event_simpleName=ProcessRollup2 event_platform=Win
| CommandLine=/(set-mppreference|add-mppreference|disableantispyware|wevtutil\s+sl|sc\s+(stop|config).*\b(sense|windefend|csagent))/i
| select([@timestamp, ComputerName, UserName, ParentBaseFileName, FileName, CommandLine, aid])
| sort(@timestamp, order=desc, limit=1000)
```

### False Positive Considerations

Authorized security operations and troubleshooting.

### Investigation Guidance

Correlate command execution with sensor tamper/prevention events; no inference of successful bypass.

</details>

---

## 02. Sensor and Prevention Diagnostics

**Description:** Inventories selected protective control state and diagnostic event types for review.

**MITRE ATT&CK:** T1562.001 (contextual)\
**Origin:** OneNote-derived adaptation\
**Validation:** Candidate — requires validation in Falcon\
**Required telemetry:** SensorAntiTamperState and related events

<details>
<summary><strong>If you want to see more details</strong></summary>

### Hunting Query (CQL)

```cql
#event_simpleName=/^(EAMBypassEvent|SensorAntiTamperState|DriverPreventionStatus|DetectionExcluded|SensorSelfDiagnosticTelemetry)$/
| select([@timestamp, #event_simpleName, ComputerName, aid])
| sort(@timestamp, order=desc, limit=1000)
```

### False Positive Considerations

Routine control state changes; event fields and licensing vary.

### Investigation Guidance

Use fieldset() for schema inspection before alerting on outcomes.

</details>

---
