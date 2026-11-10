[← Framework home](../README.md)

# Defense Evasion

**CrowdStrike Falcon / NG-SIEM**  ·  **CQL**  ·  `TA0005 · legacy folder`  ·  **2 queries**

Investigate tampering, security control changes, and evasion-related activity.

---

> **Compatibility:** Retained as a legacy folder name; see [MITRE mapping](../docs/MITRE-ATTACK-2026-MAPPING.md).

## Query library

| Hunt | Status |
|---|---|
| [01. Security Control Modification Commands](#01-security-control-modification-commands) | `Candidate` |
| [02. Sensor and Prevention Diagnostics](#02-sensor-and-prevention-diagnostics) | `Candidate` |

---

### 01. Security Control Modification Commands

Looks for command-line attempts to alter Defender settings, relevant services or event logging.

**MITRE:** T1562.001 / T1070 (contextual)\  ·  **Telemetry:** ProcessRollup2

<details>
<summary><strong>If you want to see more details</strong></summary>

```cql
#event_simpleName=ProcessRollup2 event_platform=Win
| CommandLine=/(set-mppreference|add-mppreference|disableantispyware|wevtutil\s+sl|sc\s+(stop|config).*\b(sense|windefend|csagent))/i
| select([@timestamp, ComputerName, UserName, ParentBaseFileName, FileName, CommandLine, aid])
| sort(@timestamp, order=desc, limit=1000)
```

**False positives:** Authorized security operations and troubleshooting.

**Analyst pivot:** Correlate command execution with sensor tamper/prevention events; no inference of successful bypass.

*Origin: OneNote-derived adaptation\*

</details>

### 02. Sensor and Prevention Diagnostics

Inventories selected protective control state and diagnostic event types for review.

**MITRE:** T1562.001 (contextual)\  ·  **Telemetry:** SensorAntiTamperState and related events

<details>
<summary><strong>If you want to see more details</strong></summary>

```cql
#event_simpleName=/^(EAMBypassEvent|SensorAntiTamperState|DriverPreventionStatus|DetectionExcluded|SensorSelfDiagnosticTelemetry)$/
| select([@timestamp, #event_simpleName, ComputerName, aid])
| sort(@timestamp, order=desc, limit=1000)
```

**False positives:** Routine control state changes; event fields and licensing vary.

**Analyst pivot:** Use fieldset() for schema inspection before alerting on outcomes.

*Origin: OneNote-derived adaptation\*

</details>

---

`Migration recheck` = original supplied query was previously tested, but this publication copy needs validation. `Candidate` / `Community candidate` = not validated in the target Falcon environment.

[← Back to framework](../README.md)
