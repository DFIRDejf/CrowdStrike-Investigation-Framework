[← Home](../README.md) · [All queries](../QUERY-CATALOG.md)

# Defense Evasion

**CrowdStrike Falcon / NG-SIEM**  ·  **CQL**  ·  `TA0005 · legacy folder`  ·  **8 queries**

Investigate tampering, security control changes, and evasion-related activity.

---

> **Compatibility:** Retained as a legacy folder name; see [MITRE mapping](../docs/MITRE-ATTACK-2026-MAPPING.md).

## Query library

| Hunt | MITRE | Status |
|:--|:--|:--|
| [01. Security Control Modification Commands](#01-security-control-modification-commands) | T1562.001 / T1070 (contextual)\ | `Candidate` |
| [02. Sensor and Prevention Diagnostics](#02-sensor-and-prevention-diagnostics) | T1562.001 (contextual)\ | `Candidate` |
| [03. Security Log and Trace File Deletion](#03-security-log-and-trace-file-deletion) | T1070.004 | `Requires Validation` |
| [04. Firewall and WFP Modification Events](#04-firewall-and-wfp-modification-events) | T1562.004 | `Requires Validation` |
| [05. Unsigned Modules and Suspicious File Signatures](#05-unsigned-modules-and-suspicious-file-signatures) | T1027 / T1036 | `Requires Validation` |
| [06. Sensor Anti-Tamper and Bypass Telemetry](#06-sensor-anti-tamper-and-bypass-telemetry) | T1562.001 | `Requires Validation` |
| [07. Suspicious Macro and Invalid Script Events](#07-suspicious-macro-and-invalid-script-events) | T1027 | `Requires Validation` |
| [08. Potential Log Clearing Commands](#08-potential-log-clearing-commands) | T1070 | `Requires Validation` |

---

### 01. Security Control Modification Commands

Looks for command-line attempts to alter Defender settings, relevant services or event logging.

**MITRE:** T1562.001 / T1070 (contextual)  ·  **Telemetry:** ProcessRollup2

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

*Origin: OneNote-derived adaptation*

</details>

### 02. Sensor and Prevention Diagnostics

Inventories selected protective control state and diagnostic event types for review.

**MITRE:** T1562.001 (contextual)  ·  **Telemetry:** SensorAntiTamperState and related events

<details>
<summary><strong>If you want to see more details</strong></summary>

```cql
#event_simpleName=/^(EAMBypassEvent|SensorAntiTamperState|DriverPreventionStatus|DetectionExcluded|SensorSelfDiagnosticTelemetry)$/
| select([@timestamp, #event_simpleName, ComputerName, aid])
| sort(@timestamp, order=desc, limit=1000)
```

**False positives:** Routine control state changes; event fields and licensing vary.

**Analyst pivot:** Use fieldset() for schema inspection before alerting on outcomes.

*Origin: OneNote-derived adaptation*

</details>

### 03. Security Log and Trace File Deletion

Examines deletion and USN records involving logs and script files.

**MITRE:** T1070.004  ·  **Source:** `CS Queries.one`  ·  **Status:** `Requires Validation`

<details>
<summary><strong>If you want to see more details</strong></summary>

```cql
#event_simpleName=/^(FileDeleted|USNRecord)$/
| @rawstring=/(\.evtx|\.log|\.pf|\.ps1|\.tmp)/i
| select([@timestamp, #event_simpleName, ComputerName, UserName, @rawstring, aid])
| sort(@timestamp, order=asc, limit=10000)
```

**False positives:** Ordinary log rollover and cleanup; deletion alone does not prove an attack.

**Validation:** Confirm fieldsets and event semantics in the target tenant. [DO WERYFIKACJI W ŚRODOWISKU]

</details>

### 04. Firewall and WFP Modification Events

Surfaces firewall rule manipulation and Windows Filtering Platform activity.

**MITRE:** T1562.004  ·  **Source:** `CS Queries.one`  ·  **Status:** `Requires Validation`

<details>
<summary><strong>If you want to see more details</strong></summary>

```cql
#event_simpleName=/^(WfpFilterTamperingFilterAdded|FirewallDeleteRuleIP4|FirewallSetRuleIP4)$/
| select([@timestamp, #event_simpleName, ComputerName, UserName, @rawstring, aid])
| sort(@timestamp, order=asc, limit=10000)
```

**False positives:** Review approved administrative operations and expected security tooling.

**Validation:** Confirm fieldsets and event semantics in the target tenant. [DO WERYFIKACJI W ŚRODOWISKU]

</details>

### 05. Unsigned Modules and Suspicious File Signatures

Inspects file signature discrepancies and unsigned module events.

**MITRE:** T1027 / T1036  ·  **Source:** `CS Queries.one`  ·  **Status:** `Requires Validation`

<details>
<summary><strong>If you want to see more details</strong></summary>

```cql
#event_simpleName=/^(FileSignatureMismatch|PackedExecutableWritten|UnsignedModuleLoad)$/
| select([@timestamp, #event_simpleName, ComputerName, UserName, @rawstring, aid])
| sort(@timestamp, order=asc, limit=10000)
```

**False positives:** Review approved administrative operations and expected security tooling.

**Validation:** Confirm fieldsets and event semantics in the target tenant. [DO WERYFIKACJI W ŚRODOWISKU]

</details>

### 06. Sensor Anti-Tamper and Bypass Telemetry

Reviews sensor bypass, exclusions and anti-tamper status event families.

**MITRE:** T1562.001  ·  **Source:** `CS Queries.one`  ·  **Status:** `Requires Validation`

<details>
<summary><strong>If you want to see more details</strong></summary>

```cql
#event_simpleName=/^(EAMBypassEvent|SensorAntiTamperState|DriverPreventionStatus|DetectionExcluded|SensorSelfDiagnosticTelemetry)$/
| select([@timestamp, #event_simpleName, ComputerName, UserName, @rawstring, aid])
| sort(@timestamp, order=asc, limit=10000)
```

**False positives:** Diagnostics, policy deployment and sensor upgrades.

**Validation:** Confirm fieldsets and event semantics in the target tenant. [DO WERYFIKACJI W ŚRODOWISKU]

</details>

### 07. Suspicious Macro and Invalid Script Events

Surfaces macros, malformed scripts and packed process detection events.

**MITRE:** T1027  ·  **Source:** `CS Queries.one`  ·  **Status:** `Requires Validation`

<details>
<summary><strong>If you want to see more details</strong></summary>

```cql
#event_simpleName=/^(MacroDetectInfo|MacroContentInfo|ScriptControlDetectInvalidInfo|ProcessExecOnPackedExecutable)$/
| select([@timestamp, #event_simpleName, ComputerName, UserName, @rawstring, aid])
| sort(@timestamp, order=asc, limit=10000)
```

**False positives:** Review approved administrative operations and expected security tooling.

**Validation:** Confirm fieldsets and event semantics in the target tenant. [DO WERYFIKACJI W ŚRODOWISKU]

</details>

### 08. Potential Log Clearing Commands

Searches for process commands that may clear Windows event logs or command history.

**MITRE:** T1070  ·  **Source:** `CS Queries.one`  ·  **Status:** `Requires Validation`

<details>
<summary><strong>If you want to see more details</strong></summary>

```cql
#event_simpleName=ProcessRollup2
| CommandLine=/wevtutil\s+(cl|clear-log)|clear-eventlog|remove-item.*(history|\.evtx)|del\s+.*\.log|powershell.*clear-history/i
| select([@timestamp, ComputerName, UserName, ParentBaseFileName, ImageFileName, CommandLine, TargetProcessId, aid])
| sort(@timestamp, order=asc, limit=10000)
```

**False positives:** Approved log maintenance; inspect process ancestry and change control.

**Validation:** Confirm fieldsets and event semantics in the target tenant. [DO WERYFIKACJI W ŚRODOWISKU]

</details>


---

`Migration recheck` = original supplied query was previously tested, but this publication copy needs validation. `Candidate` / `Community candidate` = not validated in the target Falcon environment.

[← Home](../README.md) · [All queries](../QUERY-CATALOG.md)
