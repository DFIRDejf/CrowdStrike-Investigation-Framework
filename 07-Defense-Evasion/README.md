[← Home](../README.md) · [All queries](../QUERY-CATALOG.md)

# Defense Evasion

**CrowdStrike Falcon / NG-SIEM**  ·  **CQL**  ·  `TA0005 · legacy folder`  ·  **8 queries**

Investigate tampering, security control changes, and evasion-related activity.

---

> **Compatibility:** This legacy category name is retained to preserve existing links. Validate ATT&CK mappings against the current official framework.

## Query library

| Hunt | ID | MITRE | Status |
|:--|:--|:--|:--|
| [01. Security Control Modification Commands](#cs-ta0005-001) | `CS-TA0005-001` | T1562.001 / T1070 (contextual) | `Requires Validation` |
| [02. Sensor and Prevention Diagnostics](#cs-ta0005-002) | `CS-TA0005-002` | T1562.001 (contextual) | `Requires Validation` |
| [03. Security Log and Trace File Deletion](#cs-ta0005-003) | `CS-TA0005-003` | T1070.004 | `Requires Validation` |
| [04. Firewall and WFP Modification Events](#cs-ta0005-004) | `CS-TA0005-004` | T1562.004 | `Requires Validation` |
| [05. Unsigned Modules and Suspicious File Signatures](#cs-ta0005-005) | `CS-TA0005-005` | T1027 / T1036 | `Requires Validation` |
| [06. Sensor Anti-Tamper and Bypass Telemetry](#cs-ta0005-006) | `CS-TA0005-006` | T1562.001 | `Requires Validation` |
| [07. Suspicious Macro and Invalid Script Events](#cs-ta0005-007) | `CS-TA0005-007` | T1027 | `Requires Validation` |
| [08. Potential Log Clearing Commands](#cs-ta0005-008) | `CS-TA0005-008` | T1070 | `Requires Validation` |

---

<a name="cs-ta0005-001"></a>

### 01. Security Control Modification Commands

Looks for command-line attempts to alter Defender settings, relevant services or event logging.

**Query ID:** `CS-TA0005-001` · **Platform:** `Windows` · **Tags:** `Process`

**MITRE:** T1562.001 / T1070 (contextual) · **Status:** `Requires Validation`

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

```cql
#event_simpleName=ProcessRollup2 event_platform=Win
| CommandLine=/(set-mppreference|add-mppreference|disableantispyware|wevtutil\s+sl|sc\s+(stop|config).*\b(sense|windefend|csagent))/i
| select([@timestamp, ComputerName, UserName, ParentBaseFileName, FileName, CommandLine, aid])
| sort(@timestamp, order=desc, limit=1000)
```

**False positives:** Authorized security operations and troubleshooting.

**Analyst pivot:** Correlate command execution with sensor tamper/prevention events; no inference of successful bypass.

</details>

<a name="cs-ta0005-002"></a>

### 02. Sensor and Prevention Diagnostics

Inventories selected protective control state and diagnostic event types for review.

**Query ID:** `CS-TA0005-002` · **Platform:** `Not scoped` · **Tags:** `Security`

**MITRE:** T1562.001 (contextual) · **Status:** `Requires Validation`

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

```cql
#event_simpleName=/^(EAMBypassEvent|SensorAntiTamperState|DriverPreventionStatus|DetectionExcluded|SensorSelfDiagnosticTelemetry)$/
| select([@timestamp, #event_simpleName, ComputerName, aid])
| sort(@timestamp, order=desc, limit=1000)
```

**False positives:** Routine control state changes; event fields and licensing vary.

**Analyst pivot:** Use fieldset() for schema inspection before alerting on outcomes.

</details>

<a name="cs-ta0005-003"></a>

### 03. Security Log and Trace File Deletion

Examines deletion and USN records involving logs and script files.

**Query ID:** `CS-TA0005-003` · **Platform:** `Not scoped` · **Tags:** `File`

**MITRE:** T1070.004 · **Status:** `Requires Validation`

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

```cql
#event_simpleName=/^(FileDeleted|USNRecord)$/
| @rawstring=/(\.evtx|\.log|\.pf|\.ps1|\.tmp)/i
| select([@timestamp, #event_simpleName, ComputerName, UserName, @rawstring, aid])
| sort(@timestamp, order=asc, limit=10000)
```

**False positives:** Ordinary log rollover and cleanup; deletion alone does not prove an attack.

**Validation:** Confirm fieldsets and event semantics in the target tenant. [DO WERYFIKACJI W ŚRODOWISKU]

</details>

<a name="cs-ta0005-004"></a>

### 04. Firewall and WFP Modification Events

Surfaces firewall rule manipulation and Windows Filtering Platform activity.

**Query ID:** `CS-TA0005-004` · **Platform:** `Not scoped` · **Tags:** `Security`

**MITRE:** T1562.004 · **Status:** `Requires Validation`

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

```cql
#event_simpleName=/^(WfpFilterTamperingFilterAdded|FirewallDeleteRuleIP4|FirewallSetRuleIP4)$/
| select([@timestamp, #event_simpleName, ComputerName, UserName, @rawstring, aid])
| sort(@timestamp, order=asc, limit=10000)
```

**False positives:** Review approved administrative operations and expected security tooling.

**Validation:** Confirm fieldsets and event semantics in the target tenant. [DO WERYFIKACJI W ŚRODOWISKU]

</details>

<a name="cs-ta0005-005"></a>

### 05. Unsigned Modules and Suspicious File Signatures

Inspects file signature discrepancies and unsigned module events.

**Query ID:** `CS-TA0005-005` · **Platform:** `Not scoped` · **Tags:** `File`

**MITRE:** T1027 / T1036 · **Status:** `Requires Validation`

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

```cql
#event_simpleName=/^(FileSignatureMismatch|PackedExecutableWritten|UnsignedModuleLoad)$/
| select([@timestamp, #event_simpleName, ComputerName, UserName, @rawstring, aid])
| sort(@timestamp, order=asc, limit=10000)
```

**False positives:** Review approved administrative operations and expected security tooling.

**Validation:** Confirm fieldsets and event semantics in the target tenant. [DO WERYFIKACJI W ŚRODOWISKU]

</details>

<a name="cs-ta0005-006"></a>

### 06. Sensor Anti-Tamper and Bypass Telemetry

Reviews sensor bypass, exclusions and anti-tamper status event families.

**Query ID:** `CS-TA0005-006` · **Platform:** `Not scoped` · **Tags:** `Security`

**MITRE:** T1562.001 · **Status:** `Requires Validation`

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

```cql
#event_simpleName=/^(EAMBypassEvent|SensorAntiTamperState|DriverPreventionStatus|DetectionExcluded|SensorSelfDiagnosticTelemetry)$/
| select([@timestamp, #event_simpleName, ComputerName, UserName, @rawstring, aid])
| sort(@timestamp, order=asc, limit=10000)
```

**False positives:** Diagnostics, policy deployment and sensor upgrades.

**Validation:** Confirm fieldsets and event semantics in the target tenant. [DO WERYFIKACJI W ŚRODOWISKU]

</details>

<a name="cs-ta0005-007"></a>

### 07. Suspicious Macro and Invalid Script Events

Surfaces macros, malformed scripts and packed process detection events.

**Query ID:** `CS-TA0005-007` · **Platform:** `Not scoped` · **Tags:** `Process`

**MITRE:** T1027 · **Status:** `Requires Validation`

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

```cql
#event_simpleName=/^(MacroDetectInfo|MacroContentInfo|ScriptControlDetectInvalidInfo|ProcessExecOnPackedExecutable)$/
| select([@timestamp, #event_simpleName, ComputerName, UserName, @rawstring, aid])
| sort(@timestamp, order=asc, limit=10000)
```

**False positives:** Review approved administrative operations and expected security tooling.

**Validation:** Confirm fieldsets and event semantics in the target tenant. [DO WERYFIKACJI W ŚRODOWISKU]

</details>

<a name="cs-ta0005-008"></a>

### 08. Potential Log Clearing Commands

Searches for process commands that may clear Windows event logs or command history.

**Query ID:** `CS-TA0005-008` · **Platform:** `Not scoped` · **Tags:** `Process`

**MITRE:** T1070 · **Status:** `Requires Validation`

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

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

`Requires Validation` = not yet tenant-validated · `Tested` = exact-version tested · `Production reviewed` = peer-reviewed with evidence.

[← Home](../README.md) · [All queries](../QUERY-CATALOG.md)
