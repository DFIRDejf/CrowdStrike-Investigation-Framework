[← Home](../README.md) · [All queries](../QUERY-CATALOG.md)

# Persistence

**CrowdStrike Falcon / NG-SIEM**  ·  **CQL**  ·  `TA0003`  ·  **6 queries**

Investigate accounts, scheduled tasks, autoruns, and registry-based persistence.

---

## Query library

| Hunt | MITRE | Status |
|:--|:--|:--|
| [01. Local Account Creation via Net](#01-local-account-creation-via-net) | T1136 | `Migration recheck` |
| [02. Scheduled Task Registration and Autorun Telemetry](#02-scheduled-task-registration-and-autorun-telemetry) | T1053.005 / T1547.001 | `Candidate` |
| [03. Run Keys and Startup Artifact Telemetry](#03-run-keys-and-startup-artifact-telemetry) | T1547.001 | `Candidate` |
| [04. Account Creation and Modification Events](#04-account-creation-and-modification-events) | T1136 / T1098 | `Requires Validation` |
| [05. Windows Service Creation and Reconfiguration](#05-windows-service-creation-and-reconfiguration) | T1543.003 | `Requires Validation` |
| [06. WMI Provider Registration and Autorun Artifacts](#06-wmi-provider-registration-and-autorun-artifacts) | T1546.003 / T1547.001 | `Requires Validation` |

---

### 01. Local Account Creation via Net

Detects net.exe or net1.exe commands that create local or domain accounts using the /add switch.

**MITRE:** T1136

<details>
<summary><strong>If you want to see more details</strong></summary>

```cql
#event_simpleName=ProcessRollup2
| ImageFileName=/\\net1?\.exe$/i
| CommandLine=/(?i)\bnet1?\s+user\b.*\/add\b/
| groupBy(CommandLine, limit=max)
```

**False positives:** Confirm account creation in authentication and account-management telemetry; command execution alone does not prove success.

**Analyst pivot:** Scope by host, user and narrow time window; pivot to process tree and nearby evidence before concluding malicious activity.

</details>

### 02. Scheduled Task Registration and Autorun Telemetry

Reviews task and autorun event families to identify persistence candidates.

**MITRE:** T1053.005 / T1547.001  ·  **Telemetry:** ScheduledTaskInfo, AutoRunProcessInfo

<details>
<summary><strong>If you want to see more details</strong></summary>

```cql
#event_simpleName=/^(ScheduledTaskInfo|AutoRunProcessInfo)$/
| select([@timestamp, #event_simpleName, ComputerName, UserName, aid])
| sort(@timestamp, order=desc, limit=1000)
```

**False positives:** Enterprise task schedulers, application updates. Field enrichment requires fieldset validation.

**Analyst pivot:** Inspect raw event fields before building a production filter.

*Origin: OneNote-derived adaptation*

</details>

### 03. Run Keys and Startup Artifact Telemetry

Retrieves registry/autorun event families that may capture persistence-related modifications.

**MITRE:** T1547.001  ·  **Telemetry:** RegGenericInfo, RegistryOperationDetectInfo, AsepFileChangeDetectInfo

<details>
<summary><strong>If you want to see more details</strong></summary>

```cql
#event_simpleName=/^(RegGenericInfo|RegistryOperationDetectInfo|AsepFileChangeDetectInfo)$/
| select([@timestamp, #event_simpleName, ComputerName, UserName, aid])
| sort(@timestamp, order=desc, limit=1000)
```

**False positives:** Legitimate OS configuration changes and product installations.

**Analyst pivot:** Validate path, hive, value and writing process from environment-specific fieldsets.

*Origin: OneNote-derived adaptation*

</details>

### 04. Account Creation and Modification Events

Inspects local and Active Directory account updates.

**MITRE:** T1136 / T1098  ·  **Source:** `CS Queries.one`  ·  **Status:** `Requires Validation`

<details>
<summary><strong>If you want to see more details</strong></summary>

```cql
#event_simpleName=/^(UserAccountCreated|ActiveDirectoryAccountCreated|LocalWindowsUserUpdate|ActiveDirectoryAuditUserModified)$/
| select([@timestamp, #event_simpleName, ComputerName, UserName, @rawstring, aid])
| sort(@timestamp, order=asc, limit=10000)
```

**False positives:** Identity lifecycle management and authorized account changes.

**Validation:** Confirm event and field availability and expected semantics in Falcon. [DO WERYFIKACJI W ŚRODOWISKU]

</details>

### 05. Windows Service Creation and Reconfiguration

Hunts for command patterns used to create or reconfigure Windows services.

**MITRE:** T1543.003  ·  **Source:** `CS Queries.one`  ·  **Status:** `Requires Validation`

<details>
<summary><strong>If you want to see more details</strong></summary>

```cql
#event_simpleName=ProcessRollup2
| CommandLine=/sc\.exe\s+(create|config)|new-service|\binstallutil\b/i
| select([@timestamp, ComputerName, UserName, ParentBaseFileName, ImageFileName, CommandLine, TargetProcessId, aid])
| sort(@timestamp, order=asc, limit=10000)
```

**False positives:** Normal service deployment and software maintenance.

**Validation:** Confirm event and field availability and expected semantics in Falcon. [DO WERYFIKACJI W ŚRODOWISKU]

</details>

### 06. WMI Provider Registration and Autorun Artifacts

Inspects WMI provider and autostart changes.

**MITRE:** T1546.003 / T1547.001  ·  **Source:** `CS Queries.one`  ·  **Status:** `Requires Validation`

<details>
<summary><strong>If you want to see more details</strong></summary>

```cql
#event_simpleName=/^(WmiProviderRegistrationEtw|AsepFileChangeDetectInfo)$/
| @rawstring=/(Consumer|Subscription|RunOnce|\\Run\b)/i
| select([@timestamp, #event_simpleName, ComputerName, UserName, @rawstring, aid])
| sort(@timestamp, order=asc, limit=10000)
```

**False positives:** Expected system management and autorun changes.

**Validation:** Confirm event and field availability and expected semantics in Falcon. [DO WERYFIKACJI W ŚRODOWISKU]

</details>


---

`Migration recheck` = original supplied query was previously tested, but this publication copy needs validation. `Candidate` / `Community candidate` = not validated in the target Falcon environment.

[← Home](../README.md) · [All queries](../QUERY-CATALOG.md)
