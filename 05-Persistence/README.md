[← Home](../README.md) · [All queries](../QUERY-CATALOG.md)

# Persistence

**CrowdStrike Falcon / NG-SIEM**  ·  **CQL**  ·  `TA0003`  ·  **6 queries**

Investigate accounts, scheduled tasks, autoruns, and registry-based persistence.

---

## Query library

| Hunt | ID | MITRE | Status |
|:--|:--|:--|:--|
| [01. Local Account Creation via Net](#cs-ta0003-001) | `CS-TA0003-001` | T1136 | `Requires Validation` |
| [02. Scheduled Task Registration and Autorun Telemetry](#cs-ta0003-002) | `CS-TA0003-002` | T1053.005 / T1547.001 | `Requires Validation` |
| [03. Run Keys and Startup Artifact Telemetry](#cs-ta0003-003) | `CS-TA0003-003` | T1547.001 | `Requires Validation` |
| [04. Account Creation and Modification Events](#cs-ta0003-004) | `CS-TA0003-004` | T1136 / T1098 | `Requires Validation` |
| [05. Windows Service Creation and Reconfiguration](#cs-ta0003-005) | `CS-TA0003-005` | T1543.003 | `Requires Validation` |
| [06. WMI Provider Registration and Autorun Artifacts](#cs-ta0003-006) | `CS-TA0003-006` | T1546.003 / T1547.001 | `Requires Validation` |

---

<a name="cs-ta0003-001"></a>

### 01. Local Account Creation via Net

Detects net.exe or net1.exe commands that create local or domain accounts using the /add switch.

**Query ID:** `CS-TA0003-001` · **Platform:** `Not scoped` · **Tags:** `Process`

**MITRE:** T1136 · **Status:** `Requires Validation`

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

```cql
#event_simpleName=ProcessRollup2
| ImageFileName=/\\net1?\.exe$/i
| CommandLine=/(?i)\bnet1?\s+user\b.*\/add\b/
| groupBy(CommandLine, limit=max)
```

**False positives:** Confirm account creation in authentication and account-management telemetry; command execution alone does not prove success.

**Analyst pivot:** Scope by host, user and narrow time window; pivot to process tree and nearby evidence before concluding malicious activity.

</details>

<a name="cs-ta0003-002"></a>

### 02. Scheduled Task Registration and Autorun Telemetry

Reviews task and autorun event families to identify persistence candidates.

**Query ID:** `CS-TA0003-002` · **Platform:** `Not scoped` · **Tags:** `Process`

**MITRE:** T1053.005 / T1547.001 · **Status:** `Requires Validation`

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

```cql
#event_simpleName=/^(ScheduledTaskInfo|AutoRunProcessInfo)$/
| select([@timestamp, #event_simpleName, ComputerName, UserName, aid])
| sort(@timestamp, order=desc, limit=1000)
```

**False positives:** Enterprise task schedulers, application updates. Field enrichment requires fieldset validation.

**Analyst pivot:** Inspect raw event fields before building a production filter.

</details>

<a name="cs-ta0003-003"></a>

### 03. Run Keys and Startup Artifact Telemetry

Retrieves registry/autorun event families that may capture persistence-related modifications.

**Query ID:** `CS-TA0003-003` · **Platform:** `Not scoped` · **Tags:** `File`

**MITRE:** T1547.001 · **Status:** `Requires Validation`

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

```cql
#event_simpleName=/^(RegGenericInfo|RegistryOperationDetectInfo|AsepFileChangeDetectInfo)$/
| select([@timestamp, #event_simpleName, ComputerName, UserName, aid])
| sort(@timestamp, order=desc, limit=1000)
```

**False positives:** Legitimate OS configuration changes and product installations.

**Analyst pivot:** Validate path, hive, value and writing process from environment-specific fieldsets.

</details>

<a name="cs-ta0003-004"></a>

### 04. Account Creation and Modification Events

Inspects local and Active Directory account updates.

**Query ID:** `CS-TA0003-004` · **Platform:** `Not scoped` · **Tags:** `Identity`

**MITRE:** T1136 / T1098 · **Status:** `Requires Validation`

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

```cql
#event_simpleName=/^(UserAccountCreated|ActiveDirectoryAccountCreated|LocalWindowsUserUpdate|ActiveDirectoryAuditUserModified)$/
| select([@timestamp, #event_simpleName, ComputerName, UserName, @rawstring, aid])
| sort(@timestamp, order=asc, limit=10000)
```

**False positives:** Identity lifecycle management and authorized account changes.

**Validation:** Confirm event and field availability and expected semantics in Falcon. [DO WERYFIKACJI W ŚRODOWISKU]

</details>

<a name="cs-ta0003-005"></a>

### 05. Windows Service Creation and Reconfiguration

Hunts for command patterns used to create or reconfigure Windows services.

**Query ID:** `CS-TA0003-005` · **Platform:** `Not scoped` · **Tags:** `Process`

**MITRE:** T1543.003 · **Status:** `Requires Validation`

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

```cql
#event_simpleName=ProcessRollup2
| CommandLine=/sc\.exe\s+(create|config)|new-service|\binstallutil\b/i
| select([@timestamp, ComputerName, UserName, ParentBaseFileName, ImageFileName, CommandLine, TargetProcessId, aid])
| sort(@timestamp, order=asc, limit=10000)
```

**False positives:** Normal service deployment and software maintenance.

**Validation:** Confirm event and field availability and expected semantics in Falcon. [DO WERYFIKACJI W ŚRODOWISKU]

</details>

<a name="cs-ta0003-006"></a>

### 06. WMI Provider Registration and Autorun Artifacts

Inspects WMI provider and autostart changes.

**Query ID:** `CS-TA0003-006` · **Platform:** `Not scoped` · **Tags:** `File`, `WMI`

**MITRE:** T1546.003 / T1547.001 · **Status:** `Requires Validation`

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

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

`Requires Validation` = not yet tenant-validated · `Tested` = exact-version tested · `Production reviewed` = peer-reviewed with evidence.

[← Home](../README.md) · [All queries](../QUERY-CATALOG.md)
