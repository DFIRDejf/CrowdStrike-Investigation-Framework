[← Framework home](../README.md)

# Persistence

**CrowdStrike Falcon / NG-SIEM**  ·  **CQL**  ·  `TA0003`  ·  **3 queries**

Investigate accounts, scheduled tasks, autoruns, and registry-based persistence.

---

## Query library

| Hunt | Status |
|---|---|
| [01. Local Account Creation via Net](#01-local-account-creation-via-net) | `Migration recheck` |
| [02. Scheduled Task Registration and Autorun Telemetry](#02-scheduled-task-registration-and-autorun-telemetry) | `Candidate` |
| [03. Run Keys and Startup Artifact Telemetry](#03-run-keys-and-startup-artifact-telemetry) | `Candidate` |

---

### 01. Local Account Creation via Net

Detects net.exe or net1.exe commands that create local or domain accounts using the /add switch.

**MITRE:** T1136\

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

**MITRE:** T1053.005 / T1547.001\  ·  **Telemetry:** ScheduledTaskInfo, AutoRunProcessInfo

<details>
<summary><strong>If you want to see more details</strong></summary>

```cql
#event_simpleName=/^(ScheduledTaskInfo|AutoRunProcessInfo)$/
| select([@timestamp, #event_simpleName, ComputerName, UserName, aid])
| sort(@timestamp, order=desc, limit=1000)
```

**False positives:** Enterprise task schedulers, application updates. Field enrichment requires fieldset validation.

**Analyst pivot:** Inspect raw event fields before building a production filter.

*Origin: OneNote-derived adaptation\*

</details>

### 03. Run Keys and Startup Artifact Telemetry

Retrieves registry/autorun event families that may capture persistence-related modifications.

**MITRE:** T1547.001\  ·  **Telemetry:** RegGenericInfo, RegistryOperationDetectInfo, AsepFileChangeDetectInfo

<details>
<summary><strong>If you want to see more details</strong></summary>

```cql
#event_simpleName=/^(RegGenericInfo|RegistryOperationDetectInfo|AsepFileChangeDetectInfo)$/
| select([@timestamp, #event_simpleName, ComputerName, UserName, aid])
| sort(@timestamp, order=desc, limit=1000)
```

**False positives:** Legitimate OS configuration changes and product installations.

**Analyst pivot:** Validate path, hive, value and writing process from environment-specific fieldsets.

*Origin: OneNote-derived adaptation\*

</details>

---

`Migration recheck` = original supplied query was previously tested, but this publication copy needs validation. `Candidate` / `Community candidate` = not validated in the target Falcon environment.

[← Back to framework](../README.md)
