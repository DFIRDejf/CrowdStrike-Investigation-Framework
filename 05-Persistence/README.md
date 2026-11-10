# Persistence — CrowdStrike CQL

> **3 CQL entries** | CrowdStrike Falcon / NG-SIEM | MITRE: TA0003

Investigate account creation, autoruns, scheduled tasks and other access-retention mechanisms.

> **Validation notice:** Entries marked *User-reported validated source* were provided as working queries, but publication copies were sanitized and must be re-tested. Entries marked *Candidate* and *Community-derived* have **not** been tested in this environment.

## Query Index

1. [Local Account Creation via Net](#01-local-account-creation-via-net)
2. [Scheduled Task Registration and Autorun Telemetry](#02-scheduled-task-registration-and-autorun-telemetry)
3. [Run Keys and Startup Artifact Telemetry](#03-run-keys-and-startup-artifact-telemetry)

---

## 01. Local Account Creation via Net

**Description:** Detects net.exe or net1.exe commands that create local or domain accounts using the /add switch.

**MITRE ATT&CK:** T1136\
**Origin:** Previously supplied CQL — sanitized migration copy\
**Validation:** User-reported validated source; revalidate sanitized copy\
**Required telemetry:** See event filters in query

<details>
<summary><strong>If you want to see more details</strong></summary>

### Hunting Query (CQL)

```cql
#event_simpleName=ProcessRollup2
| ImageFileName=/\\net1?\.exe$/i
| CommandLine=/(?i)\bnet1?\s+user\b.*\/add\b/
| groupBy(CommandLine, limit=max)
```

### False Positive Considerations

Confirm account creation in authentication and account-management telemetry; command execution alone does not prove success.

### Investigation Guidance

Scope by host, user and narrow time window; pivot to process tree and nearby evidence before concluding malicious activity.

</details>

---

## 02. Scheduled Task Registration and Autorun Telemetry

**Description:** Reviews task and autorun event families to identify persistence candidates.

**MITRE ATT&CK:** T1053.005 / T1547.001\
**Origin:** OneNote-derived adaptation\
**Validation:** Candidate — requires validation in Falcon\
**Required telemetry:** ScheduledTaskInfo, AutoRunProcessInfo

<details>
<summary><strong>If you want to see more details</strong></summary>

### Hunting Query (CQL)

```cql
#event_simpleName=/^(ScheduledTaskInfo|AutoRunProcessInfo)$/
| select([@timestamp, #event_simpleName, ComputerName, UserName, aid])
| sort(@timestamp, order=desc, limit=1000)
```

### False Positive Considerations

Enterprise task schedulers, application updates. Field enrichment requires fieldset validation.

### Investigation Guidance

Inspect raw event fields before building a production filter.

</details>

---

## 03. Run Keys and Startup Artifact Telemetry

**Description:** Retrieves registry/autorun event families that may capture persistence-related modifications.

**MITRE ATT&CK:** T1547.001\
**Origin:** OneNote-derived adaptation\
**Validation:** Candidate — requires validation in Falcon\
**Required telemetry:** RegGenericInfo, RegistryOperationDetectInfo, AsepFileChangeDetectInfo

<details>
<summary><strong>If you want to see more details</strong></summary>

### Hunting Query (CQL)

```cql
#event_simpleName=/^(RegGenericInfo|RegistryOperationDetectInfo|AsepFileChangeDetectInfo)$/
| select([@timestamp, #event_simpleName, ComputerName, UserName, aid])
| sort(@timestamp, order=desc, limit=1000)
```

### False Positive Considerations

Legitimate OS configuration changes and product installations.

### Investigation Guidance

Validate path, hive, value and writing process from environment-specific fieldsets.

</details>

---
