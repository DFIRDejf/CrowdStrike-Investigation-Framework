# Credential Access — CrowdStrike CQL

> **3 CQL entries** | CrowdStrike Falcon / NG-SIEM | MITRE: TA0006

Investigate suspected credential access, dumping, and authentication abuse.

> **Validation notice:** Entries marked *User-reported validated source* were provided as working queries, but publication copies were sanitized and must be re-tested. Entries marked *Candidate* and *Community-derived* have **not** been tested in this environment.

## Query Index

1. [Credential Dumping Command-Line Indicators](#01-credential-dumping-command-line-indicators)
2. [Authentication Failure and Brute Force Event Families](#02-authentication-failure-and-brute-force-event-families)
3. [Credential Access Detection Event Families](#03-credential-access-detection-event-families)

---

## 01. Credential Dumping Command-Line Indicators

**Description:** Surfaces processes whose command-line arguments mention common credential dumping tools or LSASS-related operations.

**MITRE ATT&CK:** T1003\
**Origin:** OneNote-derived adaptation\
**Validation:** Candidate — requires validation in Falcon\
**Required telemetry:** ProcessRollup2

<details>
<summary><strong>If you want to see more details</strong></summary>

### Hunting Query (CQL)

```cql
#event_simpleName=ProcessRollup2 event_platform=Win
| CommandLine=/(procdump|lsass|comsvcs\.dll|\bminidump\b|reg\s+save\s+hklm\\(sam|system|security)|ntdsutil|secretsdump|mimikatz)/i
| select([@timestamp, aid, ComputerName, UserName, ParentBaseFileName, FileName, CommandLine])
| sort(@timestamp, order=desc, limit=1000)
```

### False Positive Considerations

Authorized troubleshooting, memory dumps and security assessments.

### Investigation Guidance

Cross-check protected process access telemetry and file creation evidence.

</details>

---

## 02. Authentication Failure and Brute Force Event Families

**Description:** Provides a starting point for validating auth failures and password spraying telemetry in Falcon.

**MITRE ATT&CK:** T1110 (contextual)\
**Origin:** OneNote-derived adaptation\
**Validation:** Candidate — requires validation in Falcon\
**Required telemetry:** Brute force detection and SSO failure event families

<details>
<summary><strong>If you want to see more details</strong></summary>

### Hunting Query (CQL)

```cql
#event_simpleName=/^(RemoteBruteForceDetectInfo|SmbClientShareLogonBruteForceLowThreshold|SmbClientShareLogonBruteForceSuspected|SsoUserLogonFailure)$/
| groupBy([#event_simpleName, ComputerName], function=[count(as=EventCount)], limit=1000)
| sort(EventCount, order=desc, limit=1000)
```

### False Positive Considerations

Password mistypes, misconfigured services, password rotations.

### Investigation Guidance

Review actual failure counts, source hosts, success follow-up and per-event fieldsets.

</details>

---

## 03. Credential Access Detection Event Families

**Description:** Retrieves dedicated credential access detection telemetry for further analyst filtering.

**MITRE ATT&CK:** T1003\
**Origin:** OneNote-derived adaptation\
**Validation:** Candidate — requires validation in Falcon\
**Required telemetry:** Credential dumping-related detection events

<details>
<summary><strong>If you want to see more details</strong></summary>

### Hunting Query (CQL)

```cql
#event_simpleName=/^(SAMHashDumpFromUnsignedModule|PrivilegedProcessHandleFromUnsignedModule|ReflectiveDllOpenProcess)$/
| select([@timestamp, #event_simpleName, ComputerName, UserName, aid])
| sort(@timestamp, order=desc, limit=1000)
```

### False Positive Considerations

IR tooling and endpoint scanning may trigger some events.

### Investigation Guidance

Inspect decision/action and target process fields with fieldset().

</details>

---
