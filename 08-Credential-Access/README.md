[← Framework home](../README.md)

# Credential Access

**CrowdStrike Falcon / NG-SIEM**  ·  **CQL**  ·  `TA0006`  ·  **3 queries**

Hunt for credential theft, dumping attempts, and suspicious authentication behavior.

---

## Query library

| Hunt | Status |
|---|---|
| [01. Credential Dumping Command-Line Indicators](#01-credential-dumping-command-line-indicators) | `Candidate` |
| [02. Authentication Failure and Brute Force Event Families](#02-authentication-failure-and-brute-force-event-families) | `Candidate` |
| [03. Credential Access Detection Event Families](#03-credential-access-detection-event-families) | `Candidate` |

---

### 01. Credential Dumping Command-Line Indicators

Surfaces processes whose command-line arguments mention common credential dumping tools or LSASS-related operations.

**MITRE:** T1003\  ·  **Telemetry:** ProcessRollup2

<details>
<summary><strong>If you want to see more details</strong></summary>

```cql
#event_simpleName=ProcessRollup2 event_platform=Win
| CommandLine=/(procdump|lsass|comsvcs\.dll|\bminidump\b|reg\s+save\s+hklm\\(sam|system|security)|ntdsutil|secretsdump|mimikatz)/i
| select([@timestamp, aid, ComputerName, UserName, ParentBaseFileName, FileName, CommandLine])
| sort(@timestamp, order=desc, limit=1000)
```

**False positives:** Authorized troubleshooting, memory dumps and security assessments.

**Analyst pivot:** Cross-check protected process access telemetry and file creation evidence.

*Origin: OneNote-derived adaptation\*

</details>

### 02. Authentication Failure and Brute Force Event Families

Provides a starting point for validating auth failures and password spraying telemetry in Falcon.

**MITRE:** T1110 (contextual)\  ·  **Telemetry:** Brute force detection and SSO failure event families

<details>
<summary><strong>If you want to see more details</strong></summary>

```cql
#event_simpleName=/^(RemoteBruteForceDetectInfo|SmbClientShareLogonBruteForceLowThreshold|SmbClientShareLogonBruteForceSuspected|SsoUserLogonFailure)$/
| groupBy([#event_simpleName, ComputerName], function=[count(as=EventCount)], limit=1000)
| sort(EventCount, order=desc, limit=1000)
```

**False positives:** Password mistypes, misconfigured services, password rotations.

**Analyst pivot:** Review actual failure counts, source hosts, success follow-up and per-event fieldsets.

*Origin: OneNote-derived adaptation\*

</details>

### 03. Credential Access Detection Event Families

Retrieves dedicated credential access detection telemetry for further analyst filtering.

**MITRE:** T1003\  ·  **Telemetry:** Credential dumping-related detection events

<details>
<summary><strong>If you want to see more details</strong></summary>

```cql
#event_simpleName=/^(SAMHashDumpFromUnsignedModule|PrivilegedProcessHandleFromUnsignedModule|ReflectiveDllOpenProcess)$/
| select([@timestamp, #event_simpleName, ComputerName, UserName, aid])
| sort(@timestamp, order=desc, limit=1000)
```

**False positives:** IR tooling and endpoint scanning may trigger some events.

**Analyst pivot:** Inspect decision/action and target process fields with fieldset().

*Origin: OneNote-derived adaptation\*

</details>

---

`Migration recheck` = original supplied query was previously tested, but this publication copy needs validation. `Candidate` / `Community candidate` = not validated in the target Falcon environment.

[← Back to framework](../README.md)
