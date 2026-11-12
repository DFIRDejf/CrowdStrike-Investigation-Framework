[← Home](../README.md) · [All queries](../QUERY-CATALOG.md)

# Credential Access

**CrowdStrike Falcon / NG-SIEM**  ·  **CQL**  ·  `TA0006`  ·  **9 queries**

Hunt for credential theft, dumping attempts, and suspicious authentication behavior.

---

## Query library

| Hunt | MITRE | Status |
|:--|:--|:--|
| [01. Credential Dumping Command-Line Indicators](#01-credential-dumping-command-line-indicators) | T1003 | `Candidate` |
| [02. Authentication Failure and Brute Force Event Families](#02-authentication-failure-and-brute-force-event-families) | T1110 (contextual) | `Candidate` |
| [03. Credential Access Detection Event Families](#03-credential-access-detection-event-families) | T1003 | `Candidate` |
| [04. LSASS, SAM and NTDS Dumping Commands](#04-lsass-sam-and-ntds-dumping-commands) | T1003.001 / T1003.002 | `Requires Validation` |
| [05. SAM Dump and Privileged Handle Detection Events](#05-sam-dump-and-privileged-handle-detection-events) | T1003.002 | `Requires Validation` |
| [06. Kerberoasting and AS-REP Tooling Footprints](#06-kerberoasting-and-as-rep-tooling-footprints) | T1558.003 / T1558.004 | `Requires Validation` |
| [07. DCSync and Directory Replication Indicators](#07-dcsync-and-directory-replication-indicators) | T1003.006 | `Requires Validation` |
| [08. KRBTGT-Related Directory Events](#08-krbtgt-related-directory-events) | T1558 (context) | `Requires Validation` |
| [09. Credential Stores and Sensitive Files](#09-credential-stores-and-sensitive-files) | T1552 / T1555 | `Requires Validation` |

---

### 01. Credential Dumping Command-Line Indicators

Surfaces processes whose command-line arguments mention common credential dumping tools or LSASS-related operations.

**MITRE:** T1003  ·  **Telemetry:** ProcessRollup2

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

*Origin: OneNote-derived adaptation*

</details>

### 02. Authentication Failure and Brute Force Event Families

Provides a starting point for validating auth failures and password spraying telemetry in Falcon.

**MITRE:** T1110 (contextual)  ·  **Telemetry:** Brute force detection and SSO failure event families

<details>
<summary><strong>If you want to see more details</strong></summary>

```cql
#event_simpleName=/^(RemoteBruteForceDetectInfo|SmbClientShareLogonBruteForceLowThreshold|SmbClientShareLogonBruteForceSuspected|SsoUserLogonFailure)$/
| groupBy([#event_simpleName, ComputerName], function=[count(as=EventCount)], limit=1000)
| sort(EventCount, order=desc, limit=1000)
```

**False positives:** Password mistypes, misconfigured services, password rotations.

**Analyst pivot:** Review actual failure counts, source hosts, success follow-up and per-event fieldsets.

*Origin: OneNote-derived adaptation*

</details>

### 03. Credential Access Detection Event Families

Retrieves dedicated credential access detection telemetry for further analyst filtering.

**MITRE:** T1003  ·  **Telemetry:** Credential dumping-related detection events

<details>
<summary><strong>If you want to see more details</strong></summary>

```cql
#event_simpleName=/^(SAMHashDumpFromUnsignedModule|PrivilegedProcessHandleFromUnsignedModule|ReflectiveDllOpenProcess)$/
| select([@timestamp, #event_simpleName, ComputerName, UserName, aid])
| sort(@timestamp, order=desc, limit=1000)
```

**False positives:** IR tooling and endpoint scanning may trigger some events.

**Analyst pivot:** Inspect decision/action and target process fields with fieldset().

*Origin: OneNote-derived adaptation*

</details>

### 04. LSASS, SAM and NTDS Dumping Commands

Identifies process command lines referencing credential dumping and hive extraction.

**MITRE:** T1003.001 / T1003.002  ·  **Source:** `CS Queries.one`  ·  **Status:** `Requires Validation`

<details>
<summary><strong>If you want to see more details</strong></summary>

```cql
#event_simpleName=ProcessRollup2
| CommandLine=/procdump|lsass|comsvcs\.dll|\bminidump\b|reg\s+save\s+hklm\\(sam|system|security)|ntdsutil|secretsdump|mimikatz/i
| select([@timestamp, ComputerName, UserName, ParentBaseFileName, ImageFileName, CommandLine, TargetProcessId, aid])
| sort(@timestamp, order=asc, limit=10000)
```

**False positives:** Review approved administrative operations and expected security tooling.

**Validation:** Confirm fieldsets and event semantics in the target tenant. [DO WERYFIKACJI W ŚRODOWISKU]

</details>

### 05. SAM Dump and Privileged Handle Detection Events

Collects endpoint events associated with sensitive process access and SAM dump indicators.

**MITRE:** T1003.002  ·  **Source:** `CS Queries.one`  ·  **Status:** `Requires Validation`

<details>
<summary><strong>If you want to see more details</strong></summary>

```cql
#event_simpleName=/^(SAMHashDumpFromUnsignedModule|PrivilegedProcessHandleFromUnsignedModule|ReflectiveDllOpenProcess)$/
| select([@timestamp, #event_simpleName, ComputerName, UserName, @rawstring, aid])
| sort(@timestamp, order=asc, limit=10000)
```

**False positives:** Review approved administrative operations and expected security tooling.

**Validation:** Confirm fieldsets and event semantics in the target tenant. [DO WERYFIKACJI W ŚRODOWISKU]

</details>

### 06. Kerberoasting and AS-REP Tooling Footprints

Reviews command and script telemetry for Kerberos credential attack utilities.

**MITRE:** T1558.003 / T1558.004  ·  **Source:** `CS Queries.one`  ·  **Status:** `Requires Validation`

<details>
<summary><strong>If you want to see more details</strong></summary>

```cql
#event_simpleName=/^(CommandHistory|NewScriptWritten|ScriptControlDetectInfo)$/
| @rawstring=/(kerberoast|asreproast|rubeus|GetUserSPNs|GetNPUsers|Invoke-Kerberoast)/i
| select([@timestamp, #event_simpleName, ComputerName, UserName, @rawstring, aid])
| sort(@timestamp, order=asc, limit=10000)
```

**False positives:** Authorized identity auditing; tool strings do not establish actual ticket exploitation.

**Validation:** Confirm fieldsets and event semantics in the target tenant. [DO WERYFIKACJI W ŚRODOWISKU]

</details>

### 07. DCSync and Directory Replication Indicators

Surfaces process history and AD RPC records with potential replication abuse indicators.

**MITRE:** T1003.006  ·  **Source:** `CS Queries.one`  ·  **Status:** `Requires Validation`

<details>
<summary><strong>If you want to see more details</strong></summary>

```cql
#event_simpleName=/^(CommandHistory|NewScriptWritten|ActiveDirectoryIncomingDceRpcRequest)$/
| @rawstring=/(lsadump::dcsync|\bdcsync\b|drsuapi|DsGetNCChanges|replication-get-changes)/i
| select([@timestamp, #event_simpleName, ComputerName, UserName, @rawstring, aid])
| sort(@timestamp, order=asc, limit=10000)
```

**False positives:** Legitimate domain replication; confirm RPC interfaces, source identities and permissions.

**Validation:** Confirm fieldsets and event semantics in the target tenant. [DO WERYFIKACJI W ŚRODOWISKU]

</details>

### 08. KRBTGT-Related Directory Events

Investigates directory changes and RPC events referencing KRBTGT.

**MITRE:** T1558 (context)  ·  **Source:** `CS Queries.one`  ·  **Status:** `Requires Validation`

<details>
<summary><strong>If you want to see more details</strong></summary>

```cql
#event_simpleName=/^(ActiveDirectoryAuditPasswordModificationAttempt|ActiveDirectoryAuditUserModified|ActiveDirectoryAccountPasswordUpdate|ActiveDirectoryIncomingDceRpcRequest|IdpTelemetryData)$/
| @rawstring=/krbtgt/i
| select([@timestamp, #event_simpleName, ComputerName, UserName, @rawstring, aid])
| sort(@timestamp, order=asc, limit=10000)
```

**False positives:** Planned password rotations; KRBTGT references are not proof of a Golden Ticket.

**Validation:** Confirm fieldsets and event semantics in the target tenant. [DO WERYFIKACJI W ŚRODOWISKU]

</details>

### 09. Credential Stores and Sensitive Files

Examines file and browser credential artifact accesses.

**MITRE:** T1552 / T1555  ·  **Source:** `CS Queries.one`  ·  **Status:** `Requires Validation`

<details>
<summary><strong>If you want to see more details</strong></summary>

```cql
#event_simpleName=/^(BrowserCookieInfo|ClassifiedSensitiveFileAccess|CriticalFileAccessed)$/
| @rawstring=/(login\sdata|cookies|credentials|password|secret|vault)/i
| select([@timestamp, #event_simpleName, ComputerName, UserName, @rawstring, aid])
| sort(@timestamp, order=asc, limit=10000)
```

**False positives:** Legitimate browser and security software activity.

**Validation:** Confirm fieldsets and event semantics in the target tenant. [DO WERYFIKACJI W ŚRODOWISKU]

</details>


---

`Migration recheck` = original supplied query was previously tested, but this publication copy needs validation. `Candidate` / `Community candidate` = not validated in the target Falcon environment.

[← Home](../README.md) · [All queries](../QUERY-CATALOG.md)
