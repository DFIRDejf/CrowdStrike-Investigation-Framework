[← Home](../README.md) · [All queries](../QUERY-CATALOG.md)

# Credential Access

**CrowdStrike Falcon / NG-SIEM**  ·  **CQL**  ·  `TA0006`  ·  **9 queries**

Hunt for credential theft, dumping attempts, and suspicious authentication behavior.

---

## Query library

| Hunt | ID | MITRE | Status |
|:--|:--|:--|:--|
| [01. Credential Dumping Command-Line Indicators](#cs-ta0006-001) | `CS-TA0006-001` | T1003 | `Requires Validation` |
| [02. Authentication Failure and Brute Force Event Families](#cs-ta0006-002) | `CS-TA0006-002` | T1110 (contextual) | `Requires Validation` |
| [03. Credential Access Detection Event Families](#cs-ta0006-003) | `CS-TA0006-003` | T1003 | `Requires Validation` |
| [04. LSASS, SAM and NTDS Dumping Commands](#cs-ta0006-004) | `CS-TA0006-004` | T1003.001 / T1003.002 | `Requires Validation` |
| [05. SAM Dump and Privileged Handle Detection Events](#cs-ta0006-005) | `CS-TA0006-005` | T1003.002 | `Requires Validation` |
| [06. Kerberoasting and AS-REP Tooling Footprints](#cs-ta0006-006) | `CS-TA0006-006` | T1558.003 / T1558.004 | `Requires Validation` |
| [07. DCSync and Directory Replication Indicators](#cs-ta0006-007) | `CS-TA0006-007` | T1003.006 | `Requires Validation` |
| [08. KRBTGT-Related Directory Events](#cs-ta0006-008) | `CS-TA0006-008` | T1558 (context) | `Requires Validation` |
| [09. Credential Stores and Sensitive Files](#cs-ta0006-009) | `CS-TA0006-009` | T1552 / T1555 | `Requires Validation` |

---

<a name="cs-ta0006-001"></a>

### 01. Credential Dumping Command-Line Indicators

Surfaces processes whose command-line arguments mention common credential dumping tools or LSASS-related operations.

**Query ID:** `CS-TA0006-001` · **Platform:** `Windows` · **Tags:** `Process`

**MITRE:** T1003 · **Status:** `Requires Validation`

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

```cql
#event_simpleName=ProcessRollup2 event_platform=Win
| CommandLine=/(procdump|lsass|comsvcs\.dll|\bminidump\b|reg\s+save\s+hklm\\(sam|system|security)|ntdsutil|secretsdump|mimikatz)/i
| select([@timestamp, aid, ComputerName, UserName, ParentBaseFileName, FileName, CommandLine])
| sort(@timestamp, order=desc, limit=1000)
```

</details>

---

<a name="cs-ta0006-002"></a>

### 02. Authentication Failure and Brute Force Event Families

Provides a starting point for validating auth failures and password spraying telemetry in Falcon.

**Query ID:** `CS-TA0006-002` · **Platform:** `Not scoped` · **Tags:** `Identity`, `SMB`

**MITRE:** T1110 (contextual) · **Status:** `Requires Validation`

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

```cql
#event_simpleName=/^(RemoteBruteForceDetectInfo|SmbClientShareLogonBruteForceLowThreshold|SmbClientShareLogonBruteForceSuspected|SsoUserLogonFailure)$/
| groupBy([#event_simpleName, ComputerName], function=[count(as=EventCount)], limit=1000)
| sort(EventCount, order=desc, limit=1000)
```

</details>

---

<a name="cs-ta0006-003"></a>

### 03. Credential Access Detection Event Families

Retrieves dedicated credential access detection telemetry for further analyst filtering.

**Query ID:** `CS-TA0006-003` · **Platform:** `Not scoped` · **Tags:** `Network`, `Process`

**MITRE:** T1003 · **Status:** `Requires Validation`

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

```cql
#event_simpleName=/^(SAMHashDumpFromUnsignedModule|PrivilegedProcessHandleFromUnsignedModule|ReflectiveDllOpenProcess)$/
| select([@timestamp, #event_simpleName, ComputerName, UserName, aid])
| sort(@timestamp, order=desc, limit=1000)
```

</details>

---

<a name="cs-ta0006-004"></a>

### 04. LSASS, SAM and NTDS Dumping Commands

Identifies process command lines referencing credential dumping and hive extraction.

**Query ID:** `CS-TA0006-004` · **Platform:** `Not scoped` · **Tags:** `Process`

**MITRE:** T1003.001 / T1003.002 · **Status:** `Requires Validation`

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

```cql
#event_simpleName=ProcessRollup2
| CommandLine=/procdump|lsass|comsvcs\.dll|\bminidump\b|reg\s+save\s+hklm\\(sam|system|security)|ntdsutil|secretsdump|mimikatz/i
| select([@timestamp, ComputerName, UserName, ParentBaseFileName, ImageFileName, CommandLine, TargetProcessId, aid])
| sort(@timestamp, order=asc, limit=10000)
```

</details>

---

<a name="cs-ta0006-005"></a>

### 05. SAM Dump and Privileged Handle Detection Events

Collects endpoint events associated with sensitive process access and SAM dump indicators.

**Query ID:** `CS-TA0006-005` · **Platform:** `Not scoped` · **Tags:** `Network`, `Process`

**MITRE:** T1003.002 · **Status:** `Requires Validation`

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

```cql
#event_simpleName=/^(SAMHashDumpFromUnsignedModule|PrivilegedProcessHandleFromUnsignedModule|ReflectiveDllOpenProcess)$/
| select([@timestamp, #event_simpleName, ComputerName, UserName, @rawstring, aid])
| sort(@timestamp, order=asc, limit=10000)
```

</details>

---

<a name="cs-ta0006-006"></a>

### 06. Kerberoasting and AS-REP Tooling Footprints

Reviews command and script telemetry for Kerberos credential attack utilities.

**Query ID:** `CS-TA0006-006` · **Platform:** `Not scoped` · **Tags:** `Process`

**MITRE:** T1558.003 / T1558.004 · **Status:** `Requires Validation`

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

```cql
#event_simpleName=/^(CommandHistory|NewScriptWritten|ScriptControlDetectInfo)$/
| @rawstring=/(kerberoast|asreproast|rubeus|GetUserSPNs|GetNPUsers|Invoke-Kerberoast)/i
| select([@timestamp, #event_simpleName, ComputerName, UserName, @rawstring, aid])
| sort(@timestamp, order=asc, limit=10000)
```

</details>

---

<a name="cs-ta0006-007"></a>

### 07. DCSync and Directory Replication Indicators

Surfaces process history and AD RPC records with potential replication abuse indicators.

**Query ID:** `CS-TA0006-007` · **Platform:** `Not scoped` · **Tags:** `Identity`, `Process`

**MITRE:** T1003.006 · **Status:** `Requires Validation`

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

```cql
#event_simpleName=/^(CommandHistory|NewScriptWritten|ActiveDirectoryIncomingDceRpcRequest)$/
| @rawstring=/(lsadump::dcsync|\bdcsync\b|drsuapi|DsGetNCChanges|replication-get-changes)/i
| select([@timestamp, #event_simpleName, ComputerName, UserName, @rawstring, aid])
| sort(@timestamp, order=asc, limit=10000)
```

</details>

---

<a name="cs-ta0006-008"></a>

### 08. KRBTGT-Related Directory Events

Investigates directory changes and RPC events referencing KRBTGT.

**Query ID:** `CS-TA0006-008` · **Platform:** `Not scoped` · **Tags:** `Identity`

**MITRE:** T1558 (context) · **Status:** `Requires Validation`

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

```cql
#event_simpleName=/^(ActiveDirectoryAuditPasswordModificationAttempt|ActiveDirectoryAuditUserModified|ActiveDirectoryAccountPasswordUpdate|ActiveDirectoryIncomingDceRpcRequest|IdpTelemetryData)$/
| @rawstring=/krbtgt/i
| select([@timestamp, #event_simpleName, ComputerName, UserName, @rawstring, aid])
| sort(@timestamp, order=asc, limit=10000)
```

</details>

---

<a name="cs-ta0006-009"></a>

### 09. Credential Stores and Sensitive Files

Examines file and browser credential artifact accesses.

**Query ID:** `CS-TA0006-009` · **Platform:** `Not scoped` · **Tags:** `Browser`, `File`

**MITRE:** T1552 / T1555 · **Status:** `Requires Validation`

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

```cql
#event_simpleName=/^(BrowserCookieInfo|ClassifiedSensitiveFileAccess|CriticalFileAccessed)$/
| @rawstring=/(login\sdata|cookies|credentials|password|secret|vault)/i
| select([@timestamp, #event_simpleName, ComputerName, UserName, @rawstring, aid])
| sort(@timestamp, order=asc, limit=10000)
```

</details>

---

`Requires Validation` = not yet tenant-validated · `Tested` = exact-version tested · `Production reviewed` = peer-reviewed with evidence.

[← Home](../README.md) · [All queries](../QUERY-CATALOG.md)
