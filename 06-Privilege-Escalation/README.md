[← Home](../README.md) · [All queries](../QUERY-CATALOG.md)

# Privilege Escalation

**CrowdStrike Falcon / NG-SIEM**  ·  **CQL**  ·  `TA0004`  ·  **4 queries**

Review privilege changes and indicators of unauthorized elevation.

---

## Query library

| Hunt | ID | MITRE | Status |
|:--|:--|:--|:--|
| [01. Account Added to Privileged Group Event Family](#cs-ta0004-001) | `CS-TA0004-001` | T1098 | `Requires Validation` |
| [02. Windows Token Privilege Modification Events](#cs-ta0004-002) | `CS-TA0004-002` | T1134 | `Requires Validation` |
| [03. Elevation and Token Abuse Command Indicators](#cs-ta0004-003) | `CS-TA0004-003` | T1548 / T1134 | `Requires Validation` |
| [04. Local Group and Directory Account Changes](#cs-ta0004-004) | `CS-TA0004-004` | T1098 | `Requires Validation` |

---

<a name="cs-ta0004-001"></a>

### 01. Account Added to Privileged Group Event Family

Exposes group membership change telemetry for investigation and follow-up filtering.

**Query ID:** `CS-TA0004-001` · **Platform:** `Not scoped` · **Tags:** `Identity`

**MITRE:** T1098 · **Status:** `Requires Validation`

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

```cql
#event_simpleName=/^(UserAccountAddedToGroup|ActiveDirectoryAccountDirectContainingGroupEntitiesUpdate|ActiveDirectoryAccountFlattenedContainingGroupEntitiesUpdate)$/
| select([@timestamp, #event_simpleName, ComputerName, UserName, aid])
| sort(@timestamp, order=desc, limit=1000)
```

</details>

---

<a name="cs-ta0004-002"></a>

### 02. Windows Token Privilege Modification Events

Lists telemetry associated with token privilege changes and privileged process handles.

**Query ID:** `CS-TA0004-002` · **Platform:** `Not scoped` · **Tags:** `Network`, `Process`

**MITRE:** T1134 · **Status:** `Requires Validation`

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

```cql
#event_simpleName=/^(ProcessTokenPrivilegesEdited|PrivilegedProcessHandleFromUnsignedModule)$/
| select([@timestamp, #event_simpleName, ComputerName, UserName, @rawstring, aid])
| sort(@timestamp, order=asc, limit=10000)
```

</details>

---

<a name="cs-ta0004-003"></a>

### 03. Elevation and Token Abuse Command Indicators

Finds command-line patterns for elevation, impersonation and token abuse.

**Query ID:** `CS-TA0004-003` · **Platform:** `Not scoped` · **Tags:** `Process`

**MITRE:** T1548 / T1134 · **Status:** `Requires Validation`

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

```cql
#event_simpleName=ProcessRollup2
| CommandLine=/runas|\s-verb\s+runas|start-process.*runas|seimpersonate|tokenvator|fodhelper|eventvwr/i
| select([@timestamp, ComputerName, UserName, ParentBaseFileName, ImageFileName, CommandLine, TargetProcessId, aid])
| sort(@timestamp, order=asc, limit=10000)
```

</details>

---

<a name="cs-ta0004-004"></a>

### 04. Local Group and Directory Account Changes

Surfaces group creation and directory account modification event families.

**Query ID:** `CS-TA0004-004` · **Platform:** `Not scoped` · **Tags:** `Identity`

**MITRE:** T1098 · **Status:** `Requires Validation`

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

```cql
#event_simpleName=/^(ActiveDirectoryAuditUserModified|UserGroupCreated|LocalWindowsUserUpdate)$/
| select([@timestamp, #event_simpleName, ComputerName, UserName, @rawstring, aid])
| sort(@timestamp, order=asc, limit=10000)
```

</details>

---

`Requires Validation` = not yet tenant-validated · `Tested` = exact-version tested · `Production reviewed` = peer-reviewed with evidence.

[← Home](../README.md) · [All queries](../QUERY-CATALOG.md)
