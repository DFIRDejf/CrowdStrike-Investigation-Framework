[← Framework home](../README.md)

# Privilege Escalation

**CrowdStrike Falcon / NG-SIEM**  ·  **CQL**  ·  `TA0004`  ·  **4 queries**

Review privilege changes and indicators of unauthorized elevation.

---

## Query library

| Hunt | Status |
|---|---|
| [01. Account Added to Privileged Group Event Family](#01-account-added-to-privileged-group-event-family) | `Candidate` |

| [02. Windows Token Privilege Modification Events](#02-windows-token-privilege-modification-events) | `Requires Validation` |
| [03. Elevation and Token Abuse Command Indicators](#03-elevation-and-token-abuse-command-indicators) | `Requires Validation` |
| [04. Local Group and Directory Account Changes](#04-local-group-and-directory-account-changes) | `Requires Validation` |
---

### 01. Account Added to Privileged Group Event Family

Exposes group membership change telemetry for investigation and follow-up filtering.

**MITRE:** T1098\  ·  **Telemetry:** UserAccountAddedToGroup and AD group entity events

<details>
<summary><strong>If you want to see more details</strong></summary>

```cql
#event_simpleName=/^(UserAccountAddedToGroup|ActiveDirectoryAccountDirectContainingGroupEntitiesUpdate|ActiveDirectoryAccountFlattenedContainingGroupEntitiesUpdate)$/
| select([@timestamp, #event_simpleName, ComputerName, UserName, aid])
| sort(@timestamp, order=desc, limit=1000)
```

**False positives:** Provisioning automation and authorized admin changes. Validate emitted event/field family.

**Analyst pivot:** Inspect actor, target account, target group and approval record.

*Origin: OneNote-derived adaptation\*

</details>

### 02. Windows Token Privilege Modification Events

Lists telemetry associated with token privilege changes and privileged process handles.

**MITRE:** T1134  ·  **Source:** `CS Queries.one`  ·  **Status:** `Requires Validation`

<details>
<summary><strong>If you want to see more details</strong></summary>

```cql
#event_simpleName=/^(ProcessTokenPrivilegesEdited|PrivilegedProcessHandleFromUnsignedModule)$/
| select([@timestamp, #event_simpleName, ComputerName, UserName, @rawstring, aid])
| sort(@timestamp, order=asc, limit=10000)
```

**False positives:** Review approved administrative operations and expected security tooling.

**Validation:** Confirm fieldsets and event semantics in the target tenant. [DO WERYFIKACJI W ŚRODOWISKU]

</details>

### 03. Elevation and Token Abuse Command Indicators

Finds command-line patterns for elevation, impersonation and token abuse.

**MITRE:** T1548 / T1134  ·  **Source:** `CS Queries.one`  ·  **Status:** `Requires Validation`

<details>
<summary><strong>If you want to see more details</strong></summary>

```cql
#event_simpleName=ProcessRollup2
| CommandLine=/runas|\s-verb\s+runas|start-process.*runas|seimpersonate|tokenvator|fodhelper|eventvwr/i
| select([@timestamp, ComputerName, UserName, ParentBaseFileName, ImageFileName, CommandLine, TargetProcessId, aid])
| sort(@timestamp, order=asc, limit=10000)
```

**False positives:** Review approved administrative operations and expected security tooling.

**Validation:** Confirm fieldsets and event semantics in the target tenant. [DO WERYFIKACJI W ŚRODOWISKU]

</details>

### 04. Local Group and Directory Account Changes

Surfaces group creation and directory account modification event families.

**MITRE:** T1098  ·  **Source:** `CS Queries.one`  ·  **Status:** `Requires Validation`

<details>
<summary><strong>If you want to see more details</strong></summary>

```cql
#event_simpleName=/^(ActiveDirectoryAuditUserModified|UserGroupCreated|LocalWindowsUserUpdate)$/
| select([@timestamp, #event_simpleName, ComputerName, UserName, @rawstring, aid])
| sort(@timestamp, order=asc, limit=10000)
```

**False positives:** Review approved administrative operations and expected security tooling.

**Validation:** Confirm fieldsets and event semantics in the target tenant. [DO WERYFIKACJI W ŚRODOWISKU]

</details>


---

`Migration recheck` = original supplied query was previously tested, but this publication copy needs validation. `Candidate` / `Community candidate` = not validated in the target Falcon environment.

[← Back to framework](../README.md)
