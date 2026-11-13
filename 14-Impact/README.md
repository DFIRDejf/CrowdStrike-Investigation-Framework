[← Home](../README.md) · [All queries](../QUERY-CATALOG.md)

# Impact

**CrowdStrike Falcon / NG-SIEM**  ·  **CQL**  ·  `TA0040`  ·  **5 queries**

Spot disruptive activity and attempts to inhibit system recovery.

---

## Query library

| Hunt | ID | MITRE | Status |
|:--|:--|:--|:--|
| [01. Backup and Recovery Inhibition Commands](#cs-ta0040-001) | `CS-TA0040-001` | T1490 | `Requires Validation` |
| [02. Ransomware File Rename and Entropy Events](#cs-ta0040-002) | `CS-TA0040-002` | T1486 | `Requires Validation` |
| [03. Host Prevention and Containment Event Inventory](#cs-ta0040-003) | `CS-TA0040-003` | T1489 (context) | `Requires Validation` |
| [04. Service and Account Disruption Events](#cs-ta0040-004) | `CS-TA0040-004` | T1489 / T1531 | `Requires Validation` |
| [05. Recovery Inhibition Command Indicators](#cs-ta0040-005) | `CS-TA0040-005` | T1490 | `Requires Validation` |

---

<a name="cs-ta0040-001"></a>

### 01. Backup and Recovery Inhibition Commands

Searches for common commands used to remove backups or interfere with recovery.

**Query ID:** `CS-TA0040-001` · **Platform:** `Windows` · **Tags:** `Process`

**MITRE:** T1490 · **Status:** `Requires Validation`

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

```cql
#event_simpleName=ProcessRollup2 event_platform=Win
| CommandLine=/(vssadmin\s+delete|wbadmin\s+delete|bcdedit.*recoveryenabled|wmic.*shadowcopy.*delete|delete\s+shadows)/i
| select([@timestamp, ComputerName, UserName, ParentBaseFileName, FileName, CommandLine, aid])
| sort(@timestamp, order=desc, limit=1000)
```

</details>

---

<a name="cs-ta0040-002"></a>

### 02. Ransomware File Rename and Entropy Events

Collects file events associated with encryption, renaming and boot record tampering.

**Query ID:** `CS-TA0040-002` · **Platform:** `Not scoped` · **Tags:** `File`

**MITRE:** T1486 · **Status:** `Requires Validation`

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

```cql
#event_simpleName=/^(RansomwareRenameFile|FileWrittenWithEntropyHigh|MbrOverwriteRawDetectInfo)$/
| select([@timestamp, #event_simpleName, ComputerName, UserName, @rawstring, aid])
| sort(@timestamp, order=asc, limit=10000)
```

</details>

---

<a name="cs-ta0040-003"></a>

### 03. Host Prevention and Containment Event Inventory

Displays endpoint controls blocking operations or processes; these do not themselves imply attacker impact.

**Query ID:** `CS-TA0040-003` · **Platform:** `Not scoped` · **Tags:** `File`, `Process`, `Security`

**MITRE:** T1489 (context) · **Status:** `Requires Validation`

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

```cql
#event_simpleName=/^(FirewallEnabled|FileSystemOperationBlocked|ProcessBlocked)$/
| select([@timestamp, #event_simpleName, ComputerName, UserName, @rawstring, aid])
| sort(@timestamp, order=asc, limit=10000)
```

</details>

---

<a name="cs-ta0040-004"></a>

### 04. Service and Account Disruption Events

Surfaces group/user disruption and service creation telemetry.

**Query ID:** `CS-TA0040-004` · **Platform:** `Not scoped` · **Tags:** `Identity`

**MITRE:** T1489 / T1531 · **Status:** `Requires Validation`

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

```cql
#event_simpleName=/^(UserAccountRemovedFromGroup|UserGroupDeleted|ActiveDirectoryAccountDisabled|SystemdServiceCreated|KernelServiceStarted)$/
| select([@timestamp, #event_simpleName, ComputerName, UserName, @rawstring, aid])
| sort(@timestamp, order=asc, limit=10000)
```

</details>

---

<a name="cs-ta0040-005"></a>

### 05. Recovery Inhibition Command Indicators

Searches for commands targeting shadow copies and Windows recovery settings.

**Query ID:** `CS-TA0040-005` · **Platform:** `Not scoped` · **Tags:** `Process`

**MITRE:** T1490 · **Status:** `Requires Validation`

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

```cql
#event_simpleName=ProcessRollup2
| CommandLine=/vssadmin\s+delete|wbadmin\s+delete|bcdedit.*recoveryenabled|wmic.*shadowcopy.*delete|delete\s+shadows/i
| select([@timestamp, ComputerName, UserName, ParentBaseFileName, ImageFileName, CommandLine, TargetProcessId, aid])
| sort(@timestamp, order=asc, limit=10000)
```

</details>

---

`Requires Validation` = not yet tenant-validated · `Tested` = exact-version tested · `Production reviewed` = peer-reviewed with evidence.

[← Home](../README.md) · [All queries](../QUERY-CATALOG.md)
