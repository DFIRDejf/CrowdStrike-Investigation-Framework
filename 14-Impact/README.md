[← Framework home](../README.md)

# Impact

**CrowdStrike Falcon / NG-SIEM**  ·  **CQL**  ·  `TA0040`  ·  **5 queries**

Spot disruptive activity and attempts to inhibit system recovery.

---

## Query library

| Hunt | Status |
|---|---|
| [01. Backup and Recovery Inhibition Commands](#01-backup-and-recovery-inhibition-commands) | `Candidate` |
| [02. Ransomware File Rename and Entropy Events](#02-ransomware-file-rename-and-entropy-events) | `Requires Validation` |
| [03. Host Prevention and Containment Event Inventory](#03-host-prevention-and-containment-event-inventory) | `Requires Validation` |
| [04. Service and Account Disruption Events](#04-service-and-account-disruption-events) | `Requires Validation` |
| [05. Recovery Inhibition Command Indicators](#05-recovery-inhibition-command-indicators) | `Requires Validation` |
---

### 01. Backup and Recovery Inhibition Commands

Searches for common commands used to remove backups or interfere with recovery.

**MITRE:** T1490\  ·  **Telemetry:** ProcessRollup2

<details>
<summary><strong>If you want to see more details</strong></summary>

```cql
#event_simpleName=ProcessRollup2 event_platform=Win
| CommandLine=/(vssadmin\s+delete|wbadmin\s+delete|bcdedit.*recoveryenabled|wmic.*shadowcopy.*delete|delete\s+shadows)/i
| select([@timestamp, ComputerName, UserName, ParentBaseFileName, FileName, CommandLine, aid])
| sort(@timestamp, order=desc, limit=1000)
```

**False positives:** Authorized backup maintenance and disaster recovery testing.

**Analyst pivot:** Verify intent, resulting backup state and associated destructive actions.

*Origin: OneNote-derived adaptation\*

</details>

### 02. Ransomware File Rename and Entropy Events

Collects file events associated with encryption, renaming and boot record tampering.

**MITRE:** T1486  ·  **Source:** `CS Queries.one`  ·  **Status:** `Requires Validation`

<details>
<summary><strong>If you want to see more details</strong></summary>

```cql
#event_simpleName=/^(RansomwareRenameFile|FileWrittenWithEntropyHigh|MbrOverwriteRawDetectInfo)$/
| select([@timestamp, #event_simpleName, ComputerName, UserName, @rawstring, aid])
| sort(@timestamp, order=asc, limit=10000)
```

**False positives:** Backup encryption and compressed outputs; high entropy is not definitive ransomware.

**Validation:** Confirm event fields and semantic coverage in Falcon. [DO WERYFIKACJI W ŚRODOWISKU]

</details>

### 03. Host Prevention and Containment Event Inventory

Displays endpoint controls blocking operations or processes; these do not themselves imply attacker impact.

**MITRE:** T1489 (context)  ·  **Source:** `CS Queries.one`  ·  **Status:** `Requires Validation`

<details>
<summary><strong>If you want to see more details</strong></summary>

```cql
#event_simpleName=/^(FirewallEnabled|FileSystemOperationBlocked|ProcessBlocked)$/
| select([@timestamp, #event_simpleName, ComputerName, UserName, @rawstring, aid])
| sort(@timestamp, order=asc, limit=10000)
```

**False positives:** Expected endpoint protection actions and false-positive blocks.

**Validation:** Confirm event fields and semantic coverage in Falcon. [DO WERYFIKACJI W ŚRODOWISKU]

</details>

### 04. Service and Account Disruption Events

Surfaces group/user disruption and service creation telemetry.

**MITRE:** T1489 / T1531  ·  **Source:** `CS Queries.one`  ·  **Status:** `Requires Validation`

<details>
<summary><strong>If you want to see more details</strong></summary>

```cql
#event_simpleName=/^(UserAccountRemovedFromGroup|UserGroupDeleted|ActiveDirectoryAccountDisabled|SystemdServiceCreated|KernelServiceStarted)$/
| select([@timestamp, #event_simpleName, ComputerName, UserName, @rawstring, aid])
| sort(@timestamp, order=asc, limit=10000)
```

**False positives:** Routine identity cleanup and system service maintenance.

**Validation:** Confirm event fields and semantic coverage in Falcon. [DO WERYFIKACJI W ŚRODOWISKU]

</details>

### 05. Recovery Inhibition Command Indicators

Searches for commands targeting shadow copies and Windows recovery settings.

**MITRE:** T1490  ·  **Source:** `CS Queries.one`  ·  **Status:** `Requires Validation`

<details>
<summary><strong>If you want to see more details</strong></summary>

```cql
#event_simpleName=ProcessRollup2
| CommandLine=/vssadmin\s+delete|wbadmin\s+delete|bcdedit.*recoveryenabled|wmic.*shadowcopy.*delete|delete\s+shadows/i
| select([@timestamp, ComputerName, UserName, ParentBaseFileName, ImageFileName, CommandLine, TargetProcessId, aid])
| sort(@timestamp, order=asc, limit=10000)
```

**False positives:** Authorized backup rotation or recovery configuration changes.

**Validation:** Confirm event fields and semantic coverage in Falcon. [DO WERYFIKACJI W ŚRODOWISKU]

</details>


---

`Migration recheck` = original supplied query was previously tested, but this publication copy needs validation. `Candidate` / `Community candidate` = not validated in the target Falcon environment.

[← Back to framework](../README.md)
