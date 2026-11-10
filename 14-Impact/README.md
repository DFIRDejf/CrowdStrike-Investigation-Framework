[← Framework home](../README.md)

# Impact

**CrowdStrike Falcon / NG-SIEM**  ·  **CQL**  ·  `TA0040`  ·  **1 queries**

Spot disruptive activity and attempts to inhibit system recovery.

---

## Query library

| Hunt | Status |
|---|---|
| [01. Backup and Recovery Inhibition Commands](#01-backup-and-recovery-inhibition-commands) | `Candidate` |

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

---

`Migration recheck` = original supplied query was previously tested, but this publication copy needs validation. `Candidate` / `Community candidate` = not validated in the target Falcon environment.

[← Back to framework](../README.md)
