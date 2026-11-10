# Impact — CrowdStrike CQL

> **1 CQL entries** | CrowdStrike Falcon / NG-SIEM | MITRE: TA0040

Identify potentially disruptive activities including attempts to inhibit recovery.

> **Validation notice:** Entries marked *User-reported validated source* were provided as working queries, but publication copies were sanitized and must be re-tested. Entries marked *Candidate* and *Community-derived* have **not** been tested in this environment.

## Query Index

1. [Backup and Recovery Inhibition Commands](#01-backup-and-recovery-inhibition-commands)

---

## 01. Backup and Recovery Inhibition Commands

**Description:** Searches for common commands used to remove backups or interfere with recovery.

**MITRE ATT&CK:** T1490\
**Origin:** OneNote-derived adaptation\
**Validation:** Candidate — requires validation in Falcon\
**Required telemetry:** ProcessRollup2

<details>
<summary><strong>If you want to see more details</strong></summary>

### Hunting Query (CQL)

```cql
#event_simpleName=ProcessRollup2 event_platform=Win
| CommandLine=/(vssadmin\s+delete|wbadmin\s+delete|bcdedit.*recoveryenabled|wmic.*shadowcopy.*delete|delete\s+shadows)/i
| select([@timestamp, ComputerName, UserName, ParentBaseFileName, FileName, CommandLine, aid])
| sort(@timestamp, order=desc, limit=1000)
```

### False Positive Considerations

Authorized backup maintenance and disaster recovery testing.

### Investigation Guidance

Verify intent, resulting backup state and associated destructive actions.

</details>

---
