[← Framework home](../README.md)

# Collection

**CrowdStrike Falcon / NG-SIEM**  ·  **CQL**  ·  `TA0009`  ·  **4 queries**

Find access to sensitive files, staging paths, and data packaging activity.

---

## Query library

| Hunt | Status |
|---|---|
| [01. Archiving and Data Transfer Utilities](#01-archiving-and-data-transfer-utilities) | `Migration recheck` |
| [02. Sensitive File and Critical File Access Telemetry](#02-sensitive-file-and-critical-file-access-telemetry) | `Candidate` |
| [03. Archive File Creation Event Families](#03-archive-file-creation-event-families) | `Candidate` |
| [04. Potential Data Staging Paths and Compression](#04-potential-data-staging-paths-and-compression) | `Candidate` |

---

### 01. Archiving and Data Transfer Utilities

Searches process command lines for archiving, copying and transfer tools that may be used during data staging.

**MITRE:** T1560 / T1005\

<details>
<summary><strong>If you want to see more details</strong></summary>

```cql
#event_simpleName=ProcessRollup2 event_platform=Win
| CommandLine=/(?i)(7z|7za|winrar|rar|tar|robocopy|xcopy|rclone|azcopy|winscp|curl|ftp)(\.exe)?\b/
| table([@timestamp, ComputerName, UserName, ParentBaseFileName,
FileName, CommandLine, TargetProcessId])
| sort(@timestamp, order=desc)
```

**False positives:** The regex detects tool names, not actual compression or exfiltration. Legitimate backup and copy activity is common.

**Analyst pivot:** Scope by host, user and narrow time window; pivot to process tree and nearby evidence before concluding malicious activity.

</details>

### 02. Sensitive File and Critical File Access Telemetry

Discovers file access events classified as sensitive or critical.

**MITRE:** T1005 (contextual)\  ·  **Telemetry:** ClassifiedSensitiveFileAccess, CriticalFileAccessed

<details>
<summary><strong>If you want to see more details</strong></summary>

```cql
#event_simpleName=/^(ClassifiedSensitiveFileAccess|CriticalFileAccessed)$/
| select([@timestamp, #event_simpleName, ComputerName, UserName, aid])
| sort(@timestamp, order=desc, limit=1000)
```

**False positives:** Backup jobs, search indexing, EDR and business-critical applications.

**Analyst pivot:** Validate classification, paths and process fields before use in correlation.

*Origin: OneNote-derived adaptation\*

</details>

### 03. Archive File Creation Event Families

Reviews archive-format write events as potential staging evidence.

**MITRE:** T1560\  ·  **Telemetry:** Archive-format file write events

<details>
<summary><strong>If you want to see more details</strong></summary>

```cql
#event_simpleName=/^(GzipFileWritten|XzFileWritten|RarFileWritten|TarFileWritten|BZip2FileWritten|LZipFileWritten|ArcFileWritten|ArjFileWritten)$/
| groupBy([#event_simpleName, ComputerName], function=[count(as=ArchiveEvents)], limit=1000)
| sort(ArchiveEvents, order=desc, limit=1000)
```

**False positives:** Development, software packaging and backups.

**Analyst pivot:** Pivot into the writing process and destination file path.

*Origin: OneNote-derived adaptation\*

</details>

### 04. Potential Data Staging Paths and Compression

Finds command-line activity involving common staging folders and compression commands.

**MITRE:** T1074.001 / T1560\  ·  **Telemetry:** ProcessRollup2

<details>
<summary><strong>If you want to see more details</strong></summary>

```cql
#event_simpleName=ProcessRollup2 event_platform=Win
| CommandLine=/(\\Users\\Public\\|\\ProgramData\\|\\Temp\\|\bCompress-Archive\b|\b7z\s+a\b|\btar\s+\-c)/i
| select([@timestamp, ComputerName, UserName, ParentBaseFileName, FileName, CommandLine, aid])
| sort(@timestamp, order=desc, limit=1000)
```

**False positives:** Legitimate backup, deployment and archiving tasks.

**Analyst pivot:** Require multiple indicators and review file names and paths.

*Origin: OneNote-derived adaptation\*

</details>

---

`Migration recheck` = original supplied query was previously tested, but this publication copy needs validation. `Candidate` / `Community candidate` = not validated in the target Falcon environment.

[← Back to framework](../README.md)
