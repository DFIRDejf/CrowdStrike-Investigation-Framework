# Collection — CrowdStrike CQL

> **4 CQL entries** | CrowdStrike Falcon / NG-SIEM | MITRE: TA0009

Investigate sensitive-file access, local staging and archive creation behaviors.

> **Validation notice:** Entries marked *User-reported validated source* were provided as working queries, but publication copies were sanitized and must be re-tested. Entries marked *Candidate* and *Community-derived* have **not** been tested in this environment.

## Query Index

1. [Archiving and Data Transfer Utilities](#01-archiving-and-data-transfer-utilities)
2. [Sensitive File and Critical File Access Telemetry](#02-sensitive-file-and-critical-file-access-telemetry)
3. [Archive File Creation Event Families](#03-archive-file-creation-event-families)
4. [Potential Data Staging Paths and Compression](#04-potential-data-staging-paths-and-compression)

---

## 01. Archiving and Data Transfer Utilities

**Description:** Searches process command lines for archiving, copying and transfer tools that may be used during data staging.

**MITRE ATT&CK:** T1560 / T1005\
**Origin:** Previously supplied CQL — sanitized migration copy\
**Validation:** User-reported validated source; revalidate sanitized copy\
**Required telemetry:** See event filters in query

<details>
<summary><strong>If you want to see more details</strong></summary>

### Hunting Query (CQL)

```cql
#event_simpleName=ProcessRollup2 event_platform=Win
| CommandLine=/(?i)(7z|7za|winrar|rar|tar|robocopy|xcopy|rclone|azcopy|winscp|curl|ftp)(\.exe)?\b/
| table([@timestamp, ComputerName, UserName, ParentBaseFileName,
FileName, CommandLine, TargetProcessId])
| sort(@timestamp, order=desc)
```

### False Positive Considerations

The regex detects tool names, not actual compression or exfiltration. Legitimate backup and copy activity is common.

### Investigation Guidance

Scope by host, user and narrow time window; pivot to process tree and nearby evidence before concluding malicious activity.

</details>

---

## 02. Sensitive File and Critical File Access Telemetry

**Description:** Discovers file access events classified as sensitive or critical.

**MITRE ATT&CK:** T1005 (contextual)\
**Origin:** OneNote-derived adaptation\
**Validation:** Candidate — requires validation in Falcon\
**Required telemetry:** ClassifiedSensitiveFileAccess, CriticalFileAccessed

<details>
<summary><strong>If you want to see more details</strong></summary>

### Hunting Query (CQL)

```cql
#event_simpleName=/^(ClassifiedSensitiveFileAccess|CriticalFileAccessed)$/
| select([@timestamp, #event_simpleName, ComputerName, UserName, aid])
| sort(@timestamp, order=desc, limit=1000)
```

### False Positive Considerations

Backup jobs, search indexing, EDR and business-critical applications.

### Investigation Guidance

Validate classification, paths and process fields before use in correlation.

</details>

---

## 03. Archive File Creation Event Families

**Description:** Reviews archive-format write events as potential staging evidence.

**MITRE ATT&CK:** T1560\
**Origin:** OneNote-derived adaptation\
**Validation:** Candidate — requires validation in Falcon\
**Required telemetry:** Archive-format file write events

<details>
<summary><strong>If you want to see more details</strong></summary>

### Hunting Query (CQL)

```cql
#event_simpleName=/^(GzipFileWritten|XzFileWritten|RarFileWritten|TarFileWritten|BZip2FileWritten|LZipFileWritten|ArcFileWritten|ArjFileWritten)$/
| groupBy([#event_simpleName, ComputerName], function=[count(as=ArchiveEvents)], limit=1000)
| sort(ArchiveEvents, order=desc, limit=1000)
```

### False Positive Considerations

Development, software packaging and backups.

### Investigation Guidance

Pivot into the writing process and destination file path.

</details>

---

## 04. Potential Data Staging Paths and Compression

**Description:** Finds command-line activity involving common staging folders and compression commands.

**MITRE ATT&CK:** T1074.001 / T1560\
**Origin:** OneNote-derived adaptation\
**Validation:** Candidate — requires validation in Falcon\
**Required telemetry:** ProcessRollup2

<details>
<summary><strong>If you want to see more details</strong></summary>

### Hunting Query (CQL)

```cql
#event_simpleName=ProcessRollup2 event_platform=Win
| CommandLine=/(\\Users\\Public\\|\\ProgramData\\|\\Temp\\|\bCompress-Archive\b|\b7z\s+a\b|\btar\s+\-c)/i
| select([@timestamp, ComputerName, UserName, ParentBaseFileName, FileName, CommandLine, aid])
| sort(@timestamp, order=desc, limit=1000)
```

### False Positive Considerations

Legitimate backup, deployment and archiving tasks.

### Investigation Guidance

Require multiple indicators and review file names and paths.

</details>

---
