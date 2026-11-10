[← Home](../README.md) · [All queries](../QUERY-CATALOG.md)

# Collection

**CrowdStrike Falcon / NG-SIEM**  ·  **CQL**  ·  `TA0009`  ·  **9 queries**

Find access to sensitive files, staging paths, and data packaging activity.

---

## Query library

| Hunt | MITRE | Status |
|:--|:--|:--|
| [01. Archiving and Data Transfer Utilities](#01-archiving-and-data-transfer-utilities) | T1560 / T1005 | `Migration recheck` |
| [02. Sensitive File and Critical File Access Telemetry](#02-sensitive-file-and-critical-file-access-telemetry) | T1005 (contextual)\ | `Candidate` |
| [03. Archive File Creation Event Families](#03-archive-file-creation-event-families) | T1560\ | `Candidate` |
| [04. Potential Data Staging Paths and Compression](#04-potential-data-staging-paths-and-compression) | T1074.001 / T1560\ | `Candidate` |
| [05. File Collection with Copy Utilities](#05-file-collection-with-copy-utilities) | T1005 / T1039 | `Requires Validation` |
| [06. Potential Data Staging in Shared Paths](#06-potential-data-staging-in-shared-paths) | T1074.001 / T1560 | `Requires Validation` |
| [07. File and USN Metadata for Archives](#07-file-and-usn-metadata-for-archives) | T1005 / T1560 | `Requires Validation` |
| [08. Archive Output and High-Entropy Write Events](#08-archive-output-and-high-entropy-write-events) | T1560 | `Requires Validation` |
| [09. Specific Archive Format Writes](#09-specific-archive-format-writes) | T1560 | `Requires Validation` |

---

### 01. Archiving and Data Transfer Utilities

Searches process command lines for archiving, copying and transfer tools that may be used during data staging.

**MITRE:** T1560 / T1005

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

**MITRE:** T1005 (contextual)  ·  **Telemetry:** ClassifiedSensitiveFileAccess, CriticalFileAccessed

<details>
<summary><strong>If you want to see more details</strong></summary>

```cql
#event_simpleName=/^(ClassifiedSensitiveFileAccess|CriticalFileAccessed)$/
| select([@timestamp, #event_simpleName, ComputerName, UserName, aid])
| sort(@timestamp, order=desc, limit=1000)
```

**False positives:** Backup jobs, search indexing, EDR and business-critical applications.

**Analyst pivot:** Validate classification, paths and process fields before use in correlation.

*Origin: OneNote-derived adaptation*

</details>

### 03. Archive File Creation Event Families

Reviews archive-format write events as potential staging evidence.

**MITRE:** T1560  ·  **Telemetry:** Archive-format file write events

<details>
<summary><strong>If you want to see more details</strong></summary>

```cql
#event_simpleName=/^(GzipFileWritten|XzFileWritten|RarFileWritten|TarFileWritten|BZip2FileWritten|LZipFileWritten|ArcFileWritten|ArjFileWritten)$/
| groupBy([#event_simpleName, ComputerName], function=[count(as=ArchiveEvents)], limit=1000)
| sort(ArchiveEvents, order=desc, limit=1000)
```

**False positives:** Development, software packaging and backups.

**Analyst pivot:** Pivot into the writing process and destination file path.

*Origin: OneNote-derived adaptation*

</details>

### 04. Potential Data Staging Paths and Compression

Finds command-line activity involving common staging folders and compression commands.

**MITRE:** T1074.001 / T1560  ·  **Telemetry:** ProcessRollup2

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

*Origin: OneNote-derived adaptation*

</details>

### 05. File Collection with Copy Utilities

Searches for process commands invoking file copying and collection operations.

**MITRE:** T1005 / T1039  ·  **Source:** `CS Queries.one`  ·  **Status:** `Requires Validation`

<details>
<summary><strong>If you want to see more details</strong></summary>

```cql
#event_simpleName=ProcessRollup2
| CommandLine=/robocopy|xcopy|copy\s+|copy-item|rsync|scp\s+/i
| select([@timestamp, ComputerName, UserName, ParentBaseFileName, ImageFileName, CommandLine, TargetProcessId, aid])
| sort(@timestamp, order=asc, limit=10000)
```

**False positives:** Backup utilities, migration tooling and routine file copying.

**Validation:** Confirm event fields and semantic coverage in Falcon. [DO WERYFIKACJI W ŚRODOWISKU]

</details>

### 06. Potential Data Staging in Shared Paths

Highlights staging and compression command lines using common scratch locations.

**MITRE:** T1074.001 / T1560  ·  **Source:** `CS Queries.one`  ·  **Status:** `Requires Validation`

<details>
<summary><strong>If you want to see more details</strong></summary>

```cql
#event_simpleName=ProcessRollup2
| CommandLine=/\\Users\\Public\\|\\ProgramData\\|\\Temp\\|\\tmp\\|\bCompress-Archive\b|\b7z\s+a\b|\btar\s+\-c/i
| select([@timestamp, ComputerName, UserName, ParentBaseFileName, ImageFileName, CommandLine, TargetProcessId, aid])
| sort(@timestamp, order=asc, limit=10000)
```

**False positives:** Software installations, extraction and temporary application files.

**Validation:** Confirm event fields and semantic coverage in Falcon. [DO WERYFIKACJI W ŚRODOWISKU]

</details>

### 07. File and USN Metadata for Archives

Examines created filesystem artifacts with common archive and database export extensions.

**MITRE:** T1005 / T1560  ·  **Source:** `CS Queries.one`  ·  **Status:** `Requires Validation`

<details>
<summary><strong>If you want to see more details</strong></summary>

```cql
#event_simpleName=/^(FileCreateInfo|FileInfo|MftRecord|USNRecord)$/
| @rawstring=/(\.zip|\.7z|\.rar|\.pst|\.csv|\.bak|\.sql)/i
| select([@timestamp, #event_simpleName, ComputerName, UserName, @rawstring, aid])
| sort(@timestamp, order=asc, limit=10000)
```

**False positives:** Routine compressed backups and normal database maintenance.

**Validation:** Confirm event fields and semantic coverage in Falcon. [DO WERYFIKACJI W ŚRODOWISKU]

</details>

### 08. Archive Output and High-Entropy Write Events

Lists archive-related file writing event families and entropy signals.

**MITRE:** T1560  ·  **Source:** `CS Queries.one`  ·  **Status:** `Requires Validation`

<details>
<summary><strong>If you want to see more details</strong></summary>

```cql
#event_simpleName=/^(GenericFileWritten|FileWrittenWithEntropyHigh|ArchiveFileContent)$/
| @rawstring=/(\.zip|\.7z|\.rar|\.tar|\.gz|password|secret)/i
| select([@timestamp, #event_simpleName, ComputerName, UserName, @rawstring, aid])
| sort(@timestamp, order=asc, limit=10000)
```

**False positives:** Compressed benign files and encrypted business documents.

**Validation:** Confirm event fields and semantic coverage in Falcon. [DO WERYFIKACJI W ŚRODOWISKU]

</details>

### 09. Specific Archive Format Writes

Reviews recognized archive file write events by compression type.

**MITRE:** T1560  ·  **Source:** `CS Queries.one`  ·  **Status:** `Requires Validation`

<details>
<summary><strong>If you want to see more details</strong></summary>

```cql
#event_simpleName=/^(GzipFileWritten|XzFileWritten|RarFileWritten|TarFileWritten|BZip2FileWritten|LZipFileWritten|ArcFileWritten|ArjFileWritten)$/
| select([@timestamp, #event_simpleName, ComputerName, UserName, @rawstring, aid])
| sort(@timestamp, order=asc, limit=10000)
```

**False positives:** Approved packaging, application caches and software distribution.

**Validation:** Confirm event fields and semantic coverage in Falcon. [DO WERYFIKACJI W ŚRODOWISKU]

</details>


---

`Migration recheck` = original supplied query was previously tested, but this publication copy needs validation. `Candidate` / `Community candidate` = not validated in the target Falcon environment.

[← Home](../README.md) · [All queries](../QUERY-CATALOG.md)
