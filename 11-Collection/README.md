[← Home](../README.md) · [All queries](../QUERY-CATALOG.md)

# Collection

**CrowdStrike Falcon / NG-SIEM**  ·  **CQL**  ·  `TA0009`  ·  **10 queries**

Find access to sensitive files, staging paths, and data packaging activity.

---

## Query library

| Hunt | ID | MITRE | Status |
|:--|:--|:--|:--|
| [01. Archiving and Data Transfer Utilities](#cs-ta0009-001) | `CS-TA0009-001` | T1560 / T1005 | `Requires Validation` |
| [02. Sensitive File and Critical File Access Telemetry](#cs-ta0009-002) | `CS-TA0009-002` | T1005 (contextual) | `Requires Validation` |
| [03. Archive File Creation Event Families](#cs-ta0009-003) | `CS-TA0009-003` | T1560 | `Requires Validation` |
| [04. Potential Data Staging Paths and Compression](#cs-ta0009-004) | `CS-TA0009-004` | T1074.001 / T1560 | `Requires Validation` |
| [05. File Collection with Copy Utilities](#cs-ta0009-005) | `CS-TA0009-005` | T1005 / T1039 | `Requires Validation` |
| [06. Potential Data Staging in Shared Paths](#cs-ta0009-006) | `CS-TA0009-006` | T1074.001 / T1560 | `Requires Validation` |
| [07. File and USN Metadata for Archives](#cs-ta0009-007) | `CS-TA0009-007` | T1005 / T1560 | `Requires Validation` |
| [08. Archive Output and High-Entropy Write Events](#cs-ta0009-008) | `CS-TA0009-008` | T1560 | `Requires Validation` |
| [09. Specific Archive Format Writes](#cs-ta0009-009) | `CS-TA0009-009` | T1560 | `Requires Validation` |
| [10. Potential Archive Artifacts in File Metadata](#cs-fa-003) | `CS-FA-003` | DFIR / T1560 (contextual) | `Requires Validation` |
---

<a name="cs-ta0009-001"></a>

### 01. Archiving and Data Transfer Utilities

Searches process command lines for archiving, copying and transfer tools that may be used during data staging.

**Query ID:** `CS-TA0009-001` · **Platform:** `Windows` · **Tags:** `Process`

**MITRE:** T1560 / T1005 · **Status:** `Requires Validation`

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

```cql
#event_simpleName=ProcessRollup2 event_platform=Win
| CommandLine=/(?i)(7z|7za|winrar|rar|tar|robocopy|xcopy|rclone|azcopy|winscp|curl|ftp)(\.exe)?\b/
| table([@timestamp, ComputerName, UserName, ParentBaseFileName,
FileName, CommandLine, TargetProcessId])
| sort(@timestamp, order=desc)
```

</details>

---

<a name="cs-ta0009-002"></a>

### 02. Sensitive File and Critical File Access Telemetry

Discovers file access events classified as sensitive or critical.

**Query ID:** `CS-TA0009-002` · **Platform:** `Not scoped` · **Tags:** `File`

**MITRE:** T1005 (contextual) · **Status:** `Requires Validation`

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

```cql
#event_simpleName=/^(ClassifiedSensitiveFileAccess|CriticalFileAccessed)$/
| select([@timestamp, #event_simpleName, ComputerName, UserName, aid])
| sort(@timestamp, order=desc, limit=1000)
```

</details>

---

<a name="cs-ta0009-003"></a>

### 03. Archive File Creation Event Families

Reviews archive-format write events as potential staging evidence.

**Query ID:** `CS-TA0009-003` · **Platform:** `Not scoped` · **Tags:** `File`

**MITRE:** T1560 · **Status:** `Requires Validation`

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

```cql
#event_simpleName=/^(GzipFileWritten|XzFileWritten|RarFileWritten|TarFileWritten|BZip2FileWritten|LZipFileWritten|ArcFileWritten|ArjFileWritten)$/
| groupBy([#event_simpleName, ComputerName], function=[count(as=ArchiveEvents)], limit=1000)
| sort(ArchiveEvents, order=desc, limit=1000)
```

</details>

---

<a name="cs-ta0009-004"></a>

### 04. Potential Data Staging Paths and Compression

Finds command-line activity involving common staging folders and compression commands.

**Query ID:** `CS-TA0009-004` · **Platform:** `Windows` · **Tags:** `Process`

**MITRE:** T1074.001 / T1560 · **Status:** `Requires Validation`

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

```cql
#event_simpleName=ProcessRollup2 event_platform=Win
| CommandLine=/(\\Users\\Public\\|\\ProgramData\\|\\Temp\\|\bCompress-Archive\b|\b7z\s+a\b|\btar\s+\-c)/i
| select([@timestamp, ComputerName, UserName, ParentBaseFileName, FileName, CommandLine, aid])
| sort(@timestamp, order=desc, limit=1000)
```

</details>

---

<a name="cs-ta0009-005"></a>

### 05. File Collection with Copy Utilities

Searches for process commands invoking file copying and collection operations.

**Query ID:** `CS-TA0009-005` · **Platform:** `Not scoped` · **Tags:** `Process`

**MITRE:** T1005 / T1039 · **Status:** `Requires Validation`

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

```cql
#event_simpleName=ProcessRollup2
| CommandLine=/robocopy|xcopy|copy\s+|copy-item|rsync|scp\s+/i
| select([@timestamp, ComputerName, UserName, ParentBaseFileName, ImageFileName, CommandLine, TargetProcessId, aid])
| sort(@timestamp, order=asc, limit=10000)
```

</details>

---

<a name="cs-ta0009-006"></a>

### 06. Potential Data Staging in Shared Paths

Highlights staging and compression command lines using common scratch locations.

**Query ID:** `CS-TA0009-006` · **Platform:** `Not scoped` · **Tags:** `Process`

**MITRE:** T1074.001 / T1560 · **Status:** `Requires Validation`

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

```cql
#event_simpleName=ProcessRollup2
| CommandLine=/\\Users\\Public\\|\\ProgramData\\|\\Temp\\|\\tmp\\|\bCompress-Archive\b|\b7z\s+a\b|\btar\s+\-c/i
| select([@timestamp, ComputerName, UserName, ParentBaseFileName, ImageFileName, CommandLine, TargetProcessId, aid])
| sort(@timestamp, order=asc, limit=10000)
```

</details>

---

<a name="cs-ta0009-007"></a>

### 07. File and USN Metadata for Archives

Examines created filesystem artifacts with common archive and database export extensions.

**Query ID:** `CS-TA0009-007` · **Platform:** `Not scoped` · **Tags:** `File`

**MITRE:** T1005 / T1560 · **Status:** `Requires Validation`

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

```cql
#event_simpleName=/^(FileCreateInfo|FileInfo|MftRecord|USNRecord)$/
| @rawstring=/(\.zip|\.7z|\.rar|\.pst|\.csv|\.bak|\.sql)/i
| select([@timestamp, #event_simpleName, ComputerName, UserName, @rawstring, aid])
| sort(@timestamp, order=asc, limit=10000)
```

</details>

---

<a name="cs-ta0009-008"></a>

### 08. Archive Output and High-Entropy Write Events

Lists archive-related file writing event families and entropy signals.

**Query ID:** `CS-TA0009-008` · **Platform:** `Not scoped` · **Tags:** `File`

**MITRE:** T1560 · **Status:** `Requires Validation`

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

```cql
#event_simpleName=/^(GenericFileWritten|FileWrittenWithEntropyHigh|ArchiveFileContent)$/
| @rawstring=/(\.zip|\.7z|\.rar|\.tar|\.gz|password|secret)/i
| select([@timestamp, #event_simpleName, ComputerName, UserName, @rawstring, aid])
| sort(@timestamp, order=asc, limit=10000)
```

</details>

---

<a name="cs-ta0009-009"></a>

### 09. Specific Archive Format Writes

Reviews recognized archive file write events by compression type.

**Query ID:** `CS-TA0009-009` · **Platform:** `Not scoped` · **Tags:** `File`

**MITRE:** T1560 · **Status:** `Requires Validation`

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

```cql
#event_simpleName=/^(GzipFileWritten|XzFileWritten|RarFileWritten|TarFileWritten|BZip2FileWritten|LZipFileWritten|ArcFileWritten|ArjFileWritten)$/
| select([@timestamp, #event_simpleName, ComputerName, UserName, @rawstring, aid])
| sort(@timestamp, order=asc, limit=10000)
```

</details>

---

<a name="cs-fa-003"></a>

### 10. Potential Archive Artifacts in File Metadata

Searches for common archive/file-exfil extensions in file-system evidence.

**Query ID:** `CS-FA-003` · **Platform:** `Not scoped` · **Tags:** `File`

**MITRE:** DFIR / T1560 (contextual) · **Status:** `Requires Validation`

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

```cql
#event_simpleName=/^(FileInfo|USNRecord)$/
| FileName=/\.(zip|7z|rar|tar|gz|pst|bak|sql)$/i
| select([@timestamp, #event_simpleName, ComputerName, FileName, aid])
| sort(@timestamp, order=desc, limit=1000)
```

</details>

---

`Requires Validation` = not yet tenant-validated · `Tested` = exact-version tested · `Production reviewed` = peer-reviewed with evidence.

[← Home](../README.md) · [All queries](../QUERY-CATALOG.md)
