[← Home](../README.md) · [All queries](../QUERY-CATALOG.md)

# Forensic Artifacts

**CrowdStrike Falcon / NG-SIEM**  ·  **CQL**  ·  `Operational`  ·  **3 queries**

Reconstruct file-system and execution evidence from Falcon telemetry.

---

## Query library

| Hunt | ID | MITRE | Status |
|:--|:--|:--|:--|
| [01. Executable File Written After User Logon](#cs-fa-001) | `CS-FA-001` | Investigation utility | `Requires Validation` |
| [02. File-System Artifact Event Inventory](#cs-fa-002) | `CS-FA-002` | DFIR utility | `Requires Validation` |
| [03. Potential Archive Artifacts in File Metadata](#cs-fa-003) | `CS-FA-003` | DFIR / T1560 (contextual) | `Requires Validation` |

---

<a name="cs-fa-001"></a>

### 01. Executable File Written After User Logon

Joins executable file writes with user logon events to investigate executable creation after authentication.

**Query ID:** `CS-FA-001` · **Platform:** `Not scoped` · **Tags:** `File`, `Identity`

**MITRE:** Investigation utility · **Status:** `Requires Validation`

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

```cql
#event_simpleName=PeFileWritten FileName=/.exe/i
| rename(field=UserName, as=PE_User)
| join(query={#event_simpleName=UserLogon}, field=[aid], include=[LogonTime, LogonDomain, ComputerName, UserName, LogonType])
| test(ContextTimeStamp >= LogonTime)
| ContextTimeStamp:=ContextTimeStamp*1000
| formatTime(format="%Y/%m/%d %H:%M:%S %Z", field=ContextTimeStamp, as="WriteTime")
| LogonTime:=LogonTime*1000
| formatTime(format="%Y/%m/%d %H:%M:%S %Z", field=LogonTime, as="Logon_Time")
| groupBy([LogonDomain, ComputerName, UserName, Logon_Time, WriteTime, PE_User, FileName,Activity_duration], function=[])
| sort(WriteTime, order=asc, limit=max)
```

**False positives:** Join by aid can produce many-to-many matches; Activity_duration is referenced but not created in this query.

**Analyst pivot:** Scope by host, user and narrow time window; pivot to process tree and nearby evidence before concluding malicious activity.

</details>

<a name="cs-fa-002"></a>

### 02. File-System Artifact Event Inventory

Inventories file system artifact events to establish coverage before content-based hunting.

**Query ID:** `CS-FA-002` · **Platform:** `Not scoped` · **Tags:** `File`

**MITRE:** DFIR utility · **Status:** `Requires Validation`

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

```cql
#event_simpleName=/^(FileInfo|USNRecord|PrefetchFile)$/
| groupBy([#event_simpleName, ComputerName], function=[count(as=Events)], limit=1000)
| sort(Events, order=desc, limit=1000)
```

**False positives:** Presence depends on sensor/forensics collection; timing may reflect artifact import.

**Analyst pivot:** Use per-event fieldset validation and compare event time to ingest time.

</details>

<a name="cs-fa-003"></a>

### 03. Potential Archive Artifacts in File Metadata

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

**False positives:** Common business artifacts and backup packages. FileName must be verified for both event families.

**Analyst pivot:** Compare metadata, file path, process and related archive-write telemetry.

</details>

---

`Requires Validation` = not yet tenant-validated · `Tested` = exact-version tested · `Production reviewed` = peer-reviewed with evidence.

[← Home](../README.md) · [All queries](../QUERY-CATALOG.md)
