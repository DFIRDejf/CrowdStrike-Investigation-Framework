[← Home](../README.md) · [All queries](../QUERY-CATALOG.md)

# Forensic Artifacts

**CrowdStrike Falcon / NG-SIEM**  ·  **CQL**  ·  `Operational`  ·  **3 queries**

Reconstruct file-system and execution evidence from Falcon telemetry.

---

## Query library

| Hunt | MITRE | Status |
|:--|:--|:--|
| [01. Executable File Written After User Logon](#01-executable-file-written-after-user-logon) | Investigation utility | `Migration recheck` |
| [02. File-System Artifact Event Inventory](#02-file-system-artifact-event-inventory) | DFIR utility\ | `Candidate` |
| [03. Potential Archive Artifacts in File Metadata](#03-potential-archive-artifacts-in-file-metadata) | DFIR / T1560 (contextual)\ | `Candidate` |

---

### 01. Executable File Written After User Logon

Joins executable file writes with user logon events to investigate executable creation after authentication.

**MITRE:** Investigation utility

<details>
<summary><strong>If you want to see more details</strong></summary>

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

### 02. File-System Artifact Event Inventory

Inventories file system artifact events to establish coverage before content-based hunting.

**MITRE:** DFIR utility  ·  **Telemetry:** FileInfo, USNRecord, PrefetchFile

<details>
<summary><strong>If you want to see more details</strong></summary>

```cql
#event_simpleName=/^(FileInfo|USNRecord|PrefetchFile)$/
| groupBy([#event_simpleName, ComputerName], function=[count(as=Events)], limit=1000)
| sort(Events, order=desc, limit=1000)
```

**False positives:** Presence depends on sensor/forensics collection; timing may reflect artifact import.

**Analyst pivot:** Use per-event fieldset validation and compare event time to ingest time.

*Origin: OneNote-derived adaptation*

</details>

### 03. Potential Archive Artifacts in File Metadata

Searches for common archive/file-exfil extensions in file-system evidence.

**MITRE:** DFIR / T1560 (contextual)  ·  **Telemetry:** FileInfo, USNRecord

<details>
<summary><strong>If you want to see more details</strong></summary>

```cql
#event_simpleName=/^(FileInfo|USNRecord)$/
| FileName=/\.(zip|7z|rar|tar|gz|pst|bak|sql)$/i
| select([@timestamp, #event_simpleName, ComputerName, FileName, aid])
| sort(@timestamp, order=desc, limit=1000)
```

**False positives:** Common business artifacts and backup packages. FileName must be verified for both event families.

**Analyst pivot:** Compare metadata, file path, process and related archive-write telemetry.

*Origin: OneNote-derived adaptation*

</details>

---

`Migration recheck` = original supplied query was previously tested, but this publication copy needs validation. `Candidate` / `Community candidate` = not validated in the target Falcon environment.

[← Home](../README.md) · [All queries](../QUERY-CATALOG.md)
