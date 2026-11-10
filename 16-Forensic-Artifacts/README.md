# Forensic Artifacts — CrowdStrike CQL

> **3 CQL entries** | CrowdStrike Falcon / NG-SIEM | MITRE: Operational (not a MITRE tactic)

Investigate disk, file-system and other forensic artifacts captured by Falcon and integrated forensics sources.

> **Validation notice:** Entries marked *User-reported validated source* were provided as working queries, but publication copies were sanitized and must be re-tested. Entries marked *Candidate* and *Community-derived* have **not** been tested in this environment.

## Query Index

1. [Executable File Written After User Logon](#01-executable-file-written-after-user-logon)
2. [File-System Artifact Event Inventory](#02-file-system-artifact-event-inventory)
3. [Potential Archive Artifacts in File Metadata](#03-potential-archive-artifacts-in-file-metadata)

---

## 01. Executable File Written After User Logon

**Description:** Joins executable file writes with user logon events to investigate executable creation after authentication.

**MITRE ATT&CK:** Investigation utility\
**Origin:** Previously supplied CQL — sanitized migration copy\
**Validation:** User-reported validated source; revalidate sanitized copy\
**Required telemetry:** See event filters in query

<details>
<summary><strong>If you want to see more details</strong></summary>

### Hunting Query (CQL)

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

### False Positive Considerations

Join by aid can produce many-to-many matches; Activity_duration is referenced but not created in this query.

### Investigation Guidance

Scope by host, user and narrow time window; pivot to process tree and nearby evidence before concluding malicious activity.

</details>

---

## 02. File-System Artifact Event Inventory

**Description:** Inventories file system artifact events to establish coverage before content-based hunting.

**MITRE ATT&CK:** DFIR utility\
**Origin:** OneNote-derived adaptation\
**Validation:** Candidate — requires validation in Falcon\
**Required telemetry:** FileInfo, USNRecord, PrefetchFile

<details>
<summary><strong>If you want to see more details</strong></summary>

### Hunting Query (CQL)

```cql
#event_simpleName=/^(FileInfo|USNRecord|PrefetchFile)$/
| groupBy([#event_simpleName, ComputerName], function=[count(as=Events)], limit=1000)
| sort(Events, order=desc, limit=1000)
```

### False Positive Considerations

Presence depends on sensor/forensics collection; timing may reflect artifact import.

### Investigation Guidance

Use per-event fieldset validation and compare event time to ingest time.

</details>

---

## 03. Potential Archive Artifacts in File Metadata

**Description:** Searches for common archive/file-exfil extensions in file-system evidence.

**MITRE ATT&CK:** DFIR / T1560 (contextual)\
**Origin:** OneNote-derived adaptation\
**Validation:** Candidate — requires validation in Falcon\
**Required telemetry:** FileInfo, USNRecord

<details>
<summary><strong>If you want to see more details</strong></summary>

### Hunting Query (CQL)

```cql
#event_simpleName=/^(FileInfo|USNRecord)$/
| FileName=/\.(zip|7z|rar|tar|gz|pst|bak|sql)$/i
| select([@timestamp, #event_simpleName, ComputerName, FileName, aid])
| sort(@timestamp, order=desc, limit=1000)
```

### False Positive Considerations

Common business artifacts and backup packages. FileName must be verified for both event families.

### Investigation Guidance

Compare metadata, file path, process and related archive-write telemetry.

</details>

---
