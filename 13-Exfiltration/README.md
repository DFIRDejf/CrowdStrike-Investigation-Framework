[← Home](../README.md) · [All queries](../QUERY-CATALOG.md)

# Exfiltration

**CrowdStrike Falcon / NG-SIEM**  ·  **CQL**  ·  `TA0010`  ·  **7 queries**

Investigate sensitive file access and suspicious outbound transfer patterns.

---

## Query library

| Hunt | ID | MITRE | Status |
|:--|:--|:--|:--|
| [01. Sensitive File Access Followed by External Connection](#cs-ta0010-001) | `CS-TA0010-001` | T1041 (potential) | `Requires Validation` |
| [02. Command-Line Upload and Transfer Indicators](#cs-ta0010-002) | `CS-TA0010-002` | T1048 / T1567 (contextual) | `Requires Validation` |
| [03. Upload-Related Falcon Event Inventory](#cs-ta0010-003) | `CS-TA0010-003` | T1041 (context) | `Requires Validation` |
| [04. FTP Command Event Telemetry](#cs-ta0010-004) | `CS-TA0010-004` | T1048 | `Requires Validation` |
| [05. SRU Network and Application Usage](#cs-ta0010-005) | `CS-TA0010-005` | T1041 (coverage context) | `Requires Validation` |
| [06. Outbound Network Destination Event Counts](#cs-ta0010-006) | `CS-TA0010-006` | T1041 (lead) | `Requires Validation` |
| [07. Transfer and Cloud Upload Command Indicators](#cs-ta0010-007) | `CS-TA0010-007` | T1041 / T1567 | `Requires Validation` |

---

<a name="cs-ta0010-001"></a>

### 01. Sensitive File Access Followed by External Connection

Correlates sensitive file access with network connections sharing aid and ContextProcessId within 30 minutes.

**Query ID:** `CS-TA0010-001` · **Platform:** `Not scoped` · **Tags:** `File`, `Network`

**MITRE:** T1041 (potential) · **Status:** `Requires Validation`

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

```cql
correlate(
Sensitive: {#event_simpleName=ClassifiedSensitiveFileAccess
| aid=*
| ContextProcessId=*
} include:[ComputerName,UserName,FilePath,SensitiveFileClassification,ContextProcessId,aid],
Network: {#event_simpleName=NetworkConnectIP4
| !cidr(RemoteAddressIP4, subnet=["224.0.0.0/4", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "0.0.0.0/32"])
| ContextProcessId=*
| aid=*
} include:[ComputerName,RemoteAddressIP4,RemotePort,ContextBaseFileName,ContextProcessId,aid],
globalConstraints=[aid, ContextProcessId],sequence=true,within=30m,maxPerRoot=20)
| select([Sensitive.@timestamp,Sensitive.ComputerName,Sensitive.UserName,Sensitive.FilePath,Sensitive.SensitiveFileClassification,Network.@timestamp,Network.RemoteAddressIP4,Network.RemotePort,Network.ContextBaseFileName,Sensitive.ContextProcessId,Sensitive.aid])
| sort(Network.@timestamp, order=asc, limit=10000)
```

</details>

<a name="cs-ta0010-002"></a>

### 02. Command-Line Upload and Transfer Indicators

Surfaces usage of command-line transfer utilities and upload-oriented arguments.

**Query ID:** `CS-TA0010-002` · **Platform:** `Windows` · **Tags:** `Process`

**MITRE:** T1048 / T1567 (contextual) · **Status:** `Requires Validation`

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

```cql
#event_simpleName=ProcessRollup2 event_platform=Win
| CommandLine=/(rclone|megacmd|megasync|azcopy|aws\s+s3\s+(cp|sync)|curl\s+.*(\-T|\-F|--upload-file)|scp\s|sftp\s|winscp|ftp\s)/i
| select([@timestamp, aid, ComputerName, UserName, FileName, ParentBaseFileName, CommandLine])
| sort(@timestamp, order=desc, limit=1000)
```

</details>

<a name="cs-ta0010-003"></a>

### 03. Upload-Related Falcon Event Inventory

Surfaces events with upload-related names for semantic verification, not attribution of data theft.

**Query ID:** `CS-TA0010-003` · **Platform:** `Not scoped` · **Tags:** `Browser`

**MITRE:** T1041 (context) · **Status:** `Requires Validation`

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

```cql
#event_simpleName=/^(LfoUploadDataComplete|LfoUploadDataUnneeded|BrowserDownloadStarted|BrowserDownloadEnded)$/
| @rawstring=/(upload|transfer|filename|\.zip|\.7z)/i
| select([@timestamp, #event_simpleName, ComputerName, UserName, @rawstring, aid])
| sort(@timestamp, order=asc, limit=10000)
```

</details>

<a name="cs-ta0010-004"></a>

### 04. FTP Command Event Telemetry

Inspects FTP command telemetry that may support transfer investigations.

**Query ID:** `CS-TA0010-004` · **Platform:** `Not scoped` · **Tags:** `Network`, `Process`

**MITRE:** T1048 · **Status:** `Requires Validation`

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

```cql
#event_simpleName=/^(FtpCommand)$/
| select([@timestamp, #event_simpleName, ComputerName, UserName, @rawstring, aid])
| sort(@timestamp, order=asc, limit=10000)
```

</details>

<a name="cs-ta0010-005"></a>

### 05. SRU Network and Application Usage

Lists System Resource Usage event families for later byte-volume field mapping.

**Query ID:** `CS-TA0010-005` · **Platform:** `Not scoped` · **Tags:** `Network`, `SRU`

**MITRE:** T1041 (coverage context) · **Status:** `Requires Validation`

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

```cql
#event_simpleName=/^(SruNetworkDataUsage|SruApplicationResourceUsage)$/
| select([@timestamp, #event_simpleName, ComputerName, UserName, @rawstring, aid])
| sort(@timestamp, order=asc, limit=10000)
```

</details>

<a name="cs-ta0010-006"></a>

### 06. Outbound Network Destination Event Counts

Aggregates connection events by remote destination and associated process.

**Query ID:** `CS-TA0010-006` · **Platform:** `Not scoped` · **Tags:** `Network`

**MITRE:** T1041 (lead) · **Status:** `Requires Validation`

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

```cql
#event_simpleName=NetworkConnectIP4
| RemoteAddressIP4=*
| groupBy([ComputerName, RemoteAddressIP4, RemotePort, ContextBaseFileName], function=[count(as=NetworkEvents), min(@timestamp, as=FirstSeen), max(@timestamp, as=LastSeen)], limit=10000)
| sort(NetworkEvents, order=desc, limit=10000)
```

</details>

<a name="cs-ta0010-007"></a>

### 07. Transfer and Cloud Upload Command Indicators

Searches for common upload, synchronization and file-transfer commands.

**Query ID:** `CS-TA0010-007` · **Platform:** `Not scoped` · **Tags:** `Process`

**MITRE:** T1041 / T1567 · **Status:** `Requires Validation`

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

```cql
#event_simpleName=ProcessRollup2
| CommandLine=/rclone|megacmd|megasync|azcopy|aws\s+s3\s+(cp|sync)|curl\s+.*(\-T|\-F|--upload-file)|scp\s|sftp\s|winscp|ftp\s/i
| select([@timestamp, ComputerName, UserName, ParentBaseFileName, ImageFileName, CommandLine, TargetProcessId, aid])
| sort(@timestamp, order=asc, limit=10000)
```

</details>

---

`Requires Validation` = not yet tenant-validated · `Tested` = exact-version tested · `Production reviewed` = peer-reviewed with evidence.

[← Home](../README.md) · [All queries](../QUERY-CATALOG.md)
