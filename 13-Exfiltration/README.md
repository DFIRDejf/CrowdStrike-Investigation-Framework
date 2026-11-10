# Exfiltration — CrowdStrike CQL

> **2 CQL entries** | CrowdStrike Falcon / NG-SIEM | MITRE: TA0010

Investigate suspicious outbound data movement and transfer utilities, including correlation with sensitive file access.

> **Validation notice:** Entries marked *User-reported validated source* were provided as working queries, but publication copies were sanitized and must be re-tested. Entries marked *Candidate* and *Community-derived* have **not** been tested in this environment.

## Query Index

1. [Sensitive File Access Followed by External Connection](#01-sensitive-file-access-followed-by-external-connection)
2. [Command-Line Upload and Transfer Indicators](#02-command-line-upload-and-transfer-indicators)

---

## 01. Sensitive File Access Followed by External Connection

**Description:** Correlates sensitive file access with network connections sharing aid and ContextProcessId within 30 minutes.

**MITRE ATT&CK:** T1041 (potential)\
**Origin:** Previously supplied CQL — sanitized migration copy\
**Validation:** User-reported validated source; revalidate sanitized copy\
**Required telemetry:** See event filters in query

<details>
<summary><strong>If you want to see more details</strong></summary>

### Hunting Query (CQL)

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

### False Positive Considerations

Organizational CIDRs were removed; restore approved internal/excluded ranges in your private deployment. Temporal correlation is not proof of file transfer.

### Investigation Guidance

Scope by host, user and narrow time window; pivot to process tree and nearby evidence before concluding malicious activity.

</details>

---

## 02. Command-Line Upload and Transfer Indicators

**Description:** Surfaces usage of command-line transfer utilities and upload-oriented arguments.

**MITRE ATT&CK:** T1048 / T1567 (contextual)\
**Origin:** OneNote-derived adaptation\
**Validation:** Candidate — requires validation in Falcon\
**Required telemetry:** ProcessRollup2

<details>
<summary><strong>If you want to see more details</strong></summary>

### Hunting Query (CQL)

```cql
#event_simpleName=ProcessRollup2 event_platform=Win
| CommandLine=/(rclone|megacmd|megasync|azcopy|aws\s+s3\s+(cp|sync)|curl\s+.*(\-T|\-F|--upload-file)|scp\s|sftp\s|winscp|ftp\s)/i
| select([@timestamp, aid, ComputerName, UserName, FileName, ParentBaseFileName, CommandLine])
| sort(@timestamp, order=desc, limit=1000)
```

### False Positive Considerations

Enterprise data transfers, DevOps pipelines and legitimate file synchronization.

### Investigation Guidance

Correlate process access to sensitive files and approved external destinations.

</details>

---
