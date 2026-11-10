[← Framework home](../README.md)

# Exfiltration

**CrowdStrike Falcon / NG-SIEM**  ·  **CQL**  ·  `TA0010`  ·  **2 queries**

Investigate sensitive file access and suspicious outbound transfer patterns.

---

## Query library

| Hunt | Status |
|---|---|
| [01. Sensitive File Access Followed by External Connection](#01-sensitive-file-access-followed-by-external-connection) | `Migration recheck` |
| [02. Command-Line Upload and Transfer Indicators](#02-command-line-upload-and-transfer-indicators) | `Candidate` |

---

### 01. Sensitive File Access Followed by External Connection

Correlates sensitive file access with network connections sharing aid and ContextProcessId within 30 minutes.

**MITRE:** T1041 (potential)\

<details>
<summary><strong>If you want to see more details</strong></summary>

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

**False positives:** Organizational CIDRs were removed; restore approved internal/excluded ranges in your private deployment. Temporal correlation is not proof of file transfer.

**Analyst pivot:** Scope by host, user and narrow time window; pivot to process tree and nearby evidence before concluding malicious activity.

</details>

### 02. Command-Line Upload and Transfer Indicators

Surfaces usage of command-line transfer utilities and upload-oriented arguments.

**MITRE:** T1048 / T1567 (contextual)\  ·  **Telemetry:** ProcessRollup2

<details>
<summary><strong>If you want to see more details</strong></summary>

```cql
#event_simpleName=ProcessRollup2 event_platform=Win
| CommandLine=/(rclone|megacmd|megasync|azcopy|aws\s+s3\s+(cp|sync)|curl\s+.*(\-T|\-F|--upload-file)|scp\s|sftp\s|winscp|ftp\s)/i
| select([@timestamp, aid, ComputerName, UserName, FileName, ParentBaseFileName, CommandLine])
| sort(@timestamp, order=desc, limit=1000)
```

**False positives:** Enterprise data transfers, DevOps pipelines and legitimate file synchronization.

**Analyst pivot:** Correlate process access to sensitive files and approved external destinations.

*Origin: OneNote-derived adaptation\*

</details>

---

`Migration recheck` = original supplied query was previously tested, but this publication copy needs validation. `Candidate` / `Community candidate` = not validated in the target Falcon environment.

[← Back to framework](../README.md)
