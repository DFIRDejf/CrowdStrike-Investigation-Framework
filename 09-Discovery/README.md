# Discovery — CrowdStrike CQL

> **2 CQL entries** | CrowdStrike Falcon / NG-SIEM | MITRE: TA0007

Detect suspicious system, account, Active Directory and network enumeration.

> **Validation notice:** Entries marked *User-reported validated source* were provided as working queries, but publication copies were sanitized and must be re-tested. Entries marked *Candidate* and *Community-derived* have **not** been tested in this environment.

## Query Index

1. [Account and Domain Enumeration Commands](#01-account-and-domain-enumeration-commands)
2. [High Port Diversity by Destination](#02-high-port-diversity-by-destination)

---

## 01. Account and Domain Enumeration Commands

**Description:** Finds common Windows identity and domain enumeration commands.

**MITRE ATT&CK:** T1087 / T1069 / T1018\
**Origin:** OneNote-derived adaptation\
**Validation:** Candidate — requires validation in Falcon\
**Required telemetry:** ProcessRollup2

<details>
<summary><strong>If you want to see more details</strong></summary>

### Hunting Query (CQL)

```cql
#event_simpleName=ProcessRollup2 event_platform=Win
| CommandLine=/(whoami\s+\/all|net\s+(user|group|localgroup|view)|nltest\s|dsquery\s|adfind|ldapsearch|setspn\s|systeminfo)/i
| select([@timestamp, aid, ComputerName, UserName, ParentBaseFileName, FileName, CommandLine])
| sort(@timestamp, order=desc, limit=1000)
```

### False Positive Considerations

Helpdesk, inventory, domain administrators and diagnostic scripts.

### Investigation Guidance

Correlate a burst of commands under one process chain and identity.

</details>

---

## 02. High Port Diversity by Destination

**Description:** Identifies hosts that connect to many distinct remote ports on a destination; may indicate scanning or administration.

**MITRE ATT&CK:** T1046\
**Origin:** OneNote-derived adaptation\
**Validation:** Candidate — requires validation in Falcon\
**Required telemetry:** NetworkConnectIP4

<details>
<summary><strong>If you want to see more details</strong></summary>

### Hunting Query (CQL)

```cql
#event_simpleName=NetworkConnectIP4 event_platform=Win
| RemoteAddressIP4=*
| groupBy([aid, ComputerName, RemoteAddressIP4], function=[count(RemotePort, distinct=true, as=DistinctPorts), count(as=Connections)], limit=10000)
| DistinctPorts>=20
| sort(DistinctPorts, order=desc, limit=1000)
```

### False Positive Considerations

Vulnerability scanning, service discovery and monitoring.

### Investigation Guidance

Tune port threshold against approved scanners and time window.

</details>

---
