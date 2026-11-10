[← Framework home](../README.md)

# Discovery

**CrowdStrike Falcon / NG-SIEM**  ·  **CQL**  ·  `TA0007`  ·  **2 queries**

Identify host, network, and Active Directory enumeration.

---

## Query library

| Hunt | Status |
|---|---|
| [01. Account and Domain Enumeration Commands](#01-account-and-domain-enumeration-commands) | `Candidate` |
| [02. High Port Diversity by Destination](#02-high-port-diversity-by-destination) | `Candidate` |

---

### 01. Account and Domain Enumeration Commands

Finds common Windows identity and domain enumeration commands.

**MITRE:** T1087 / T1069 / T1018\  ·  **Telemetry:** ProcessRollup2

<details>
<summary><strong>If you want to see more details</strong></summary>

```cql
#event_simpleName=ProcessRollup2 event_platform=Win
| CommandLine=/(whoami\s+\/all|net\s+(user|group|localgroup|view)|nltest\s|dsquery\s|adfind|ldapsearch|setspn\s|systeminfo)/i
| select([@timestamp, aid, ComputerName, UserName, ParentBaseFileName, FileName, CommandLine])
| sort(@timestamp, order=desc, limit=1000)
```

**False positives:** Helpdesk, inventory, domain administrators and diagnostic scripts.

**Analyst pivot:** Correlate a burst of commands under one process chain and identity.

*Origin: OneNote-derived adaptation\*

</details>

### 02. High Port Diversity by Destination

Identifies hosts that connect to many distinct remote ports on a destination; may indicate scanning or administration.

**MITRE:** T1046\  ·  **Telemetry:** NetworkConnectIP4

<details>
<summary><strong>If you want to see more details</strong></summary>

```cql
#event_simpleName=NetworkConnectIP4 event_platform=Win
| RemoteAddressIP4=*
| groupBy([aid, ComputerName, RemoteAddressIP4], function=[count(RemotePort, distinct=true, as=DistinctPorts), count(as=Connections)], limit=10000)
| DistinctPorts>=20
| sort(DistinctPorts, order=desc, limit=1000)
```

**False positives:** Vulnerability scanning, service discovery and monitoring.

**Analyst pivot:** Tune port threshold against approved scanners and time window.

*Origin: OneNote-derived adaptation\*

</details>

---

`Migration recheck` = original supplied query was previously tested, but this publication copy needs validation. `Candidate` / `Community candidate` = not validated in the target Falcon environment.

[← Back to framework](../README.md)
