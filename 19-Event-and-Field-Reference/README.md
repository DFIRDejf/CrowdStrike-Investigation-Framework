[← Framework home](../README.md)

# Event and Field Reference

**CrowdStrike Falcon / NG-SIEM**  ·  **CQL**  ·  `Reference`  ·  **Reference**

Find the event families and field relationships needed for effective hunts.

---

> Field availability and direction must be verified in the target Falcon tenant.

## Event families

| Family | Examples | Useful investigative questions |
|---|---|---|
| Process execution | `ProcessRollup2`, `EndOfProcess` | Who launched what and under which parent? |
| Command / script | `CommandHistory`, `ScriptControlDetectInfo`, `RemoteCommandResponse` | What commands/scripts were observed? |
| Network | `NetworkConnectIP4`, `NetworkReceiveAcceptIP4` | Which process initiated outbound or accepted inbound traffic? |
| DNS | `DnsRequest` | Which domains are associated with processes? |
| SMB | `SmbServerV1AuditEtw`, `SmbServerShareOpenedEtw`, `SmbClientShareOpenedEtw` | Which share accesses occurred? |
| Download | `BrowserDownloadStarted`, `BrowserDownloadEnded` | Which URLs/extensions were downloaded? |
| Sensitive file access | `ClassifiedSensitiveFileAccess`, `CriticalFileAccessed` | What data classification was accessed? |
| Scheduled / autorun | `ScheduledTaskInfo`, `AutoRunProcessInfo` | Which tasks or startup entries appear? |
| Registry | `RegGenericInfo`, `RegistryOperationDetectInfo` | Which registry changes occurred? |
| Forensic | `FileInfo`, `USNRecord`, `PrefetchFile`, `PeFileWritten` | What file-system and execution artifacts exist? |

## Field relationships

| Purpose | Process-side field | Secondary-event field | Notes |
|---|---|---|---|
| Endpoint identity | `aid` | `aid` | Include in correlations to avoid cross-agent collisions |
| Process identity | `TargetProcessId` | `ContextProcessId` | Compare as strings/identifiers in a single sensor scope |
| Host | `ComputerName` | `ComputerName` | Do not assume every event family contains it |
| User | `UserName` | `UserName` | Use other user fields only after fieldset validation |
| Network remote address | — | `RemoteAddressIP4` | Validate inbound/outbound perspective per event type |
| Network port | — | `RemotePort` | Meaning changes by event family |
| Process command | `CommandLine` | — | Not all telemetry includes full command lines |

## Field inspection patterns

### Fieldset

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

```cql
#event_simpleName=NetworkConnectIP4
| fieldset()
```

Repeat for each source family. Do not guess fields based on names from other products or event types.

</details>

### Normalized inbound/outbound IPs

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

```cql
#event_simpleName=/^(NetworkConnectIP4|NetworkReceiveAcceptIP4)$/
| case {
    #event_simpleName=NetworkConnectIP4
      | SourceIP:=LocalAddressIP4
      | DestinationIP:=RemoteAddressIP4
      | Direction:="Outbound";
    #event_simpleName=NetworkReceiveAcceptIP4
      | SourceIP:=RemoteAddressIP4
      | DestinationIP:=LocalAddressIP4
      | Direction:="Inbound";
  }
| select([@timestamp, #event_simpleName, ComputerName, SourceIP, DestinationIP, Direction, aid])
```

**Candidate:** confirm the IP meaning in each raw event using the actual fieldset and packet/context telemetry; do not rely solely on field naming.

</details>

**Before publishing:** inspect `fieldset()`, verify event semantics, and check null rates across representative hosts.

[← Back to framework](../README.md)
