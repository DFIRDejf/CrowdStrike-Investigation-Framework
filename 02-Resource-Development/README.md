[← Framework home](../README.md)

# Resource Development

**CrowdStrike Falcon / NG-SIEM**  ·  **CQL**  ·  `TA0042`  ·  **3 queries**

Track adversary preparation and infrastructure signals where enterprise data provides visibility.

---

## Query library

| Hunt | Status |
|---|---|
| [01. Browser Downloads of Executables and Archives](#01-browser-downloads-of-executables-and-archives) | `Requires Validation` |
| [02. Penetration Testing Utility Execution](#02-penetration-testing-utility-execution) | `Requires Validation` |
| [03. Suspicious Browser Download URL Extensions](#03-suspicious-browser-download-url-extensions) | `Requires Validation` |

---


### 01. Browser Downloads of Executables and Archives

Searches browser telemetry for potentially downloaded scripts, archives and executables.

**MITRE:** T1588 (context)  ·  **Source:** `CS Queries.one`  ·  **Status:** `Requires Validation`

<details>
<summary><strong>If you want to see more details</strong></summary>

```cql
#event_simpleName=/^(BrowserDownloadStarted|BrowserDownloadEnded)$/
| @rawstring=/(\.exe|\.zip|\.ps1|\.7z|\.rar|\.msi)/i
| select([@timestamp, #event_simpleName, ComputerName, UserName, @rawstring, aid])
| sort(@timestamp, order=asc, limit=10000)
```

**False positives:** Routine software delivery; downloads do not prove adversary procurement.

**Validation:** Confirm event and field availability and expected semantics in Falcon. [DO WERYFIKACJI W ŚRODOWISKU]

</details>

### 02. Penetration Testing Utility Execution

Identifies execution command lines referencing known offensive tooling.

**MITRE:** T1588 (context)  ·  **Source:** `CS Queries.one`  ·  **Status:** `Requires Validation`

<details>
<summary><strong>If you want to see more details</strong></summary>

```cql
#event_simpleName=ProcessRollup2
| CommandLine=/nmap|bloodhound|sharphound|rubeus|impacket|metasploit|mimikatz/i
| select([@timestamp, ComputerName, UserName, ParentBaseFileName, ImageFileName, CommandLine, TargetProcessId, aid])
| sort(@timestamp, order=asc, limit=10000)
```

**False positives:** Authorized red teams and legitimate security testing.

**Validation:** Confirm event and field availability and expected semantics in Falcon. [DO WERYFIKACJI W ŚRODOWISKU]

</details>

### 03. Suspicious Browser Download URL Extensions

Reviews download URL extensions frequently associated with deployable tools.

**MITRE:** T1588 (context)  ·  **Source:** `CS Queries.one`  ·  **Status:** `Requires Validation`

<details>
<summary><strong>If you want to see more details</strong></summary>

```cql
#event_simpleName=/^(BrowserDownloadStarted|BrowserDownloadEnded)$/
| Url=/\.(exe|zip|ps1|7z|rar|msi|dll|sys|bat|cmd|psm1|vbs|py|sh|tar|gz)([?#]|$)/i
| select([@timestamp, ComputerName, UserName, Url, aid])
| sort(@timestamp, order=asc, limit=10000)
```

**False positives:** Package managers, vendor software updates and normal file transfers.

**Validation:** Confirm event and field availability and expected semantics in Falcon. [DO WERYFIKACJI W ŚRODOWISKU]

</details>

[← Back to framework](../README.md)
