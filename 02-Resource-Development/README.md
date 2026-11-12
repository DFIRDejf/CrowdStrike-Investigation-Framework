[← Home](../README.md) · [All queries](../QUERY-CATALOG.md)

# Resource Development

**CrowdStrike Falcon / NG-SIEM**  ·  **CQL**  ·  `TA0042`  ·  **3 queries**

Track adversary preparation and infrastructure signals where enterprise data provides visibility.

---

## Query library

| Hunt | ID | MITRE | Status |
|:--|:--|:--|:--|
| [01. Browser Downloads of Executables and Archives](#cs-ta0042-001) | `CS-TA0042-001` | T1588 (context) | `Requires Validation` |
| [02. Penetration Testing Utility Execution](#cs-ta0042-002) | `CS-TA0042-002` | T1588 (context) | `Requires Validation` |
| [03. Suspicious Browser Download URL Extensions](#cs-ta0042-003) | `CS-TA0042-003` | T1588 (context) | `Requires Validation` |

---

<a name="cs-ta0042-001"></a>

### 01. Browser Downloads of Executables and Archives

Searches browser telemetry for potentially downloaded scripts, archives and executables.

**Query ID:** `CS-TA0042-001` · **Platform:** `Not scoped` · **Tags:** `Browser`

**MITRE:** T1588 (context) · **Status:** `Requires Validation`

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

```cql
#event_simpleName=/^(BrowserDownloadStarted|BrowserDownloadEnded)$/
| @rawstring=/(\.exe|\.zip|\.ps1|\.7z|\.rar|\.msi)/i
| select([@timestamp, #event_simpleName, ComputerName, UserName, @rawstring, aid])
| sort(@timestamp, order=asc, limit=10000)
```

**False positives:** Routine software delivery; downloads do not prove adversary procurement.

**Validation:** Confirm event and field availability and expected semantics in Falcon. [DO WERYFIKACJI W ŚRODOWISKU]

</details>

<a name="cs-ta0042-002"></a>

### 02. Penetration Testing Utility Execution

Identifies execution command lines referencing known offensive tooling.

**Query ID:** `CS-TA0042-002` · **Platform:** `Not scoped` · **Tags:** `Process`

**MITRE:** T1588 (context) · **Status:** `Requires Validation`

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

```cql
#event_simpleName=ProcessRollup2
| CommandLine=/nmap|bloodhound|sharphound|rubeus|impacket|metasploit|mimikatz/i
| select([@timestamp, ComputerName, UserName, ParentBaseFileName, ImageFileName, CommandLine, TargetProcessId, aid])
| sort(@timestamp, order=asc, limit=10000)
```

**False positives:** Authorized red teams and legitimate security testing.

**Validation:** Confirm event and field availability and expected semantics in Falcon. [DO WERYFIKACJI W ŚRODOWISKU]

</details>

<a name="cs-ta0042-003"></a>

### 03. Suspicious Browser Download URL Extensions

Reviews download URL extensions frequently associated with deployable tools.

**Query ID:** `CS-TA0042-003` · **Platform:** `Not scoped` · **Tags:** `Browser`

**MITRE:** T1588 (context) · **Status:** `Requires Validation`

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

```cql
#event_simpleName=/^(BrowserDownloadStarted|BrowserDownloadEnded)$/
| Url=/\.(exe|zip|ps1|7z|rar|msi|dll|sys|bat|cmd|psm1|vbs|py|sh|tar|gz)([?#]|$)/i
| select([@timestamp, ComputerName, UserName, Url, aid])
| sort(@timestamp, order=asc, limit=10000)
```

**False positives:** Package managers, vendor software updates and normal file transfers.

**Validation:** Confirm event and field availability and expected semantics in Falcon. [DO WERYFIKACJI W ŚRODOWISKU]

</details>

[← Home](../README.md) · [All queries](../QUERY-CATALOG.md)
