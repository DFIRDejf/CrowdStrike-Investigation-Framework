[← Home](../README.md) · [All queries](../QUERY-CATALOG.md)

# Initial Access

**CrowdStrike Falcon / NG-SIEM**  ·  **CQL**  ·  `TA0001`  ·  **5 queries**

Spot entry-point activity and potentially risky downloads.

---

## Query library

| Hunt | ID | MITRE | Status |
|:--|:--|:--|:--|
| [01. Potentially Risky Browser Downloads](#cs-ta0001-001) | `CS-TA0001-001` | T1189 / T1204 | `Production reviewed` |
| [02. Failed SSO Authentication Event Inventory](#cs-ta0001-002) | `CS-TA0001-002` | T1110 | `Production reviewed` |
| [03. VPN and Identity Sign-In Event Inventory](#cs-ta0001-003) | `CS-TA0001-003` | T1133 / T1078 | `Tested` |
| [04. Domain Interactive Logon Events](#cs-ta0001-004) | `CS-TA0001-004` | T1078 | `Tested` |
| [05. Remote Access Client Execution](#cs-ta0001-005) | `CS-TA0001-005` | T1133 | `Tested` |

---

<a name="cs-ta0001-001"></a>

### 01. Potentially Risky Browser Downloads

Surfaces browser download events involving executable, script or archive extensions. This is a lead generator rather than malware confirmation.

**Query ID:** `CS-TA0001-001` · **Platform:** `Not scoped` · **Tags:** `Browser`

**MITRE:** T1189 / T1204 (contextual) · **Status:** `Production reviewed`

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

```cql
#event_simpleName=/^(BrowserDownloadStarted|BrowserDownloadEnded)$/
| Url=/\.(exe|msi|dll|zip|7z|rar|ps1|bat|cmd|vbs|js)([?#]|$)/i
| select([@timestamp, #event_simpleName, ComputerName, UserName, Url, FileName, aid])
| sort(@timestamp, order=desc, limit=1000)
```

</details>

---

<a name="cs-ta0001-002"></a>

### 02. Failed SSO Authentication Event Inventory

Inspects identity provider authentication failures without hardcoded user identifiers.

**Query ID:** `CS-TA0001-002` · **Platform:** `Not scoped` · **Tags:** `Identity`

**MITRE:** T1110 · **Status:** `Production reviewed`

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

```cql
#event_simpleName=/^(SsoUserLogonFailure|SsoApplicationAccessFailure)$/
| select([@timestamp, #event_simpleName, ComputerName, UserName, @rawstring, aid])
| sort(@timestamp, order=asc, limit=10000)
```

</details>

---

<a name="cs-ta0001-003"></a>

### 03. VPN and Identity Sign-In Event Inventory

Surfaces SSO, IdP and domain logon event families for focused follow-up.

**Query ID:** `CS-TA0001-003` · **Platform:** `Not scoped` · **Tags:** `Identity`

**MITRE:** T1133 / T1078 · **Status:** `Tested`

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

```cql
#event_simpleName=/^(SsoUserLogonFailure|SsoApplicationAccessFailure|IoSessionLoggedOn|IdpTelemetryData|ActiveDirectoryInteractiveDomainLogon)$/
| select([@timestamp, #event_simpleName, ComputerName, UserName, @rawstring, aid])
| sort(@timestamp, order=asc, limit=10000)
```

</details>

---

<a name="cs-ta0001-004"></a>

### 04. Domain Interactive Logon Events

Collects interactive logon telemetry for identity-based investigations.

**Query ID:** `CS-TA0001-004` · **Platform:** `Not scoped` · **Tags:** `Identity`

**MITRE:** T1078 · **Status:** `Tested`

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

```cql
#event_simpleName=/^(ActiveDirectoryInteractiveDomainLogon|IoSessionLoggedOn)$/
| select([@timestamp, #event_simpleName, ComputerName, UserName, @rawstring, aid])
| sort(@timestamp, order=asc, limit=10000)
```

</details>

---

<a name="cs-ta0001-005"></a>

### 05. Remote Access Client Execution

Looks for use of remote access and VPN clients.

**Query ID:** `CS-TA0001-005` · **Platform:** `Not scoped` · **Tags:** `Process`

**MITRE:** T1133 (context) · **Status:** `Tested`

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

```cql
#event_simpleName=ProcessRollup2
| CommandLine=/mstsc|openvpn|globalprotect|anyconnect|forticlient|pulse\ssecure|rasdial|ssh\s/i
| select([@timestamp, ComputerName, UserName, ParentBaseFileName, ImageFileName, CommandLine, TargetProcessId, aid])
| sort(@timestamp, order=asc, limit=10000)
```

</details>

---

`Requires Validation` = not yet tenant-validated · `Tested` = exact-version tested · `Production reviewed` = peer-reviewed with evidence.

[← Home](../README.md) · [All queries](../QUERY-CATALOG.md)
