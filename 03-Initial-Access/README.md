[← Home](../README.md) · [All queries](../QUERY-CATALOG.md)

# Initial Access

**CrowdStrike Falcon / NG-SIEM**  ·  **CQL**  ·  `TA0001`  ·  **5 queries**

Spot entry-point activity and potentially risky downloads.

---

## Query library

| Hunt | MITRE | Status |
|:--|:--|:--|
| [01. Potentially Risky Browser Downloads](#01-potentially-risky-browser-downloads) | T1189 / T1204 (contextual) | `Candidate` |
| [02. Failed SSO Authentication Event Inventory](#02-failed-sso-authentication-event-inventory) | T1110 | `Requires Validation` |
| [03. VPN and Identity Sign-In Event Inventory](#03-vpn-and-identity-sign-in-event-inventory) | T1133 / T1078 | `Requires Validation` |
| [04. Domain Interactive Logon Events](#04-domain-interactive-logon-events) | T1078 | `Requires Validation` |
| [05. Remote Access Client Execution](#05-remote-access-client-execution) | T1133 (context) | `Requires Validation` |

---

### 01. Potentially Risky Browser Downloads

Surfaces browser download events involving executable, script or archive extensions. This is a lead generator rather than malware confirmation.

**MITRE:** T1189 / T1204 (contextual)  ·  **Telemetry:** BrowserDownloadStarted, BrowserDownloadEnded

<details>
<summary><strong>If you want to see more details</strong></summary>

```cql
#event_simpleName=/^(BrowserDownloadStarted|BrowserDownloadEnded)$/
| Url=/\.(exe|msi|dll|zip|7z|rar|ps1|bat|cmd|vbs|js)([?#]|$)/i
| select([@timestamp, #event_simpleName, ComputerName, UserName, Url, FileName, aid])
| sort(@timestamp, order=desc, limit=1000)
```

**False positives:** Software installation, IT support downloads and development activity. Validate `Url` and `FileName` against your fieldsets.

**Analyst pivot:** Correlate download telemetry with ProcessRollup2, file writes and user context.

*Origin: OneNote-derived adaptation*

</details>

### 02. Failed SSO Authentication Event Inventory

Inspects identity provider authentication failures without hardcoded user identifiers.

**MITRE:** T1110  ·  **Source:** `CS Queries.one`  ·  **Status:** `Requires Validation`

<details>
<summary><strong>If you want to see more details</strong></summary>

```cql
#event_simpleName=/^(SsoUserLogonFailure|SsoApplicationAccessFailure)$/
| select([@timestamp, #event_simpleName, ComputerName, UserName, @rawstring, aid])
| sort(@timestamp, order=asc, limit=10000)
```

**False positives:** Mistyped passwords and expected SSO errors.

**Validation:** Confirm event and field availability and expected semantics in Falcon. [DO WERYFIKACJI W ŚRODOWISKU]

</details>

### 03. VPN and Identity Sign-In Event Inventory

Surfaces SSO, IdP and domain logon event families for focused follow-up.

**MITRE:** T1133 / T1078  ·  **Source:** `CS Queries.one`  ·  **Status:** `Requires Validation`

<details>
<summary><strong>If you want to see more details</strong></summary>

```cql
#event_simpleName=/^(SsoUserLogonFailure|SsoApplicationAccessFailure|IoSessionLoggedOn|IdpTelemetryData|ActiveDirectoryInteractiveDomainLogon)$/
| select([@timestamp, #event_simpleName, ComputerName, UserName, @rawstring, aid])
| sort(@timestamp, order=asc, limit=10000)
```

**False positives:** Normal corporate remote access; check outcome and IP semantics.

**Validation:** Confirm event and field availability and expected semantics in Falcon. [DO WERYFIKACJI W ŚRODOWISKU]

</details>

### 04. Domain Interactive Logon Events

Collects interactive logon telemetry for identity-based investigations.

**MITRE:** T1078  ·  **Source:** `CS Queries.one`  ·  **Status:** `Requires Validation`

<details>
<summary><strong>If you want to see more details</strong></summary>

```cql
#event_simpleName=/^(ActiveDirectoryInteractiveDomainLogon|IoSessionLoggedOn)$/
| select([@timestamp, #event_simpleName, ComputerName, UserName, @rawstring, aid])
| sort(@timestamp, order=asc, limit=10000)
```

**False positives:** Routine sign-ins; correlate with source and destination.

**Validation:** Confirm event and field availability and expected semantics in Falcon. [DO WERYFIKACJI W ŚRODOWISKU]

</details>

### 05. Remote Access Client Execution

Looks for use of remote access and VPN clients.

**MITRE:** T1133 (context)  ·  **Source:** `CS Queries.one`  ·  **Status:** `Requires Validation`

<details>
<summary><strong>If you want to see more details</strong></summary>

```cql
#event_simpleName=ProcessRollup2
| CommandLine=/mstsc|openvpn|globalprotect|anyconnect|forticlient|pulse\ssecure|zscaler|rasdial|ssh\s/i
| select([@timestamp, ComputerName, UserName, ParentBaseFileName, ImageFileName, CommandLine, TargetProcessId, aid])
| sort(@timestamp, order=asc, limit=10000)
```

**False positives:** Approved corporate VPN access and remote support.

**Validation:** Confirm event and field availability and expected semantics in Falcon. [DO WERYFIKACJI W ŚRODOWISKU]

</details>


---

`Migration recheck` = original supplied query was previously tested, but this publication copy needs validation. `Candidate` / `Community candidate` = not validated in the target Falcon environment.

[← Home](../README.md) · [All queries](../QUERY-CATALOG.md)
