# Initial Access — CrowdStrike CQL

> **1 CQL entries** | CrowdStrike Falcon / NG-SIEM | MITRE: TA0001

Investigate potential entry vectors and suspicious downloads using available endpoint and browser telemetry.

> **Validation notice:** Entries marked *User-reported validated source* were provided as working queries, but publication copies were sanitized and must be re-tested. Entries marked *Candidate* and *Community-derived* have **not** been tested in this environment.

## Query Index

1. [Potentially Risky Browser Downloads](#01-potentially-risky-browser-downloads)

---

## 01. Potentially Risky Browser Downloads

**Description:** Surfaces browser download events involving executable, script or archive extensions. This is a lead generator rather than malware confirmation.

**MITRE ATT&CK:** T1189 / T1204 (contextual)\
**Origin:** OneNote-derived adaptation\
**Validation:** Candidate — requires validation in Falcon\
**Required telemetry:** BrowserDownloadStarted, BrowserDownloadEnded

<details>
<summary><strong>If you want to see more details</strong></summary>

### Hunting Query (CQL)

```cql
#event_simpleName=/^(BrowserDownloadStarted|BrowserDownloadEnded)$/
| Url=/\.(exe|msi|dll|zip|7z|rar|ps1|bat|cmd|vbs|js)([?#]|$)/i
| select([@timestamp, #event_simpleName, ComputerName, UserName, Url, FileName, aid])
| sort(@timestamp, order=desc, limit=1000)
```

### False Positive Considerations

Software installation, IT support downloads and development activity. Validate `Url` and `FileName` against your fieldsets.

### Investigation Guidance

Correlate download telemetry with ProcessRollup2, file writes and user context.

</details>

---
