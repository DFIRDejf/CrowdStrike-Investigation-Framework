[← Framework home](../README.md)

# Initial Access

**CrowdStrike Falcon / NG-SIEM**  ·  **CQL**  ·  `TA0001`  ·  **1 queries**

Spot entry-point activity and potentially risky downloads.

---

## Query library

| Hunt | Status |
|---|---|
| [01. Potentially Risky Browser Downloads](#01-potentially-risky-browser-downloads) | `Candidate` |

---

### 01. Potentially Risky Browser Downloads

Surfaces browser download events involving executable, script or archive extensions. This is a lead generator rather than malware confirmation.

**MITRE:** T1189 / T1204 (contextual)\  ·  **Telemetry:** BrowserDownloadStarted, BrowserDownloadEnded

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

*Origin: OneNote-derived adaptation\*

</details>

---

`Migration recheck` = original supplied query was previously tested, but this publication copy needs validation. `Candidate` / `Community candidate` = not validated in the target Falcon environment.

[← Back to framework](../README.md)
