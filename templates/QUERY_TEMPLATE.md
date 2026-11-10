# Query Title — CrowdStrike CQL

**Category:** Example category  \n**Description:** Explain the observable behavior and analytical question.  \n**MITRE ATT&CK:** TXXXX (only when justified)  \n**Origin:** Original / OneNote / Community research + URL  \n**Validation:** Candidate — requires validation in Falcon  \n**Telemetry:** #event_simpleName and confirmed fields  \n**Owner:** TEAM / ROLE  \n**Last tested:** YYYY-MM-DD or Not tested

<details>
<summary><strong>If you want to see more details</strong></summary>

### Hunting Query (CQL)

```cql
#event_simpleName=ProcessRollup2 event_platform=Win
| select([@timestamp, ComputerName, FileName, CommandLine])
```

### False Positive Considerations

Describe expected legitimate scenarios and validated exclusions.

### Investigation Guidance

Describe evidence, triage pivots and limitations.

</details>
