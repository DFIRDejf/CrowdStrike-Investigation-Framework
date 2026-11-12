# Hunt Name — CrowdStrike CQL

**Query ID:** Assigned by `scripts/catalog.py --write` — do not manually reuse an existing ID  
**Category:** Choose one ATT&CK tactic or operational module  
**MITRE:** TXXXX (only with evidence) · **Status:** `Requires Validation`

One-sentence hunting hypothesis and a description of what the query can or cannot establish.

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

```cql
#event_simpleName=ProcessRollup2
| select([@timestamp, ComputerName, FileName, CommandLine])
```

**False positives:** List plausible benign causes.  
**Investigation guidance:** Describe supporting evidence, context and pivots.

</details>

## Review notes (for PR discussion)

- Required telemetry and any verified Falcon fieldsets
- Expected environment-specific parameters and time window
- False-positive considerations; avoid unsupported exclusions
- Validation owner, evidence and date before changing status to `Tested`
