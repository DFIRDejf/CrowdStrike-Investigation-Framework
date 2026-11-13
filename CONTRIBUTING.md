# Contributing to CrowdStrike Threat Hunting Framework

[← Framework home](README.md) · [Query Catalog](QUERY-CATALOG.md) · [MITRE Technique Index](MITRE-TECHNIQUE-INDEX.md) · [Telemetry Index](TELEMETRY-INDEX.md)

This is a **Markdown-only CQL hunting library**. No Python, build step, GitHub Actions, or external service is needed to read, copy, or maintain queries.

## Add or improve a hunt

1. Check the [Query Catalog](QUERY-CATALOG.md), [MITRE Technique Index](MITRE-TECHNIQUE-INDEX.md), and [Telemetry Index](TELEMETRY-INDEX.md) for overlapping hunts.
2. Choose the appropriate ATT&CK tactic README. Add a numbered section using `### NN. Query title`, preserving the numbering format.
3. Give the new query a **unique permanent ID** such as `CS-TA0008-012` (use the next unused ID for that category). Include `<a name="cs-ta0008-012"></a>` immediately above the heading and `**Query ID:** `CS-TA0008-012`` in its metadata. **Never recycle an existing ID**, even when renaming a query.
4. Include a concise hypothesis, an evidence-backed MITRE technique mapping, platform/telemetry information where known, and the status `Requires Validation`. Add exactly one expandable `<details>` section with summary **Show CrowdStrike query**, a fenced `cql` code block, false-positive considerations, and investigation guidance.
5. Manually update the category index, [Query Catalog](QUERY-CATALOG.md), [MITRE Technique Index](MITRE-TECHNIQUE-INDEX.md), [Telemetry Index](TELEMETRY-INDEX.md), and the query counts in the root `README.md`. Remove outdated entries when renaming or moving a hunt, without changing its permanent ID.
6. Review all relative Markdown links and stable anchors on GitHub. Confirm that the existing CQL blocks have not been modified unintentionally.
7. Submit a Pull Request with a short description of the hypothesis, affected categories, and validation status.

## Query section example

````markdown
<a name="cs-ta0008-012"></a>

### 12. Example SMB Investigation

One-sentence hunting hypothesis and limitations.

**Query ID:** `CS-TA0008-012` · **Platform:** `Not scoped` · **Tags:** `SMB`

**MITRE:** T1021.002 · **Status:** `Requires Validation`

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

```cql
#event_simpleName=SmbServerShareOpenedEtw
| select([@timestamp, ComputerName, aid])
```

**False positives:** Review approved file sharing.

**Investigation guidance:** Correlate the host and session context.

</details>
````

The example is illustrative, not guaranteed to run in every Falcon environment. Verify field availability using your own telemetry.

## Validation and security

- **Requires Validation:** No confirmed successful execution of the exact published query in the target tenant.
- **Tested:** Exact version executed and results checked with recorded evidence.
- **Production reviewed:** Peer-reviewed, with documented false positives, performance, and triage guidance.
- MITRE mappings and telemetry tags describe the hypothesis, **not** verified production coverage.
- Do not commit corporate hostnames, employee identifiers, internal allowlists, private addresses, credentials, tokens, CIDs or incident evidence.
- Do not add outbound tracking assets or executable CI workflows.
- Credit external source material in [Source and Provenance](docs/SOURCE-AND-PROVENANCE.md); do not copy third-party code if redistribution terms are unclear.

## Maintenance checklist

Because the repository is static Markdown, reviewers must manually confirm query counts, unique IDs, category index rows, catalog deep links, MITRE references, and telemetry-index references on each PR. Prioritize correctness over additional automation.
