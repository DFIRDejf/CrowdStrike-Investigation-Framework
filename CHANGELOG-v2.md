# CHANGELOG — v2 GitHub Integration Pack

**Date:** 2026-11-10\
**Scope:** category query libraries, helper modules, and updates to the existing repository navigation.

## Counts

- **53 CQL entries** in **15 query-bearing categories**, including **18 migrated** from the previous pack, **35 newly authored** examples.
- **30** OneNote-derived hunting/helpers, **5** Cool Query Friday inspired examples.
- **21** category and module links in the main navigation, including the two existing category placeholders.
- **No `15-Investigation-Timelines` folder or navigation entry.**

## 1. Query-bearing categories

| Folder | Total entries | New entries |
|---|---:|---:|
| `03-Initial-Access` | 1 | 1 |
| `04-Execution` | 7 | 4 |
| `05-Persistence` | 3 | 2 |
| `06-Privilege-Escalation` | 1 | 1 |
| `07-Defense-Evasion` | 2 | 2 |
| `08-Credential-Access` | 3 | 3 |
| `09-Discovery` | 2 | 2 |
| `10-Lateral-Movement` | 6 | 2 |
| `11-Collection` | 4 | 3 |
| `12-Command-and-Control` | 4 | 2 |
| `13-Exfiltration` | 2 | 1 |
| `14-Impact` | 1 | 1 |
| `16-Forensic-Artifacts` | 3 | 2 |
| `17-Query-Builder-Helper` | 9 | 4 |
| `21-Cool-Query-Friday` | 5 | 5 |


## 2. Newly created helper sections

- `17-Query-Builder-Helper/` — reusable investigation pivots, CIDR and command history searches, CQL fieldset and identity normalization patterns.
- `18-CQL-Functions/` — function index, semantics, caveats, and expanded examples.
- `19-Event-and-Field-Reference/` — event family catalog, field mapping and verification flow.
- `20-Query-Optimization-and-QA/` — filter-first performance policy, profiling, FP controls and validation checklist.
- `21-Cool-Query-Friday/` — original adapted examples with attribution and validation notices.
- `22-Detection-Engineering/` — hunt-to-production workflow and promotion gates.
- `docs/` — provenance, deployment, and current MITRE ATT&CK mapping.
- `templates/` — standardized Markdown query documentation skeleton.

## 3. Reclassified queries previously in the deleted folder

- **CIDR-Based Remote IP Search** → `17-Query-Builder-Helper/README.md`
- **Command History Scoped Search** → `17-Query-Builder-Helper/README.md`
- **Process and Network Connection Correlation** → `17-Query-Builder-Helper/README.md`
- **Executable File Written After User Logon** → `16-Forensic-Artifacts/README.md`
- **Process Execution and DNS Correlation** → `12-Command-and-Control/README.md`
- **Command History and Process Rollup** → `17-Query-Builder-Helper/README.md`
- **Parameterized Process Network Pivot** → `17-Query-Builder-Helper/README.md`

## 4. Validation status

- Migrated user queries: source reported as validated, sanitized publication copy requires re-check.
- OneNote-based additions: **CANDIDATE**, syntax/fields and thresholds must be checked in Falcon.
- Community adaptations: **CANDIDATE**, not run or tested against your environment.
- No source is marked `Production reviewed` or `Tested` by this pack.

## 5. Explicitly excluded / not claimed

- No deleted Investigation-Timelines category.
- No KQL, XQL or Foundry implementation.
- No hardcoded real employee identifiers or customer address ranges in new additions.
- No claim of parsing image-only OneNote content in full.
- No claim that a Reddit example works as-is in your tenant.
