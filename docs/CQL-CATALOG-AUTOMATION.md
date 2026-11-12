# CQL Catalog Automation — v4.4

[← Home](../README.md) · [All queries](../QUERY-CATALOG.md) · [Telemetry index](../TELEMETRY-INDEX.md)

The framework remains **GitHub-only**. Category README query sections are the source of truth. Python standard library and GitHub Actions maintain query metadata and searchable indexes. **CQL blocks are not rewritten by automation.**

## Query presentation

Each category query displays:
- A stable query ID such as `CS-TA0008-007`, independent of the visible query name and position.
- A platform hint based only on an explicit `event_platform` filter; otherwise `Not scoped`.
- Telemetry tags inferred from parsed event names. Tags are a convenience, **not** tenant verification.
- ATT&CK context and a single validation status.
- A dropdown labeled **Show CrowdStrike query**, with the original CQL and investigation notes.

Individual OneNote and community-origin labels are removed from query cards; historical attribution and references remain in [Source & Provenance](SOURCE-AND-PROVENANCE.md).

## Validation states

| Status | Use |
|---|---|
| `Requires Validation` | All previously unverified or migration-recheck copies; no tenant validation claimed |
| `Tested` | Exact query revision executed and documented in Falcon |
| `Production reviewed` | Tested query peer-reviewed for deployment with recorded evidence |

Automation does not advance statuses. Record testing scope, output, reviewer, date and revisions before promoting a query.

## Author a query

1. Add a sequential heading `### NN. Clear Hunt Name`, hypothesis, ATT&CK mapping, one `cql` code fence and one `<details>` block.
2. Use `**Status:** \`Requires Validation\`` (or keep it in the category index until the generator migrates the metadata).
3. Run `python3 scripts/catalog.py --write`. It assigns a stable ID **once**, inserts metadata and refreshes indexes.
4. Never manually renumber or replace the existing `<a name="cs-..."></a>` anchor or `**Query ID:**`; doing so breaks stable external links.
5. Review the generated diff; open a PR. The PR job requires fresh generated files.

## Local commands

```bash
python3 scripts/catalog.py --write
python3 scripts/catalog.py --check
python3 -m unittest discover -s tests -p 'test_*.py' -v
```

## Generated files

- `QUERY-CATALOG.md` — searchable catalog with stable IDs and validation statuses.
- `MITRE-TECHNIQUE-INDEX.md` — related queries per ATT&CK technique ID.
- `TELEMETRY-INDEX.md` — observed literal event references extracted from CQL.
- `docs/QUERY-DUPLICATES.md` — possible exact/high-similarity pairs for **manual review only**.
- README category index tables and main README counters.

## Branch automation and safeguards

On `feature/**`, `fix/**` and `docs/**` pushes, a GitHub Actions job regenerates and commits the resulting Markdown to that branch. The PR job runs read-only QA. **Never commits automatically to `main`.** Repository policies may restrict bot write access.

QA verifies query structure, unique IDs and titles, supported status, CQL preservation and local link paths. Duplicate matching compares normalized CQL text, and marks near-matches only as suggestions. A high text similarity does not establish the same threat-hunting semantics.

**Not included:** live Falcon CQL validation, tenant fieldset checks, false-positive measurement, production certification, GitHub Pages or Foundry.
