# CQL Catalog Automation (v4.3)

[← Framework home](../README.md) · [Query Catalog](../QUERY-CATALOG.md)

The v4.3 tooling uses **Python standard library** and **GitHub Actions**. Category READMEs are the source of truth. **CQL code blocks are never rewritten** by the generator.

## Add a query

1. Add a sequential `### NN. Query title` section in its category `README.md`.
2. Include `**MITRE:**`, an explicit status such as `**Status:** `Requires Validation``, one `cql` code fence, and one `<details>` dropdown.
3. Commit to a `feature/...`, `fix/...` or `docs/...` branch.
4. On push, GitHub Actions regenerates category indexes, `QUERY-CATALOG.md`, `MITRE-TECHNIQUE-INDEX.md`, and the root README counts, committing generated Markdown to that branch.
5. Pull Requests run **read-only QA** which fails for malformed entries, broken links, or stale generated files. Review the diff before merge.

## Local commands

```bash
python3 scripts/catalog.py --write
python3 scripts/catalog.py --check
python3 -m unittest discover -s tests -p 'test_*.py' -v
```

## Checks

- Sequential, unique numbered hunt headings and unique query titles per category
- Exactly one nonempty CQL code fence and one balanced dropdown per query
- Recognized validation status, never auto-promoted to `Tested`
- Local Markdown links in generated files
- No deleted `15-Investigation-Timelines` folder
- Consistent root counts, category indexes and MITRE technique mappings
- Unit tests for indexing, duplicates, status validation, and CQL preservation

**Scope:** Structural and documentation QA only. CI does not verify live CQL syntax in CrowdStrike, tenant fieldsets, false positives, or detection efficacy.

## GitHub permissions

Pull Request validation uses read-only permissions. Feature-branch synchronization requests `contents: write` and **never pushes to `main`**. If repository policy disallows token writes or the branch is protected, run `--write` locally and commit the generated Markdown. No GitHub Pages, Foundry, or external service is required.
