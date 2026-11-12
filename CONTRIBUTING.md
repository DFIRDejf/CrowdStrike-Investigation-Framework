# Contributing to CrowdStrike Threat Hunting Framework

[← Home](README.md) · [Automation & QA](docs/CQL-CATALOG-AUTOMATION.md) · [Query template](templates/QUERY_TEMPLATE.md)

Add one logical hunt group per Pull Request. Keep the CQL query read-only and preserve the historical text of existing queries.

1. Check [All queries](QUERY-CATALOG.md), [MITRE Technique Index](MITRE-TECHNIQUE-INDEX.md), and [Telemetry Index](TELEMETRY-INDEX.md) for existing or overlapping hunts.
2. Add the query to its ATT&CK category using a sequential `### NN. Title` heading and the [query template](templates/QUERY_TEMPLATE.md).
3. Document your hypothesis, MITRE mapping, available telemetry, false positives, and investigation steps. New queries must begin as `Requires Validation`.
4. Run `python3 scripts/catalog.py --write`, followed by `--check` and the Python unit tests.
5. Review the generated catalog and [duplicate report](docs/QUERY-DUPLICATES.md) before submitting the PR. Duplicates are *never* deleted automatically.

Do not publish credentials, tokens, company-specific hostnames or identifiers, sensitive case evidence or internal allowlists. Retain external source attribution in [the provenance document](docs/SOURCE-AND-PROVENANCE.md), not as repeated labels on query cards.

Promote a query to `Tested` or `Production reviewed` only with documented Falcon validation. CI checks Markdown and metadata consistency, not the query's effectiveness in production.
