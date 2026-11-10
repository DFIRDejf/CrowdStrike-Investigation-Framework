# Deployment / Merge Guide — CrowdStrike CQL Framework v2

## Important: use a new branch for batch changes

1. In GitHub, create a branch such as `feature/cql-library-v2` from `main`.
2. Review the category and helper changes in the [v2 changelog](../CHANGELOG-v2.md).
3. For each existing category, either replace its initial placeholder README or **merge** these query entries with any custom content you've already added.
4. For the new helper folders 17-22, upload each `README.md` via `Add file → Upload files`, preserving the directory hierarchy. You can also create files one by one using `Create new file` and path syntax.
5. Do **not** replace the branded root `README.md`. Merge the category and helper links into the [existing navigation](../README.md#-hunting-library) and confirm the folder paths.
6. Verify that the deleted `15-Investigation-Timelines` folder stays absent and its links are removed from the root README.
7. In GitHub Preview, expand 3–5 `<details>` sections, check code fences and links.
8. Open a Pull Request into `main` and request peer review. Commit message: `Expand CQL hunting library with OneNote and CQF research`.

## No personal data in committed copy

Ensure any extended investigation filters and any earlier private query files do not contain customer hostnames, UPNs, internal CIDR allowlists or incident IDs.

## Validated vs. candidate

- Earlier user-reported queries remain listed as source-validated **only**. Sanitized copies need tenant revalidation.
- All newly created OneNote-based and community-derived queries are examples to test, not production detections.

## Troubleshooting

- Category link 404 → verify folder capitalization and file path.
- Empty category view → ensure `README.md` exists and is committed.
- Dropdown not rendering → check blank lines around `<details>`, `<summary>`, code fences and closing tag.
- Query returns no data → confirm fieldsets, repository/time scope and entitlement, then test base filter.
