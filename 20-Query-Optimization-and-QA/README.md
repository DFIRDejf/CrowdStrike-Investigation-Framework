# Query Optimization and Quality Assurance

> **Goal:** minimize false positives and execution cost without losing relevant telemetry.

## Performance Order (from the provided OneNote notes)

1. Set a **strict time range** (via UI or `setTimeInterval`).
2. Start with indexed/tag filters (`#event_simpleName`, platform, repository).
3. Apply exact field filters and known scoped hosts/users.
4. Apply carefully justified exclusions, only after preserving true positives.
5. Use regex or unparsed-event searches when exact parsed fields cannot express the signal.
6. Apply transformations, evaluation and lookups.
7. Aggregate (`groupBy`, `count`, `collect`), then format and sort.
8. Keep explicit output limits and compare performance against a baseline.

## Quality Gates

| Check | Requirement |
|---|---|
| Syntax | Runs in Falcon CQL without errors |
| Fields | Verified with `fieldset()` / representative events |
| Correlation | Scope by `aid` and process key; document time semantics |
| Accuracy | Document representative true-positive and false-positive cases |
| False positive controls | Justify every exclusion; do not blanket-exclude admin tools |
| Performance | Defined time horizon; bounded aggregation/collection |
| Security | No internal user IDs, customer data, tokens, internal IPs or evidence paths in public copy |
| Maintenance | Owner, date, last validation, technique, and source/credits |

## Performance Profiler

<details>
<summary><strong>If you want to see more details — explain:asTable()</strong></summary>

```cql
#event_simpleName=ProcessRollup2 event_platform=Win
| CommandLine=/(encodedcommand|\-enc\s)/i
| groupBy([ComputerName], function=[count(as=Executions)], limit=1000)
| explain:asTable()
```

Source: [Cool Query Friday — March 20, 2026](https://www.reddit.com/r/crowdstrike/comments/1ryw8kr/). Use for interactive profiling only.

</details>

## FP Tuning Guidance

- Segment by fleet roles: domain controllers, backup servers, workstations, admin endpoints.
- Use activity baselines and signer/parent-path context.
- Keep allowlists controlled, documented and time-bounded.
- Preserve raw pre-tuning result counts during validation.
- Track test cases and regressions after each edit.
- Do not infer exfiltration only from a connection and a preceding sensitive-file event; inspect bytes/protocol/process context.

## Quality Checklist

- [ ] Scope and purpose are clear
- [ ] Dataset and fields are confirmed
- [ ] No ambiguous regex matches
- [ ] No undocumented hardcoded filters
- [ ] Process correlation uses `aid` where applicable
- [ ] Time window is constrained
- [ ] Tested positives/negatives are documented
- [ ] Sanitized publication copy has been revalidated
