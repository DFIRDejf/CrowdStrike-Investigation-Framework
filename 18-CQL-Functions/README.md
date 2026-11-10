# CQL Functions — Practical Reference

> **Function quick reference** for building scalable CrowdStrike Falcon LogScale / NG-SIEM searches.

This reference combines concepts present in the provided OneNote training notes with authoritative CrowdStrike documentation. These are **function patterns**, not tenant-validated detections.

| Function | Purpose | Important constraint | Official reference |
|---|---|---|---|
| `fieldset()` | Discover observed field names | Results depend on sampled events | [Docs](https://library.humio.com/crowdstrike-query-language/functions-fieldset.html) |
| `fieldstats()` | Statistics about present fields | Use a narrow time range | [Docs](https://library.humio.com/crowdstrike-query-language/functions-fieldstats.html) |
| `groupBy()` | Summarize by one or more keys | Tune `limit`; avoid high-cardinality keys | [Docs](https://library.humio.com/crowdstrike-query-language/functions-groupby.html) |
| `collect()` | Preserve representative values in aggregate | Limit collection size | [Docs](https://library.humio.com/crowdstrike-query-language/functions-collect.html) |
| `case` | Conditional transformations | Place selective filters ahead of it | [Docs](https://library.humio.com/crowdstrike-query-language/syntax-conditional.html) |
| `coalesce()` | Normalize alternate field names | Check type/availability | [Docs](https://library.humio.com/crowdstrike-query-language/functions-coalesce.html) |
| `cidr()` | Filter IPs by subnet | Select correct source/destination field | [Docs](https://library.humio.com/crowdstrike-query-language/functions-cidr.html) |
| `defineTable()` | Build an ad-hoc lookup from a subquery | Preamble only, after `setTimeInterval()` if used; maximum 10 tables | [Docs](https://library.humio.com/crowdstrike-query-language/functions-definetable.html) |
| `match()` | Join/enrich using a lookup or ad-hoc table | Match **both** `aid` and process ID where applicable | [Docs](https://library.humio.com/crowdstrike-query-language/functions-match.html) |
| `join()` | Combine two queries | Beware many-to-many explosion | [Docs](https://library.humio.com/crowdstrike-query-language/functions-join.html) |
| `correlate()` | Multi-event temporal relationships | `within`, `sequence`, and correlation keys matter; incompatible with `join()` | [Docs](https://library.humio.com/crowdstrike-query-language/functions-correlate.html) |
| `selfJoinFilter()` | Find common keys across multiple event types | Two-pass, probabilistic matches | [Docs](https://library.humio.com/crowdstrike-query-language/functions-selfjoinfilter.html) |
| `splitString()` / `concatArray()` | Break and reconstruct command history | Check separator and resulting array shape | [Docs](https://library.humio.com/crowdstrike-query-language/functions-splitstring.html) |
| `setTimeInterval()` | Control search time boundary | May override the GUI time picker | [Docs](https://library.humio.com/crowdstrike-query-language/functions-settimeinterval.html) |
| `formatTime()` | Format epoch values | Check time units (s vs ms) | [Docs](https://library.humio.com/crowdstrike-query-language/functions-formattime.html) |
| `neighbor()` | Compare adjacent ordered observations | Must run **after an aggregator / ordering stage** | [Docs](https://library.humio.com/crowdstrike-query-language/functions-neighbor.html) |
| `explain:asTable()` | Profile query costs and prefilters | Use in ad-hoc profiling only | [Docs](https://library.humio.com/crowdstrike-query-language/functions-explain-astable.html) |

## Expandable Examples

<details>
<summary><strong>If you want to see more details — groupBy and collect</strong></summary>

```cql
#event_simpleName=ProcessRollup2 event_platform=Win
| groupBy([ComputerName, FileName], function=[count(as=Executions), collect([UserName])], limit=1000)
| sort(Executions, order=desc, limit=1000)
```

Use explicit output limits; large collections increase resource consumption.

</details>

<details>
<summary><strong>If you want to see more details — defineTable and match with composite key</strong></summary>

```cql
setTimeInterval(start="1d")
| defineTable(
    query={#event_simpleName=DnsRequest | aid=* ContextProcessId=*},
    include=[aid, ContextProcessId, DomainName],
    name="DNSLookup")
| #event_simpleName=ProcessRollup2 event_platform=Win
| aid=* TargetProcessId=*
| match(file="DNSLookup", field=[aid, TargetProcessId], column=[aid, ContextProcessId], include=[DomainName])
| select([@timestamp, ComputerName, FileName, TargetProcessId, DomainName])
```

**Why composite keys matter:** Falcon process IDs are unique in the context of their endpoint (`aid`). Joining only on process IDs across endpoints risks unrelated matches. This example is a **candidate** and requires testing.

</details>

<details>
<summary><strong>If you want to see more details — setTimeInterval and profiling</strong></summary>

```cql
setTimeInterval(start="1d")
| #event_simpleName=ProcessRollup2 event_platform=Win
| groupBy([FileName], function=[count(as=Executions)], limit=1000)
| explain:asTable()
```

Use only in interactive tuning, not production detections.

</details>

## Function Selection

1. Use **exact/tag filters** before transformations.
2. For simple two-source lookup, evaluate `defineTable()` + `match()` (or `join()`).
3. For event sequences and several related event types, consider `correlate()` with explicit links and a tight `within`.
4. For multiple event types sharing a compact key, consider `selfJoinFilter()` with its probabilistic caveat.
5. Use `explain:asTable()` when optimizing expensive interactive hunts.
