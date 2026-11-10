[← Framework home](../README.md)

# CQL Functions

**CrowdStrike Falcon / NG-SIEM**  ·  **CQL**  ·  `Reference`  ·  **Reference**

Quick guidance for selecting and combining CrowdStrike CQL functions.

---

## Function quick reference

| Function | Use | Reference |
|---|---|---|
| `fieldset()` | Discover observed field names | [Docs](https://library.humio.com/crowdstrike-query-language/functions-fieldset.html) |
| `fieldstats()` | Statistics about present fields | [Docs](https://library.humio.com/crowdstrike-query-language/functions-fieldstats.html) |
| `groupBy()` | Summarize by one or more keys | [Docs](https://library.humio.com/crowdstrike-query-language/functions-groupby.html) |
| `collect()` | Preserve representative values in aggregate | [Docs](https://library.humio.com/crowdstrike-query-language/functions-collect.html) |
| `case` | Conditional transformations | [Docs](https://library.humio.com/crowdstrike-query-language/syntax-conditional.html) |
| `coalesce()` | Normalize alternate field names | [Docs](https://library.humio.com/crowdstrike-query-language/functions-coalesce.html) |
| `cidr()` | Filter IPs by subnet | [Docs](https://library.humio.com/crowdstrike-query-language/functions-cidr.html) |
| `defineTable()` | Build an ad-hoc lookup from a subquery | [Docs](https://library.humio.com/crowdstrike-query-language/functions-definetable.html) |
| `match()` | Join/enrich using a lookup or ad-hoc table | [Docs](https://library.humio.com/crowdstrike-query-language/functions-match.html) |
| `join()` | Combine two queries | [Docs](https://library.humio.com/crowdstrike-query-language/functions-join.html) |
| `correlate()` | Multi-event temporal relationships | [Docs](https://library.humio.com/crowdstrike-query-language/functions-correlate.html) |
| `selfJoinFilter()` | Find common keys across multiple event types | [Docs](https://library.humio.com/crowdstrike-query-language/functions-selfjoinfilter.html) |
| `setTimeInterval()` | Control search time boundary | [Docs](https://library.humio.com/crowdstrike-query-language/functions-settimeinterval.html) |
| `formatTime()` | Format epoch values | [Docs](https://library.humio.com/crowdstrike-query-language/functions-formattime.html) |
| `neighbor()` | Compare adjacent ordered observations | [Docs](https://library.humio.com/crowdstrike-query-language/functions-neighbor.html) |
| `explain:asTable()` | Profile query costs and prefilters | [Docs](https://library.humio.com/crowdstrike-query-language/functions-explain-astable.html) |

**Common pitfalls:** Limit high-cardinality aggregations; correlate on endpoint + process identity; check timestamp units; profile costly hunts before production.

## CQL patterns

### GroupBy and collect

<details>
<summary><strong>If you want to see more details</strong></summary>

```cql
#event_simpleName=ProcessRollup2 event_platform=Win
| groupBy([ComputerName, FileName], function=[count(as=Executions), collect([UserName])], limit=1000)
| sort(Executions, order=desc, limit=1000)
```

Use explicit output limits; large collections increase resource consumption.

</details>

### DefineTable and match with composite key

<details>
<summary><strong>If you want to see more details</strong></summary>

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

### SetTimeInterval and profiling

<details>
<summary><strong>If you want to see more details</strong></summary>

```cql
setTimeInterval(start="1d")
| #event_simpleName=ProcessRollup2 event_platform=Win
| groupBy([FileName], function=[count(as=Executions)], limit=1000)
| explain:asTable()
```

Use only in interactive tuning, not production detections.

</details>

[← Back to framework](../README.md)
