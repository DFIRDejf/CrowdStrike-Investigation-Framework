[← Framework home](../README.md)

# Query Optimization and QA

**CrowdStrike Falcon / NG-SIEM**  ·  **CQL**  ·  `Reference`  ·  **Reference**

Build efficient queries and validate signal quality before deployment.

---

## Query design order

`Time window` → `Event / tag filters` → `Exact field filters` → `Regex` → `Transforms` → `Aggregation` → `Sort`

## Release checks

| Check | Requirement |
|---|---|
| Syntax & fields | Test against real event fieldsets. |
| Correlation | Scope by `aid` and matching process identity. |
| False positives | Compare legitimate and suspicious behavior before excluding. |
| Performance | Use a bounded time range and sensible aggregation limits. |
| Privacy | Remove internal identifiers and sensitive evidence before publication. |
| Release | Record status, ownership, technique mapping and validation date. |

## Query profiling

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

```cql
#event_simpleName=ProcessRollup2 event_platform=Win
| CommandLine=/(encodedcommand|\-enc\s)/i
| groupBy([ComputerName], function=[count(as=Executions)], limit=1000)
| explain:asTable()
```

Use `explain:asTable()` for interactive tuning, not as a production detection stage.

*Source: [Cool Query Friday — query profiling](https://www.reddit.com/r/crowdstrike/comments/1ryw8kr/).*

</details>

**Analyst rule:** A sensitive-file event followed by an external connection is a lead, not proof of exfiltration.

[← Back to framework](../README.md)
