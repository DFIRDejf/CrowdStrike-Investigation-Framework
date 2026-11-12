[← Framework home](../README.md)

# Detection Engineering

**CrowdStrike Falcon / NG-SIEM**  ·  **CQL**  ·  `Reference`  ·  **Reference**

Move from a hunting hypothesis to a reviewed production detection.

---

## From hunt to detection

| Stage | Exit criterion |
|---|---|
| **1 · Hypothesis** | Describe behavior and expected data. |
| **2 · Prototype** | Confirm events and fields; test narrowly. |
| **3 · Tune** | Review benign activity, thresholds, and query cost. |
| **4 · Release** | Peer-review logic, triage guidance, and regression tests. |

## Validation status

| Status | Meaning |
|---|---|
| `Requires Validation` | Not yet verified for the exact published query in Falcon. |
| `Tested` | Exact query version has been executed and checked. |
| `Production reviewed` | Peer-reviewed; false positives and performance documented. |

**Before promoting:** owner · last validation · MITRE mapping · known FPs · runbook · test evidence.

[Query template](../templates/QUERY_TEMPLATE.md) · [QA reference](../20-Query-Optimization-and-QA/README.md)

[← Back to framework](../README.md)
