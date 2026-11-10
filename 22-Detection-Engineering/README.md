# Detection Engineering Playbook

A threat-hunting query is not automatically a production detection. This playbook describes the transition from hypothesis to robust alerting.

## Lifecycle

1. **Hypothesis:** describe a concrete adversary behavior and expected telemetry.
2. **Data validation:** inspect actual event fieldsets and availability.
3. **Prototype:** exact filters, tight time windows and minimal transformations.
4. **Hunt evaluation:** sample positives and benign activity across several host roles.
5. **Tuning:** use narrowly justified exclusions and explicit thresholds.
6. **Release:** document MITRE technique, severity, owner, runbook and evidence.
7. **Monitoring:** periodically measure volume, FP ratio and coverage changes.

## Query Promotion States

| State | Meaning |
|---|---|
| `Source validated / migration recheck` | User tested an earlier version; sanitized variant needs retesting |
| `Candidate` | Drafted based on source guidance; not executed in target Falcon |
| `Community adapted` | Based on a published research pattern; not necessarily tenant-compatible |
| `Tested` | New exact version executed successfully with expected evidence |
| `Production reviewed` | Peer-reviewed with documented FP and resource profile |

## Release Worksheet

- Detection name, owner, MITRE ATT&CK ID and rationale
- Required event families and verified fields
- Expected positive behavior and log examples
- Expected benign behavior and approved exclusions
- Search horizon, performance and alert threshold
- SOC triage, escalation criteria and response actions
- Change log, validation date and regression test result

[Use the Query Template](../templates/QUERY_TEMPLATE.md) and the [QA Checklist](../20-Query-Optimization-and-QA/README.md).
