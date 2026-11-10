# Privilege Escalation — CrowdStrike CQL

> **1 CQL entries** | CrowdStrike Falcon / NG-SIEM | MITRE: TA0004

Investigate potentially unauthorized privilege or group membership changes.

> **Validation notice:** Entries marked *User-reported validated source* were provided as working queries, but publication copies were sanitized and must be re-tested. Entries marked *Candidate* and *Community-derived* have **not** been tested in this environment.

## Query Index

1. [Account Added to Privileged Group Event Family](#01-account-added-to-privileged-group-event-family)

---

## 01. Account Added to Privileged Group Event Family

**Description:** Exposes group membership change telemetry for investigation and follow-up filtering.

**MITRE ATT&CK:** T1098\
**Origin:** OneNote-derived adaptation\
**Validation:** Candidate — requires validation in Falcon\
**Required telemetry:** UserAccountAddedToGroup and AD group entity events

<details>
<summary><strong>If you want to see more details</strong></summary>

### Hunting Query (CQL)

```cql
#event_simpleName=/^(UserAccountAddedToGroup|ActiveDirectoryAccountDirectContainingGroupEntitiesUpdate|ActiveDirectoryAccountFlattenedContainingGroupEntitiesUpdate)$/
| select([@timestamp, #event_simpleName, ComputerName, UserName, aid])
| sort(@timestamp, order=desc, limit=1000)
```

### False Positive Considerations

Provisioning automation and authorized admin changes. Validate emitted event/field family.

### Investigation Guidance

Inspect actor, target account, target group and approval record.

</details>

---
