[← Framework home](../README.md)

# Privilege Escalation

**CrowdStrike Falcon / NG-SIEM**  ·  **CQL**  ·  `TA0004`  ·  **1 queries**

Review privilege changes and indicators of unauthorized elevation.

---

## Query library

| Hunt | Status |
|---|---|
| [01. Account Added to Privileged Group Event Family](#01-account-added-to-privileged-group-event-family) | `Candidate` |

---

### 01. Account Added to Privileged Group Event Family

Exposes group membership change telemetry for investigation and follow-up filtering.

**MITRE:** T1098\  ·  **Telemetry:** UserAccountAddedToGroup and AD group entity events

<details>
<summary><strong>If you want to see more details</strong></summary>

```cql
#event_simpleName=/^(UserAccountAddedToGroup|ActiveDirectoryAccountDirectContainingGroupEntitiesUpdate|ActiveDirectoryAccountFlattenedContainingGroupEntitiesUpdate)$/
| select([@timestamp, #event_simpleName, ComputerName, UserName, aid])
| sort(@timestamp, order=desc, limit=1000)
```

**False positives:** Provisioning automation and authorized admin changes. Validate emitted event/field family.

**Analyst pivot:** Inspect actor, target account, target group and approval record.

*Origin: OneNote-derived adaptation\*

</details>

---

`Migration recheck` = original supplied query was previously tested, but this publication copy needs validation. `Candidate` / `Community candidate` = not validated in the target Falcon environment.

[← Back to framework](../README.md)
