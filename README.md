<div align="center">

<table>
<tr>
<td align="center" width="50%"><img src="assets/crowdstrike-logo.png" alt="CrowdStrike logo" width="260"></td>
<td align="center" width="50%"><img src="assets/mitre-attack-logo.png" alt="MITRE ATT&CK logo" width="260"></td>
</tr>
</table>

# CrowdStrike Threat Hunting Framework

### A structured CQL query library for proactive threat hunting, incident response, and digital forensics

**CrowdStrike Falcon · Next-Gen SIEM · CQL · MITRE ATT&CK®**

![Language](https://img.shields.io/badge/Language-CQL-ef4444?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-CrowdStrike%20Falcon-202938?style=flat-square)
![Documentation](https://img.shields.io/badge/Documentation-Markdown-2563eb?style=flat-square)
![Access](https://img.shields.io/badge/Use-Internal%20Security%20Teams-64748b?style=flat-square)

**[Explore Hunting Categories](#-hunting-library)** · **[How to Use](#-getting-started)** · **[Query Standards](#-query-documentation-standard)** · **[References](#-references)**

</div>

---

## 🎯 Mission

The **CrowdStrike Threat Hunting Framework** is an internally maintained collection of reusable **CrowdStrike Query Language (CQL)** hunting scenarios. It supports security analysts, threat hunters, detection engineers, incident responders, and digital forensic investigators in examining endpoint, identity, and network telemetry available in CrowdStrike Falcon / Next-Gen SIEM.

The framework aims to turn repeatable investigation logic into **documented, reviewable, and reusable hunting workflows** rather than isolated search snippets.

> [!IMPORTANT]
> This is an **independent internal query library**, not an official CrowdStrike or MITRE product. Query results are investigative leads, not proof of compromise. Validate syntax, field availability, event coverage, and investigative conclusions in your own environment.

## ✨ Framework Capabilities

| Capability | Purpose |
|:--|:--|
| 🧭 ATT&CK-aligned navigation | Find hunting scenarios by adversary objective and technique. |
| 🔎 Expandable CQL queries | Open detailed queries only when needed, keeping category pages readable. |
| 🧪 Validation tracking | Distinguish tested queries from drafts and environment-dependent examples. |
| 🎛️ False-positive awareness | Document benign activity, tuning opportunities, and contextual checks. |
| ⏱️ Timeline reconstruction | Support chronological correlation of processes, commands, files, and connections. |
| 🧬 Forensic investigation | Investigate file-system, execution, and other forensic-relevant telemetry. |
| ⚡ Performance-first design | Prioritize time bounds, selective event filters, and controlled output. |
| 🤝 Collaborative engineering | Use Git history and pull requests to maintain query quality. |

## 🗂️ Hunting Library

Choose a category to view its description, available scenarios, and expandable query details.

> **ATT&CK mapping note:** This repository retains a legacy **Defense Evasion** category for continuity. MITRE ATT&CK Enterprise v20 introduces **Stealth** and **Defense Impairment** as separate tactics. See the [ATT&CK mapping notes](docs/MITRE-ATTACK-2026-MAPPING.md) for details.

| # | Hunting Category | Focus | Open |
|:--:|:--|:--|:--:|
| 01 | Reconnaissance | Information gathering and target profiling | [Explore](01-Reconnaissance/README.md) |
| 02 | Resource Development | Adversary preparation and infrastructure | [Explore](02-Resource-Development/README.md) |
| 03 | Initial Access | Entry vectors and suspicious downloads | [Explore](03-Initial-Access/README.md) |
| 04 | Execution | Process, script, and command execution | [Explore](04-Execution/README.md) |
| 05 | Persistence | Tasks, services, registry, and access retention | [Explore](05-Persistence/README.md) |
| 06 | Privilege Escalation | Elevated execution and privilege abuse | [Explore](06-Privilege-Escalation/README.md) |
| 07 | Defense Evasion (legacy) | Evasion and control-bypass behavior | [Explore](07-Defense-Evasion/README.md) |
| 08 | Credential Access | Credential theft, dumping, and Kerberos abuse | [Explore](08-Credential-Access/README.md) |
| 09 | Discovery | Host, network, account, and AD enumeration | [Explore](09-Discovery/README.md) |
| 10 | Lateral Movement | SMB, remote access, and remote execution | [Explore](10-Lateral-Movement/README.md) |
| 11 | Collection | Sensitive-file access and data staging | [Explore](11-Collection/README.md) |
| 12 | Command and Control | Suspicious DNS and outbound communications | [Explore](12-Command-and-Control/README.md) |
| 13 | Exfiltration | Data movement and external transfer indicators | [Explore](13-Exfiltration/README.md) |
| 14 | Impact | Destructive activity and ransomware behavior | [Explore](14-Impact/README.md) |

### 🔬 Operational Investigation Modules

These modules cover forensic investigation, CQL reference material, and detection engineering.

| Module | Purpose | Open |
|:--|:--|:--:|
| Forensic Artifacts | Investigate endpoint artifacts and forensic evidence | [Explore](16-Forensic-Artifacts/README.md) |
| Query Builder Helper | Build scoped searches and reusable investigation pivots | [Explore](17-Query-Builder-Helper/README.md) |
| CQL Functions | Look up CQL functions, examples, and constraints | [Explore](18-CQL-Functions/README.md) |
| Event & Field Reference | Check telemetry coverage and field mappings | [Explore](19-Event-and-Field-Reference/README.md) |
| Query Optimization & QA | Profile queries, tune false positives, and validate results | [Explore](20-Query-Optimization-and-QA/README.md) |
| Cool Query Friday | Explore community-inspired CQL examples | [Explore](21-Cool-Query-Friday/README.md) |
| Detection Engineering | Evaluate hunts for promotion to detections | [Explore](22-Detection-Engineering/README.md) |

## 🚀 Getting Started

1. **Select a category** from the Hunting Library.
2. **Read the scenario overview** to understand the threat hypothesis and required telemetry.
3. **Expand “If you want to see more details”** to reveal the CQL query and analyst notes.
4. **Confirm query status and dependencies** before execution.
5. **Set a narrow investigation time range** and replace any environment-specific placeholders.
6. **Run the query in the appropriate CrowdStrike search interface.**
7. **Validate results** using process ancestry, user context, asset roles, known administrative activity, and corroborating events.
8. **Document findings** and propose tuning only after reviewing legitimate activity.

<details>
<summary><strong>If you want to see more details — Query presentation example</strong></summary>

### Example scenario: Suspicious SMB activity

**Description:** Investigate SMB-related connections that may warrant additional lateral-movement analysis.

**ATT&CK:** T1021.002 — SMB/Windows Admin Shares  
**Status:** Illustrative — requires environment validation

```cql
// Insert a validated CQL query here.
// Confirm event names and field mappings in your environment.
```

**False-positive considerations:** Authorized remote administration, backup systems, software deployment, and legitimate file sharing.

**Investigation guidance:** Correlate the initiating process, destination host, user identity, authentication activity, and surrounding timeline.

</details>

## 📐 Query Documentation Standard

Each published hunting scenario should contain:

| Field | Required content |
|:--|:--|
| Query name | Clear and action-oriented scenario title |
| Hunting hypothesis | Behavior being investigated and why it matters |
| Description | What the query identifies and what it does not prove |
| ATT&CK mapping | Tactic and technique/sub-technique, where applicable |
| Data sources | Required `#event_simpleName` values and relevant telemetry |
| CQL query | Readable, documented, expandable code block |
| Parameters | Time range, hosts, users, IPs, and optional exclusions |
| False positives | Expected benign explanations and tuning considerations |
| Investigation guidance | Recommended validation and correlation steps |
| Validation status | Use a [query validation state](#query-validation-states) |
| Maintenance | Owner and last review date, where available |

### Query Validation States

| Status | Meaning |
|:--|:--|
| `Draft` | Proposed hunting logic; not yet validated. |
| `Requires Validation` | Syntax, telemetry, performance, or false-positive behavior needs review. Candidate and community-derived entries are in this state. |
| `User-reported validated source` | The source query was reported as working. Revalidate the sanitized repository copy. |
| `Tested` | Executed successfully against a documented environment and time window; not a guarantee of universal compatibility. |

## ⚙️ CQL Engineering Principles

1. **Constrain time:** Use the smallest time window suitable for the hypothesis.
2. **Filter early:** Prefer confirmed event tags and exact field filters before expensive operations.
3. **Avoid unnecessary regex:** Use regular expressions only where exact matching cannot express the requirement.
4. **Transform after filtering:** Defer parsing, normalization, correlation, and aggregation until the dataset is reduced.
5. **Control output:** Select meaningful evidence fields; avoid unnecessary wide output and sorting.
6. **Minimize false positives:** Consider approved tools, service accounts, scheduled operations, and known management infrastructure.
7. **Validate exclusions:** Apply internal-network or allowlist filters only when they do not hide relevant activity; document their impact.
8. **Prefer observed schemas:** Do not assume field names or event availability across tenants or data sources.
9. **Preserve evidence:** Retain timestamps, host/user identifiers, process context, and original event references as needed.
10. **Review periodically:** Revalidate queries after telemetry, parser, or platform changes.

> [!CAUTION]
> Queries are intended for **read-only investigation and hunting**. Review potentially sensitive output before sharing or committing it. Never commit real credentials, tokens, customer data, or incident-specific secrets.

## 🔄 Threat Hunting Workflow

```text
Threat Intelligence / Detection Gap / Incident Hypothesis
                         |
                         v
                 Select ATT&CK Category
                         |
                         v
                  Choose CQL Scenario
                         |
                         v
              Confirm Telemetry and Scope
                         |
                         v
                  Execute and Triage
                         |
                         v
             Correlate and Validate Evidence
                         |
                +--------+--------+
                |                 |
                v                 v
          Benign Activity    Suspicious Activity
                |                 |
                v                 v
          Document / Tune   Escalate / Investigate
                |                 |
                +--------+--------+
                         |
                         v
                 Improve Query Library
```

## 🧱 Repository Layout

```text
CrowdStrike-Threat-Hunting-Framework/
├── README.md
├── assets/
│   ├── crowdstrike-logo.png
│   └── mitre-attack-logo.png
├── 01-Reconnaissance/README.md
├── 02-Resource-Development/README.md
├── 03-Initial-Access/README.md
├── 04-Execution/README.md
├── 05-Persistence/README.md
├── 06-Privilege-Escalation/README.md
├── 07-Defense-Evasion/README.md
├── 08-Credential-Access/README.md
├── 09-Discovery/README.md
├── 10-Lateral-Movement/README.md
├── 11-Collection/README.md
├── 12-Command-and-Control/README.md
├── 13-Exfiltration/README.md
├── 14-Impact/README.md
├── 16-Forensic-Artifacts/README.md
├── 17-Query-Builder-Helper/README.md
├── 18-CQL-Functions/README.md
├── 19-Event-and-Field-Reference/README.md
├── 20-Query-Optimization-and-QA/README.md
├── 21-Cool-Query-Friday/README.md
├── 22-Detection-Engineering/README.md
├── CHANGELOG-v2.md
├── docs/README.md
├── templates/README.md
└── CONTRIBUTING.md
```

## 🤝 Contribution and Review

Use the [query template](templates/QUERY_TEMPLATE.md) and follow the [contribution guide](CONTRIBUTING.md).

1. Select the most relevant category and check for existing overlapping queries.
2. Use the standardized query documentation format.
3. Validate event names, field mappings, and CQL syntax against the target environment.
4. Evaluate performance and document known false positives.
5. Create a feature branch and submit a pull request.
6. Obtain peer review before merging to `main`, in accordance with repository policy.
7. Update the category README and relevant documentation.

**Suggested branch naming:** `feature/cql-smb-hunt`, `fix/cql-field-mapping`, `docs/query-guidance`.

## 📚 References

- [Framework documentation](docs/README.md)
- [Framework v2 changelog](CHANGELOG-v2.md)
- [CrowdStrike Query Language — Official Documentation](https://library.humio.com/crowdstrike-query-language/cql.html)
- [MITRE ATT&CK® Enterprise Matrix](https://attack.mitre.org/matrices/enterprise/)
- [MITRE ATT&CK® Legal & Branding](https://attack.mitre.org/resources/legal-and-branding/)
- [CrowdStrike Brand Resources](https://www.crowdstrike.com/about-us/brand/)
- [GitHub Markdown Documentation](https://docs.github.com/en/get-started/writing-on-github)

---

<div align="center">

**Hunt with context · Validate with evidence · Improve through collaboration**

<sub>Internal, independently maintained hunting documentation. CrowdStrike and Falcon are trademarks of their respective owner. MITRE ATT&CK® is a registered trademark of The MITRE Corporation. The presence of names and logos does not imply sponsorship, endorsement, or affiliation.</sub>

</div>
