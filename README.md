<div align="center">

<table>
<tr>
<td align="center" width="50%"><img src="assets/crowdstrike-white-panel.png" alt="CrowdStrike logo" width="250"></td>
<td align="center" width="50%"><img src="assets/mitre-white-panel.png" alt="MITRE ATT&CK logo" width="250"></td>
</tr>
</table>

# CrowdStrike Threat Hunting Framework

**A curated CQL library for threat hunting, incident response, and digital forensics.**

![Language: CQL](assets/badge-language.svg) ![Platform: Falcon NG-SIEM](assets/badge-platform.svg)

**[Browse all 111 queries](QUERY-CATALOG.md)** · **[Search by MITRE technique](MITRE-TECHNIQUE-INDEX.md)** · **[Telemetry index](TELEMETRY-INDEX.md)**

</div>

---

## Before you start - useful resources

| Goal | Where to go |
|:--|:--|
| **Find a query** by name, category or technique | [Global CQL Query Catalog](QUERY-CATALOG.md) |
| **Pivot from a MITRE technique** to hunts | [MITRE Technique Index](MITRE-TECHNIQUE-INDEX.md) |
| **Build or optimize a query** | [CQL Functions](15-CQL-Functions/README.md) · [Optimization & QA](17-Query-Optimization-and-QA/README.md) · [Contribution guide](CONTRIBUTING.md) |
| **Review telemetry coverage** | [Telemetry Index](TELEMETRY-INDEX.md) · [Event & Field Reference](16-Event-and-Field-Reference/README.md) |
| **Contribute a hunt** | [Contribution guide](CONTRIBUTING.md) · [Detection Engineering](18-Detection-Engineering/README.md) |

## ATT&CK hunting library

| # | Tactic | Queries | Focus |
|:--:|:--|--:|:--|
| 01 | [Reconnaissance](01-Reconnaissance/README.md) | 3 | Early information gathering |
| 02 | [Resource Development](02-Resource-Development/README.md) | 3 | Tools and preparation |
| 03 | [Initial Access](03-Initial-Access/README.md) | 5 | Entry points and downloads |
| 04 | [Execution](04-Execution/README.md) | 14 | Processes, scripts and commands |
| 05 | [Persistence](05-Persistence/README.md) | 6 | Services, tasks and autoruns |
| 06 | [Privilege Escalation](06-Privilege-Escalation/README.md) | 4 | Privilege and token activity |
| 07 | [Defense Evasion (legacy)](07-Defense-Evasion/README.md) | 8 | Tampering and evasion |
| 08 | [Credential Access](08-Credential-Access/README.md) | 9 | Credential and Kerberos abuse |
| 09 | [Discovery](09-Discovery/README.md) | 13 | Host, account and AD enumeration |
| 10 | [Lateral Movement](10-Lateral-Movement/README.md) | 11 | SMB and remote access |
| 11 | [Collection](11-Collection/README.md) | 10 | Staging and sensitive data |
| 12 | [Command and Control](12-Command-and-Control/README.md) | 13 | DNS and outbound activity |
| 13 | [Exfiltration](13-Exfiltration/README.md) | 7 | External transfer indicators |
| 14 | [Impact](14-Impact/README.md) | 5 | Disruption and ransomware |

> The `07-Defense-Evasion` folder name is retained for compatibility with existing links. ATT&CK technique mappings are informational and need analyst validation.

## Operational modules

| Module | Content |
|:--|:--|
| [CQL Functions](15-CQL-Functions/README.md) | Reference |
| [Event & Field Reference](16-Event-and-Field-Reference/README.md) | Reference |
| [Query Optimization & QA](17-Query-Optimization-and-QA/README.md) | Guidelines |
| [Detection Engineering](18-Detection-Engineering/README.md) | Guidelines |

## How to use

1. Open the [Query Catalog](QUERY-CATALOG.md) and use **Ctrl+F** to find a technique, event, keyword or tool.
2. Follow the link to the exact hunt. Expand **Show CrowdStrike query** to view its CQL and analyst notes.
3. Set the correct time range and scope, verify fields with your tenant telemetry, and test the query in CrowdStrike Falcon.
4. Review false positives, evidence quality, and performance before promoting the validation status.

**Read-only threat hunting.** Queries are investigative starting points, not proof of compromise. Do not commit credentials, sensitive incident evidence, or internal identifiers.

---

[**Contributing**](CONTRIBUTING.md) · [**Documentation**](docs/README.md) · [**Source & provenance**](docs/SOURCE-AND-PROVENANCE.md) · [**Official CQL reference**](https://library.humio.com/crowdstrike-query-language/cql.html)

<sub>This independent research library is not an official CrowdStrike or MITRE product. Names and logos belong to their respective owners. Catalog totals are a static snapshot and must be updated manually when queries change.</sub>
