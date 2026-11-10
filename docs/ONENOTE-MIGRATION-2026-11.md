# OneNote CQL Migration — 2026-11-10

[← Framework home](../README.md)

## Scope

Added **58 additional CrowdStrike CQL candidate queries** across all **14 ATT&CK tactic folders**, from Reconnaissance to Impact, based on readable sections of the user-provided `CS Queries.one`.

All new entries are **Requires Validation** and remain embedded in their existing tactic `README.md` files with an expandable **If you want to see more details** section.

## Additions by category

| Category | New CQL entries |
|---|---:|
| [01-Reconnaissance](../01-Reconnaissance/README.md) | 3 |
| [02-Resource-Development](../02-Resource-Development/README.md) | 3 |
| [03-Initial-Access](../03-Initial-Access/README.md) | 4 |
| [04-Execution](../04-Execution/README.md) | 3 |
| [05-Persistence](../05-Persistence/README.md) | 3 |
| [06-Privilege-Escalation](../06-Privilege-Escalation/README.md) | 3 |
| [07-Defense-Evasion](../07-Defense-Evasion/README.md) | 6 |
| [08-Credential-Access](../08-Credential-Access/README.md) | 6 |
| [09-Discovery](../09-Discovery/README.md) | 4 |
| [10-Lateral-Movement](../10-Lateral-Movement/README.md) | 5 |
| [11-Collection](../11-Collection/README.md) | 5 |
| [12-Command-and-Control](../12-Command-and-Control/README.md) | 4 |
| [13-Exfiltration](../13-Exfiltration/README.md) | 5 |
| [14-Impact](../14-Impact/README.md) | 4 |
| **Total** | **58** |

## Migration rules

- Preserved the existing 53 CQL query blocks without changing their contents.
- Adapted complete, legible OneNote CQL patterns into sanitized reusable hunting examples; these are **not** claimed to be exact byte-for-byte exports of all OneNote code.
- Avoided hardcoded corporate hosts, users, email addresses, customer address ranges and case-specific identifiers.
- Consolidated repeated OneNote variations and excluded material already represented in the existing library.
- Excluded non-CQL XQL examples and corrupted/incomplete fragments.
- Image-only OneNote pages, partially garbled material, and event fields lacking sufficient source context may contain additional patterns **not recovered in this migration**.
- Did not restore `15-Investigation-Timelines`; no KQL, XQL or Foundry dependencies were added.

## Review requirements

1. Validate syntax and availability of `#event_simpleName` and selected fields via `fieldset()` in your tenant.
2. Check whether filters use field types correctly (e.g., ports vs strings) and match actual event semantics.
3. Review host/process and network direction assumptions, then validate event counts and timestamp units.
4. Tune false positives, thresholds, internal CIDR exclusions and result limits to your deployment.
5. Verify each proposed MITRE technique mapping against current ATT&CK and applicable telemetry.
6. Promote to `Tested` or `Production reviewed` **only after** recording environment-specific execution and reviewer evidence.

**Caution:** An event or command-line indicator is a hunting lead; it does not alone establish compromise, data exfiltration, or successful attacker impact.
