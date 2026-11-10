# MITRE ATT&CK Mapping Notes — November 2026

The official Enterprise ATT&CK matrix currently has **15 tactics**, including **Stealth** (`TA0005`) and **Defense Impairment** (`TA0112`). The legacy **Defense Evasion** category was replaced by these two tactics. See the [official ATT&CK Enterprise matrix](https://attack.mitre.org/matrices/enterprise/).

## Compatibility Strategy

This integration pack **retains** the existing `07-Defense-Evasion/` directory so the user's GitHub links are not unexpectedly broken. It is a legacy folder name **not** an up-to-date Enterprise ATT&CK tactic. The two included candidate hunts primarily cover defensive control impairment. MITRE technique mapping for each query must be reviewed against current technique pages.

For future taxonomy cleanup, create new `Stealth` and `Defense-Impairment` folders through a separate pull request; migrate entries, update root navigation and technique mappings, then remove the legacy folder. No automatic rename or renumbering was performed in v2.

Reference version: [MITRE ATT&CK v20.1 version history](https://attack.mitre.org/resources/versions/).
