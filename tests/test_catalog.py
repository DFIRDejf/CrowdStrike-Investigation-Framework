"""Offline regression tests for v4.4 GitHub CQL documentation tooling."""
import tempfile
import unittest
from pathlib import Path

from scripts.catalog import CatalogError, FENCE, build, event_names, duplicate_pairs, parse_category

HOME = """# Test framework

![Queries](https://img.shields.io/badge/Documented%20queries-1-grey)
[Browse all 1 queries](QUERY-CATALOG.md)

## ATT&CK hunting library

| # | Tactic | Queries | Focus |
| 01 | [Reconnaissance](01-Reconnaissance/README.md) | 1 | Recon |

## Operational modules

| Module | Content |
| [Query Builder](17-Query-Builder-Helper/README.md) | 1 queries |

## Validation at a glance

| State | Entries | Meaning |
| `Candidate` | 1 | Example |
| **Total** | **1** | Documented |

## How to use

Expand If you want to see more details.
"""

QUERY = """[← Home](../README.md) · [All queries](../QUERY-CATALOG.md)

# Reconnaissance

**CrowdStrike Falcon / NG-SIEM** · **CQL** · `TA0043` · **1 queries**

Reconnaissance investigations.

---

## Query library

| Hunt | MITRE | Status |
|:--|:--|:--|
| [01. Search with Nmap](#01-search-with-nmap) | T1046 | `Candidate` |

---

### 01. Search with Nmap

Detect nmap command execution.

**MITRE:** T1046 · **Source:** `CS Queries.one` · **Status:** `Candidate`

<details>
<summary><strong>If you want to see more details</strong></summary>

```cql
#event_simpleName=ProcessRollup2
| CommandLine=/nmap/i
```

**False positives:** Authorized scans.

*Origin: OneNote-derived adaptation*

</details>
"""

SECOND = """
### 02. DNS Lookups

Inspect DNS queries.

**MITRE:** T1590 · **Status:** `Requires Validation`

<details>
<summary><strong>If you want to see more details</strong></summary>

```cql
#event_simpleName=/^(DnsRequest|BrowserHistoryVisit)$/
| select([@timestamp, DomainName])
```

</details>
"""

HELPER = """# Query Builder Helper

**1 queries**

## Query library

| Hunt | MITRE | Status |
|:--|:--|:--|
| [01. Helper](#01-helper) | — | `Migration recheck` |

---

### 01. Helper

Build pivots.

**MITRE:** —

<details>
<summary><strong>If you want to see more details</strong></summary>

```cql
#event_simpleName=ProcessRollup2
```

</details>
"""


class CatalogTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / "README.md").write_text(HOME, encoding="utf-8")
        (self.root / "01-Reconnaissance").mkdir()
        self.path = self.root / "01-Reconnaissance" / "README.md"
        self.path.write_text(QUERY, encoding="utf-8")
        (self.root / "17-Query-Builder-Helper").mkdir()
        (self.root / "17-Query-Builder-Helper" / "README.md").write_text(HELPER, encoding="utf-8")

    def write_generated(self):
        documents = build(self.root)
        for file, content in documents.items():
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_text(content, encoding="utf-8")
        return documents

    def test_generates_stable_ids_links_and_normalizes_statuses(self):
        docs = self.write_generated()
        page = docs[self.path]
        catalog = docs[self.root / "QUERY-CATALOG.md"]
        self.assertIn('name="cs-ta0043-001"', page)
        self.assertIn("**Query ID:** `CS-TA0043-001`", page)
        self.assertIn("**Status:** `Requires Validation`", page)
        self.assertIn("01-Reconnaissance/README.md#cs-ta0043-001", catalog)
        self.assertIn("Show CrowdStrike query", page)
        self.assertNotIn("Source:", page)
        self.assertNotIn("Origin:", page)
        self.assertIn("`Requires Validation`", docs[self.root / "README.md"])

    def test_cql_preserved_and_generator_idempotent(self):
        original = self.path.read_text(encoding="utf-8")
        self.write_generated()
        self.assertEqual(FENCE.findall(original), FENCE.findall(self.path.read_text(encoding="utf-8")))
        self.assertTrue(all(p.read_text(encoding="utf-8") == content for p, content in build(self.root).items()))

    def test_stable_id_survives_renamed_query(self):
        self.write_generated()
        text = self.path.read_text(encoding="utf-8").replace(
            "### 01. Search with Nmap", "### 01. Renamed Nmap Hunt")
        self.path.write_text(text, encoding="utf-8")
        docs = self.write_generated()
        self.assertIn("Renamed Nmap Hunt", docs[self.root / "QUERY-CATALOG.md"])
        self.assertIn("README.md#cs-ta0043-001", docs[self.root / "QUERY-CATALOG.md"])

    def test_adds_query_and_telemetry_index(self):
        self.path.write_text(QUERY + SECOND, encoding="utf-8")
        docs = self.write_generated()
        self.assertIn("**3 queries**", docs[self.root / "QUERY-CATALOG.md"])
        self.assertIn("Browse all 3 queries", docs[self.root / "README.md"])
        self.assertIn("DnsRequest", docs[self.root / "TELEMETRY-INDEX.md"])
        self.assertIn("BrowserHistoryVisit", docs[self.root / "TELEMETRY-INDEX.md"])
        self.assertIn("`T1590`", docs[self.root / "MITRE-TECHNIQUE-INDEX.md"])

    def test_duplicate_query_titles_are_rejected(self):
        self.path.write_text(QUERY + SECOND.replace("DNS Lookups", "Search with Nmap"), encoding="utf-8")
        with self.assertRaisesRegex(CatalogError, "duplicated query title"):
            build(self.root)

    def test_missing_cql_is_rejected(self):
        self.path.write_text(QUERY.replace("```cql", "```text"), encoding="utf-8")
        with self.assertRaisesRegex(CatalogError, "one CQL code fence"):
            build(self.root)

    def test_invalid_status_is_rejected(self):
        self.path.write_text(QUERY.replace("`Candidate`", "`Approved`"), encoding="utf-8")
        with self.assertRaisesRegex(CatalogError, "unknown validation status"):
            build(self.root)

    def test_deprecated_folder_is_rejected(self):
        (self.root / "15-Investigation-Timelines").mkdir()
        with self.assertRaisesRegex(CatalogError, "deprecated"):
            build(self.root)

    def test_duplicate_cql_report_is_advisory(self):
        duplicate = self.root / "02-Resource-Development"
        duplicate.mkdir()
        (duplicate / "README.md").write_text(
            QUERY.replace("Search with Nmap", "Other Nmap Title")
                 .replace("Reconnaissance", "Resource Development"),
            encoding="utf-8")
        docs = self.write_generated()
        report = docs[self.root / "docs/QUERY-DUPLICATES.md"]
        self.assertIn("CS-TA0043-001", report)
        self.assertIn("CS-TA0042-001", report)
        self.assertIn("exact pairs", report)

    def test_extracts_explicit_regex_events(self):
        self.assertEqual(("BrowserHistoryVisit", "DnsRequest"),
                         event_names("#event_simpleName=/^(DnsRequest|BrowserHistoryVisit)$/"))


if __name__ == "__main__":
    unittest.main()
