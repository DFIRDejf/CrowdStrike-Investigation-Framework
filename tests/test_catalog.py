"""Offline QA regression tests for the CQL catalog generator."""
import tempfile
import unittest
from pathlib import Path
from scripts.catalog import CatalogError, build, FENCE

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

Run the query.
"""

BASE_QUERY = """[← Home](../README.md) · [All queries](../QUERY-CATALOG.md)

# Reconnaissance

**CrowdStrike Falcon / NG-SIEM** · **CQL** · `TA0043` · **1 queries**

Reconnaissance query testing.

## Query library

| Hunt | MITRE | Status |
|:--|:--|:--|
| [01. Search with Nmap](#01-search-with-nmap) | T1046 | `Candidate` |

---

### 01. Search with Nmap

Check nmap execution.

**MITRE:** T1046

<details>
<summary><strong>If you want to see more details</strong></summary>

```cql
#event_simpleName=ProcessRollup2
| CommandLine=/nmap/i
```

**False positives:** Authorized scanning.

</details>
"""

SECOND = """
### 02. DNS Lookups

Inspect DNS queries.

**MITRE:** T1590 · **Status:** `Requires Validation`

<details>
<summary><strong>If you want to see more details</strong></summary>

```cql
#event_simpleName=DnsRequest
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
        (self.root / "01-Reconnaissance" / "README.md").write_text(BASE_QUERY, encoding="utf-8")
        (self.root / "17-Query-Builder-Helper").mkdir()
        (self.root / "17-Query-Builder-Helper" / "README.md").write_text(HELPER, encoding="utf-8")
        (self.root / "22-Detection-Engineering").mkdir()
        (self.root / "22-Detection-Engineering" / "README.md").write_text("# Detection Engineering\n", encoding="utf-8")

    def test_catalog_and_technique_links_generated(self):
        outputs = build(self.root)
        catalog = outputs[self.root / "QUERY-CATALOG.md"]
        self.assertIn("| [Search with Nmap]", catalog)
        self.assertIn("01-Reconnaissance/README.md#01-search-with-nmap", catalog)
        self.assertIn("`T1046`", outputs[self.root / "MITRE-TECHNIQUE-INDEX.md"])

    def test_added_hunt_rebuilds_index_and_counts_without_editing_cql(self):
        path = self.root / "01-Reconnaissance" / "README.md"
        original = path.read_text(encoding="utf-8") + SECOND
        path.write_text(original, encoding="utf-8")
        generated = build(self.root)
        self.assertIn("| [02. DNS Lookups](#02-dns-lookups)", generated[path])
        self.assertIn("**3 documented CQL queries**", generated[self.root / "QUERY-CATALOG.md"])
        self.assertIn("Browse all 3 queries", generated[self.root / "README.md"])
        self.assertEqual(FENCE.findall(original), FENCE.findall(generated[path]))
        for file, content in generated.items():
            file.write_text(content, encoding="utf-8")
        self.assertTrue(all(p.read_text(encoding="utf-8") == val for p, val in build(self.root).items()))

    def test_duplicate_query_names_rejected(self):
        p = self.root / "01-Reconnaissance" / "README.md"
        p.write_text(BASE_QUERY + SECOND.replace("DNS Lookups", "Search with Nmap"), encoding="utf-8")
        with self.assertRaisesRegex(CatalogError, "duplicated query title"):
            build(self.root)

    def test_missing_cql_block_rejected(self):
        p = self.root / "01-Reconnaissance" / "README.md"
        p.write_text(BASE_QUERY.replace("```cql", "```text"), encoding="utf-8")
        with self.assertRaisesRegex(CatalogError, "one fenced cql"):
            build(self.root)

    def test_invalid_status_rejected(self):
        p = self.root / "01-Reconnaissance" / "README.md"
        p.write_text(BASE_QUERY.replace("`Candidate`", "`Approved`"), encoding="utf-8")
        with self.assertRaisesRegex(CatalogError, "unsupported validation status"):
            build(self.root)

    def test_deprecated_directory_rejected(self):
        (self.root / "15-Investigation-Timelines").mkdir()
        with self.assertRaisesRegex(CatalogError, "deprecated"):
            build(self.root)

    def test_preserves_exact_cql(self):
        p = self.root / "01-Reconnaissance" / "README.md"
        source = p.read_text(encoding="utf-8")
        self.assertEqual(FENCE.findall(source), FENCE.findall(build(self.root)[p]))


if __name__ == "__main__":
    unittest.main()
