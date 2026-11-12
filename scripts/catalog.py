#!/usr/bin/env python3
"""Keep CrowdStrike CQL README indexes and navigation synchronized.

Source of truth: numeric query headings, CQL code fences, query-level Status
metadata, and the existing query-index status for older entries. No CQL is
rewritten. Uses Python standard library only.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
HEADING = re.compile(r"^### (\d{2})\. ([^\r\n]+)$", re.M)
FENCE = re.compile(r"^```cql[ \t]*\r?\n(.*?)^```[ \t]*$", re.M | re.S)
INDEX = re.compile(r"^\|\s*\[(\d{2})\. ([^\]]+)\]\(#[^)]+\)\s*\|(.+?)\|\s*$", re.M)
MITRE_ID = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
ALLOWED = (
    "Migration recheck", "Candidate", "Community candidate",
    "Requires Validation", "Tested", "Production reviewed",
)
DESCRIPTIONS = {
    "Migration recheck": "Previously tested source; publication copy needs revalidation",
    "Candidate": "New example awaiting tenant validation",
    "Community candidate": "Adapted community example awaiting validation",
    "Requires Validation": "OneNote or contributed query awaiting validation",
    "Tested": "Exact query version tested in a documented environment",
    "Production reviewed": "Reviewed for deployment with QA evidence",
}


class CatalogError(Exception):
    """Actionable library consistency failure."""


@dataclass(frozen=True)
class Hunt:
    folder: str
    number: str
    name: str
    anchor: str
    mitre: str
    telemetry: str
    status: str

    @property
    def link(self) -> str:
        return f"{self.folder}/README.md#{self.anchor}"


def anchor(text: str) -> str:
    """GitHub-friendly slug for ASCII and Unicode query headings."""
    text = text.lower().strip()
    text = re.sub(r"[^\w\- ]", "", text, flags=re.UNICODE)
    return text.replace(" ", "-")


def extract_statuses(source: str) -> dict[str, str]:
    out = {}
    for number, _name, cols in INDEX.findall(source):
        statuses = [item for item in re.findall(r"`([^`]+)`", cols) if item in ALLOWED]
        if statuses:
            out[number] = statuses[-1]
    return out


def require_unique(path: Path, entries: list[Hunt]) -> None:
    names = [q.name.casefold() for q in entries]
    slugs = [q.anchor for q in entries]
    if len(set(names)) != len(names):
        raise CatalogError(f"{path}: duplicated query title")
    if len(set(slugs)) != len(slugs):
        raise CatalogError(f"{path}: duplicated query anchor")


def parse_category(path: Path) -> tuple[list[Hunt], str]:
    source = path.read_text(encoding="utf-8")
    heads = list(HEADING.finditer(source))
    if not heads:
        return [], source
    if "## Query library\n" not in source:
        raise CatalogError(f"{path}: missing '## Query library' heading")
    old_status = extract_statuses(source)
    hunts = []
    for i, head in enumerate(heads):
        number, name = head.groups()
        if int(number) != i + 1:
            raise CatalogError(f"{path}: expected sequential index {i + 1:02d}, got {number}")
        block = source[head.end(): heads[i + 1].start() if i + 1 < len(heads) else len(source)]
        code = FENCE.findall(block)
        if len(code) != 1:
            raise CatalogError(f"{path}: {name}: expected exactly one fenced cql block, got {len(code)}")
        if not code[0].strip():
            raise CatalogError(f"{path}: {name}: empty CQL")
        if block.count("<details>") != 1 or block.count("</details>") != 1:
            raise CatalogError(f"{path}: {name}: expected one balanced <details> block")
        if "<summary>" not in block:
            raise CatalogError(f"{path}: {name}: missing dropdown summary")
        m = re.search(r"^\*\*MITRE:\*\*\s*([^\r\n]*)", block, re.M)
        mitre = re.split(r"\s*·\s*\*\*", m.group(1))[0].strip().rstrip("\\").strip() if m else "—"
        m = re.search(r"\*\*Status:\*\*\s*`([^`]+)`", block)
        status = m.group(1) if m else old_status.get(number)
        if status not in ALLOWED:
            raise CatalogError(f"{path}: {name}: missing/unsupported validation status ({status!r})")
        m = re.search(r"\*\*Telemetry:\*\*\s*([^\r\n]+)", block)
        if m:
            telemetry = m.group(1).strip().rstrip("\\")
        else:
            event_names = re.findall(r"#event_simpleName\s*=\s*([A-Za-z][A-Za-z0-9_]*)", code[0])
            telemetry = event_names[0] if len(set(event_names)) == 1 else "See query"
        hunts.append(Hunt(path.parent.name, number, name.strip(),
                          anchor(f"{number}. {name}"), mitre, telemetry, status))
    require_unique(path, hunts)
    return hunts, source


def escape(s: str) -> str:
    return s.replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def render_category(source: str, hunts: list[Hunt]) -> str:
    if not hunts:
        return source
    start = source.find("## Query library\n")
    head = HEADING.search(source)
    if start < 0 or not head or head.start() <= start:
        raise CatalogError("query index boundaries not found")
    rows = ["## Query library", "", "| Hunt | MITRE | Status |", "|:--|:--|:--|"]
    for q in hunts:
        rows.append(f"| [{q.number}. {escape(q.name)}](#{q.anchor}) | {escape(q.mitre)} | `{q.status}` |")
    index = "\n".join(rows) + "\n\n---\n\n"
    result = source[:start] + index + source[head.start():]
    result = re.sub(r"\*\*\d+ queries\*\*", f"**{len(hunts)} queries**", result, count=1)
    return result


def render_catalog(all_hunts: list[Hunt]) -> str:
    n_tactics = len({q.folder for q in all_hunts if 1 <= int(q.folder[:2]) <= 14})
    n_modules = len({q.folder for q in all_hunts if int(q.folder[:2]) > 14})
    lines = [
        "# CQL Query Catalog", "",
        "[← Framework home](README.md) · [MITRE Technique Index](MITRE-TECHNIQUE-INDEX.md)", "",
        f"**{len(all_hunts)} documented CQL queries** · **{n_tactics} ATT&CK tactics** · **{n_modules} operational query modules**", "",
        "Use **Ctrl+F** to find a query by name, technique, event name, or category. Links open the exact query and analyst notes.", "",
        "> **Validation:** Statuses describe review history, not guaranteed query correctness or detection coverage.", "",
        "## All queries", "",
        "| Query | Category | MITRE ATT&CK | Telemetry | Status |",
        "|:--|:--|:--|:--|:--|",
    ]
    for q in all_hunts:
        title = q.folder[3:].replace("-", " ")
        lines.append(f"| [{escape(q.name)}]({q.link}) | [{title}]({q.folder}/README.md) | "
                     f"{escape(q.mitre)} | {escape(q.telemetry)} | `{q.status}` |")
    lines += ["", "---", "", "**Validation states:** " + " · ".join(f"`{x}`" for x in ALLOWED) +
              ". See [Detection Engineering](22-Detection-Engineering/README.md) for review criteria.",
              "", "[← Framework home](README.md)", ""]
    return "\n".join(lines)


def render_techniques(hunts: list[Hunt]) -> str:
    mapping = defaultdict(list)
    for q in hunts:
        for t in sorted(set(MITRE_ID.findall(q.mitre))):
            mapping[t].append(q)
    lines = ["# MITRE ATT&CK Technique Index", "",
             "[← Framework home](README.md) · [All queries](QUERY-CATALOG.md)", "",
             f"**{len(mapping)} distinct technique identifiers** referenced by query descriptions. "
             "An association does not imply validated detection coverage.", "",
             "Use **Ctrl+F** to look up a technique ID, e.g. `T1021.002`.", "",
             "| Technique | Query links | Count |", "|:--|:--|--:|"]
    for t, qs in sorted(mapping.items()):
        links = " · ".join(f"[{escape(q.name)}]({q.link})" for q in qs)
        lines.append(f"| `{t}` | {links} | {len(qs)} |")
    lines += ["", "> **Not a coverage metric:** These are metadata mappings and include unvalidated candidates.",
              "", "[← All queries](QUERY-CATALOG.md)", ""]
    return "\n".join(lines)


def render_root(source: str, hunts: list[Hunt]) -> str:
    total = len(hunts)
    source = re.sub(r"(Documented%20queries-)\d+", rf"\g<1>{total}", source)
    source = re.sub(r"(\[Browse all )\d+( queries\])", rf"\g<1>{total}\2", source)
    counts = Counter(q.folder for q in hunts)
    def tactic_row(m: re.Match[str]) -> str:
        folder = m.group(2).split("/")[0]
        return f"{m.group(1)}{counts.get(folder, 0)}{m.group(3)}"
    source = re.sub(r"(?m)^(\|\s*\d{2}\s*\|\s*\[[^\]]+\]\((\d{2}-[^)]+/README\.md)\)\s*\|\s*)\d+(\s*\|)", tactic_row, source)
    def module_row(m: re.Match[str]) -> str:
        folder = m.group(2).split("/")[0]
        return f"{m.group(1)}{counts[folder]} queries{m.group(3)}" if folder in counts else m.group(0)
    source = re.sub(r"(?m)^(\|\s*\[[^\]]+\]\((\d{2}-[^)]+/README\.md)\)\s*\|\s*)\d+ queries(\s*\|)$", module_row, source)
    start = source.find("## Validation at a glance\n")
    end = source.find("\n## ", start + 3)
    if start < 0 or end < 0:
        raise CatalogError("root README needs 'Validation at a glance' and next section")
    statuses = Counter(q.status for q in hunts)
    table = ["## Validation at a glance", "", "| State | Entries | Meaning |", "|:--|--:|:--|"]
    for st in ALLOWED:
        if statuses[st]:
            table.append(f"| `{st}` | {statuses[st]} | {DESCRIPTIONS[st]} |")
    table.extend([f"| **Total** | **{total}** | Documented query entries; no production-readiness claim |", ""])
    source = source[:start] + "\n".join(table) + source[end:]
    source = source.replace("Counts represent the November 2026 documentation snapshot.",
                            "Query counts are maintained by the repository catalog generator.")
    return source


def local_link_errors(root: Path, changed: dict[Path, str]) -> list[str]:
    errors = []
    for path, content in changed.items():
        for target in re.findall(r"\[[^\]]+\]\(([^)]+)\)", content):
            if target.startswith(("http://", "https://", "mailto:", "#")):
                continue
            rel = target.split("#")[0].split("?")[0]
            if not rel:
                continue
            dest = (path.parent / rel).resolve()
            if not dest.is_relative_to(root.resolve()) or (dest not in changed and not dest.exists()):
                errors.append(f"{path.relative_to(root)}: broken local link {target}")
    return errors


def build(root: Path) -> dict[Path, str]:
    if (root / "15-Investigation-Timelines").exists():
        raise CatalogError("deprecated 15-Investigation-Timelines folder must remain absent")
    generated: dict[Path, str] = {}
    hunts: list[Hunt] = []
    for path in sorted(root.glob("[0-9][0-9]-*/README.md")):
        parsed, content = parse_category(path)
        if not parsed:
            continue
        hunts.extend(parsed)
        generated[path] = render_category(content, parsed)
    if not hunts:
        raise CatalogError("No CQL query headings found")
    generated[root / "QUERY-CATALOG.md"] = render_catalog(hunts)
    generated[root / "MITRE-TECHNIQUE-INDEX.md"] = render_techniques(hunts)
    home = root / "README.md"
    generated[home] = render_root(home.read_text(encoding="utf-8"), hunts)
    errors = local_link_errors(root, generated)
    if errors:
        raise CatalogError("\n".join(errors[:20]))
    return generated


def main() -> int:
    arg = argparse.ArgumentParser(description=__doc__)
    mode = arg.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true", help="Regenerate generated Markdown indexes")
    mode.add_argument("--check", action="store_true", help="Fail if indexes/counts are out of sync")
    arg.add_argument("--root", type=Path, default=ROOT, help="Repository root (for testing)")
    args = arg.parse_args()
    try:
        generated = build(args.root.resolve())
    except (CatalogError, UnicodeDecodeError) as exc:
        print(f"CQL library QA error: {exc}", file=sys.stderr)
        return 2
    stale = [path for path, content in generated.items()
             if not path.exists() or path.read_text(encoding="utf-8") != content]
    if args.write:
        for path in stale:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(generated[path], encoding="utf-8", newline="\n")
        print(f"Catalog sync: {len(stale)} file(s) updated; {sum(x.count('```cql') for x in generated.values())} CQL fences in category indexes")
        return 0
    if stale:
        print("Generated files are out of sync. Run: python scripts/catalog.py --write", file=sys.stderr)
        for path in stale:
            print(" - " + str(path.relative_to(args.root.resolve())), file=sys.stderr)
        return 1
    print(f"CQL library QA OK: {len(generated)} generated files up-to-date")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
