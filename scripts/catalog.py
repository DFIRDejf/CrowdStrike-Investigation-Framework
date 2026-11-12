#!/usr/bin/env python3
"""CQL catalog v4.4: stable IDs, presentation metadata, indexes and structural QA.

Read-only CQL: generator never edits a fenced cql block.
Only Python standard library is required.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from dataclasses import dataclass
from difflib import SequenceMatcher
from hashlib import sha256
from itertools import combinations
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
HEAD = re.compile(r"^### (\d{2})\. ([^\r\n]+)$", re.M)
FENCE = re.compile(r"^```cql[ \t]*\r?\n(.*?)^```[ \t]*$", re.M | re.S)
INDEX = re.compile(r"^\|\s*\[(\d{2})\. ([^\]]+)\]\(#[^)]+\)\s*\|(.+?)\|\s*$", re.M)
MITRE_ID = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
ANCHOR = re.compile(r'<a name="(cs-[a-z0-9-]+)"></a>\s*$')
ID_META = re.compile(r"\*\*Query ID:\*\*\s*`(CS-[A-Z0-9-]+)`")
EXPLICIT = re.compile(r'#event_simpleName\s*=\s*(?:"([A-Za-z]\w+)"|([A-Za-z]\w+))')
EVENT_GROUP = re.compile(r'#event_simpleName\s*=\s*/\^\(([\w|]+)\)\$/[a-z]*')
PLATFORMS = {"Win": "Windows", "Lin": "Linux", "Mac": "macOS"}
ALLOWED = ("Requires Validation", "Tested", "Production reviewed")
LEGACY = ("Candidate", "Community candidate", "Migration recheck")
DESCRIPTIONS = {
    "Requires Validation": "Not tested or publication copy awaiting validation in Falcon",
    "Tested": "Exact query version tested in a documented tenant",
    "Production reviewed": "Peer-reviewed with evidence and approved operating context",
}
PREFIX = {
    "01": "TA0043", "02": "TA0042", "03": "TA0001", "04": "TA0002",
    "05": "TA0003", "06": "TA0004", "07": "TA0005", "08": "TA0006",
    "09": "TA0007", "10": "TA0008", "11": "TA0009", "12": "TA0011",
    "13": "TA0010", "14": "TA0040", "16": "FA", "17": "QB", "21": "CQF",
}


class CatalogError(Exception):
    """Hunt structure or index error."""


@dataclass(frozen=True)
class Hunt:
    folder: str
    number: str
    name: str
    query_id: str
    mitre: str
    status: str
    platform: str
    tags: tuple[str, ...]
    events: tuple[str, ...]
    code: str

    @property
    def link(self) -> str:
        return f"{self.folder}/README.md#{self.query_id.lower()}"


def cql_blocks(text: str) -> list[str]:
    return FENCE.findall(text)


def event_names(code: str) -> tuple[str, ...]:
    names = set()
    for m in EXPLICIT.finditer(code):
        names.add(m.group(1) or m.group(2))
    for m in EVENT_GROUP.finditer(code):
        names.update(m.group(1).split("|"))
    return tuple(sorted(names))


def platform_of(code: str) -> str:
    matched = set(re.findall(r"\bevent_platform\s*=\s*(Win|Lin|Mac)\b", code))
    return " / ".join(PLATFORMS[x] for x in sorted(matched)) if matched else "Not scoped"


def tags_of(names: tuple[str, ...]) -> tuple[str, ...]:
    found = set()
    for name in names:
        l = name.lower()
        if any(k in l for k in ("smb", "share")): found.add("SMB")
        if any(k in l for k in ("dns", "domainquery")): found.add("DNS")
        if any(k in l for k in ("network", "tcp", "udp", "ftp", "ssh")): found.add("Network")
        if any(k in l for k in ("process", "command", "shell", "script", "macro")): found.add("Process")
        if any(k in l for k in ("wmi",)): found.add("WMI")
        if any(k in l for k in ("file", "usn", "prefetch", "mft", "archive", "genericwritten")): found.add("File")
        if any(k in l for k in ("activedirectory", "logon", "auth", "account", "sso", "idp", "kerberos", "usergroup")): found.add("Identity")
        if "browser" in l: found.add("Browser")
        if "sru" in l: found.add("SRU")
        if any(k in l for k in ("sensor", "firewall", "wfp", "prevention", "antitamper")): found.add("Security")
    return tuple(sorted(found)) if found else ("See query",)


def escape(text: str) -> str:
    return text.replace("|", r"\|").replace("\n", " ").replace("\r", " ")


def prior_statuses(source: str) -> dict[str, str]:
    out = {}
    for number, _, columns in INDEX.findall(source):
        states = re.findall(r"`([^`]+)`", columns)
        if states: out[number] = states[-1]
    return out


def split_hunts(source: str) -> tuple[str, list[tuple[str, str, str, str | None]]]:
    heads = list(HEAD.finditer(source))
    if not heads:
        return source, []
    positions = []
    for h in heads:
        prev = source[:h.start()]
        match = ANCHOR.search(prev)
        positions.append(match.start() if match else h.start())
    prefix = source[:positions[0]]
    blocks = []
    for i, h in enumerate(heads):
        chunk = source[positions[i]:positions[i + 1] if i + 1 < len(positions) else len(source)]
        anchor = re.match(r'<a name="(cs-[a-z0-9-]+)"></a>\s*\n?', chunk)
        existing = anchor.group(1) if anchor else None
        head_in_chunk = HEAD.search(chunk)
        if head_in_chunk is None: raise CatalogError("Missing query heading")
        body = chunk[head_in_chunk.end():]
        blocks.append((h.group(1), h.group(2), body, existing))
    return prefix, blocks


def strip_outside_cql(body: str, status: str, qid: str, code: str) -> str:
    # The CQL fence and its entire content are untouched.
    match = re.search(r"(?m)^\*\*MITRE:\*\*[^\r\n]*", body)
    if not match: raise CatalogError(f"{qid}: missing MITRE metadata")
    raw_mitre = re.split(r"\s*·\s*\*\*(?:Telemetry|Source|Status|Platform|Tags):", match.group())
    mitre = raw_mitre[0].replace("**MITRE:**", "").strip().rstrip("\\").strip()
    platform = platform_of(code)
    tags = tags_of(event_names(code))
    meta = (f"**Query ID:** `{qid}` · **Platform:** `{platform}` · **Tags:** " +
            ", ".join(f"`{t}`" for t in tags) + "\n\n" +
            f"**MITRE:** {mitre} · **Status:** `{status}`")
    # Strip any prior generated metadata before replacing the MITRE line.
    no_meta = re.sub(r"(?m)^\*\*Query ID:\*\*.*\n(?:\n)?", "", body)
    no_meta = re.sub(r"(?m)^\*\*MITRE:\*\*[^\r\n]*", lambda _: meta, no_meta, count=1)
    # Keep attribution with the central source document; leave community URLs intact.
    no_meta = re.sub(r"(?m)^\*Origin:.*\*\s*\n?", "", no_meta)
    no_meta = no_meta.replace("<strong>If you want to see more details</strong>",
                              "<strong>Show CrowdStrike query</strong>")
    return no_meta


def normalize_category(source: str, folder: str) -> str:
    prefix, chunks = split_hunts(source)
    if not chunks:
        return source
    existing = set(x[3] for x in chunks if x[3])
    old_states = prior_statuses(source)
    used = set(existing)
    serial = max([int(x.rsplit("-", 1)[-1]) for x in existing if x.rsplit("-", 1)[-1].isdigit()] or [0])
    out = [prefix]
    for i, (num, title, body, anchor_id) in enumerate(chunks):
        code = cql_blocks(body)
        if len(code) != 1: raise CatalogError(f"{folder}/{num}: expected one CQL code fence")
        if anchor_id:
            qid = anchor_id.upper()
        else:
            serial += 1
            qid = f"CS-{PREFIX[folder[:2]]}-{serial:03d}"
        if qid.lower() in used and not anchor_id:
            raise CatalogError(f"duplicate generated ID {qid}")
        used.add(qid.lower())
        found = re.search(r"\*\*Status:\*\*\s*`([^`]+)`", body)
        old = found.group(1) if found else old_states.get(num, "Requires Validation")
        if old not in ALLOWED + LEGACY: raise CatalogError(f"{folder}/{num}: unknown validation status {old}")
        status = "Requires Validation" if old in LEGACY else old
        before = cql_blocks(body)
        newbody = strip_outside_cql(body, status, qid, code[0])
        if cql_blocks(newbody) != before:
            raise CatalogError(f"{qid}: generator attempted to change CQL")
        out.append(f'<a name="{qid.lower()}"></a>\n\n### {num}. {title}{newbody}')
    result = "".join(out)
    result = re.sub(r"(?m)^`Migration recheck` = .*",
                    "`Requires Validation` = not yet tenant-validated · `Tested` = exact-version tested · `Production reviewed` = peer-reviewed with evidence.", result)
    return result


def parse_category(path: Path, source: str) -> list[Hunt]:
    heads = list(HEAD.finditer(source))
    if not heads: return []
    if "## Query library\n" not in source: raise CatalogError(f"{path}: missing query index")
    hunts = []
    ids = set()
    for i, h in enumerate(heads):
        number, name = h.groups()
        if int(number) != i + 1: raise CatalogError(f"{path}: expected sequential query number {i+1:02d}")
        block = source[h.end():heads[i + 1].start() if i+1<len(heads) else len(source)]
        codes = cql_blocks(block)
        if len(codes) != 1 or not codes[0].strip(): raise CatalogError(f"{path}: {name}: expected one nonempty CQL block")
        if block.count("<details>") != 1 or block.count("</details>") != 1:
            raise CatalogError(f"{path}: {name}: expected one balanced details block")
        if "<summary>" not in block: raise CatalogError(f"{path}: {name}: missing dropdown label")
        p = ANCHOR.search(source[:h.start()])
        a = ID_META.search(block)
        if not p or not a or p.group(1).upper() != a.group(1):
            raise CatalogError(f"{path}: {name}: missing or mismatched stable query ID")
        qid = a.group(1)
        if qid in ids: raise CatalogError(f"{path}: duplicate ID {qid}")
        ids.add(qid)
        mitre = re.search(r"(?m)^\*\*MITRE:\*\*\s*(.*)", block)
        status = re.search(r"\*\*Status:\*\*\s*`([^`]+)`", block)
        if not status or status.group(1) not in ALLOWED:
            raise CatalogError(f"{path}: {name}: invalid validation status")
        if not mitre: raise CatalogError(f"{path}: {name}: missing MITRE field")
        mapping = mitre.group(1).split(" · **Status:**")[0].strip()
        platform = platform_of(codes[0]); events = event_names(codes[0])
        hunts.append(Hunt(path.parent.name, number, name, qid, mapping,
                          status.group(1), platform, tags_of(events), events, codes[0]))
    names = [x.name.lower() for x in hunts]
    if len(names) != len(set(names)): raise CatalogError(f"{path}: duplicated query title")
    return hunts


def render_category(source: str, hunts: list[Hunt]) -> str:
    if not hunts: return source
    start = source.find("## Query library\n")
    anchor_match = re.search(r'(?m)^<a name="cs-[a-z0-9-]+"></a>\s*\n\n### \d\d\.', source)
    if start < 0 or not anchor_match or anchor_match.start() <= start:
        raise CatalogError("Unable to locate query index/body boundary")
    rows = ["## Query library", "", "| Hunt | ID | MITRE | Status |", "|:--|:--|:--|:--|"]
    for q in hunts:
        rows.append(f"| [{q.number}. {escape(q.name)}](#{q.query_id.lower()}) | "
                    f"`{q.query_id}` | {escape(q.mitre)} | `{q.status}` |")
    output = source[:start] + "\n".join(rows) + "\n\n---\n\n" + source[anchor_match.start():]
    output = re.sub(r"\*\*\d+ queries\*\*", f"**{len(hunts)} queries**", output, count=1)
    return output


def render_catalog(hunts: list[Hunt]) -> str:
    n_tactics = len({q.folder for q in hunts if int(q.folder[:2]) <= 14})
    n_modules = len({q.folder for q in hunts if int(q.folder[:2]) > 14})
    lines = ["# CQL Query Catalog", "",
             "[← Home](README.md) · [MITRE techniques](MITRE-TECHNIQUE-INDEX.md) · "
             "[Telemetry index](TELEMETRY-INDEX.md)", "",
             f"**{len(hunts)} queries** · **{n_tactics} ATT&CK tactics** · **{n_modules} modules**", "",
             "Find a query with **Ctrl+F**. IDs and direct links remain stable when a query title changes.", "",
             "## All queries", "",
             "| Query | Stable ID | Category | MITRE | Status |", "|:--|:--|:--|:--|:--|"]
    for q in hunts:
        title=q.folder[3:].replace("-", " ")
        lines.append(f"| [{escape(q.name)}]({q.link}) | `{q.query_id}` | "
                     f"[{title}]({q.folder}/README.md) | {escape(q.mitre)} | `{q.status}` |")
    lines += ["", "**Status:** Requires Validation = not yet tested in the target Falcon environment. "
              "Tested and Production reviewed require recorded evidence.", "",
              "[← Home](README.md)", ""]
    return "\n".join(lines)


def render_techniques(hunts: list[Hunt]) -> str:
    mapping = defaultdict(list)
    for q in hunts:
        for t in sorted(set(MITRE_ID.findall(q.mitre))): mapping[t].append(q)
    lines = ["# MITRE ATT&CK Technique Index", "",
             "[← Home](README.md) · [All queries](QUERY-CATALOG.md)", "",
             f"**{len(mapping)} ATT&CK technique IDs** referenced in query metadata. "
             "Not a measure of validated detection coverage.", "",
             "| Technique | Queries | Count |", "|:--|:--|--:|"]
    for t, qs in sorted(mapping.items()):
        links = " · ".join(f"[{escape(q.name)}]({q.link})" for q in qs)
        lines.append(f"| `{t}` | {links} | {len(qs)} |")
    lines += ["", "> Contextual mappings are included; validate each technique mapping during QA.",
              "", "[← All queries](QUERY-CATALOG.md)", ""]
    return "\n".join(lines)


def render_telemetry(hunts: list[Hunt]) -> str:
    mapping = defaultdict(list)
    for q in hunts:
        for event in q.events: mapping[event].append(q)
    lines = ["# CQL Telemetry Index", "",
             "[← Home](README.md) · [All queries](QUERY-CATALOG.md)", "",
             f"**{len(mapping)} explicit event names** extracted from `#event_simpleName` query filters.", "",
             "Search with **Ctrl+F** for a Falcon event name. "
             "Only explicit names and simple anchored regex alternatives are indexed; "
             "complex/dynamic filters may not appear. Entries are **not verified tenant fieldsets**.", "",
             "| Event | Related queries | Count |", "|:--|:--|--:|"]
    for event, qs in sorted(mapping.items()):
        links=" · ".join(f"[{escape(q.name)}]({q.link})" for q in qs)
        lines.append(f"| `{event}` | {links} | {len(qs)} |")
    lines += ["", "Telemetry tags shown in query cards are **derived hints**, not proof of platform compatibility.", "",
              "[← All queries](QUERY-CATALOG.md)", ""]
    return "\n".join(lines)


def normalized_code(code: str) -> str:
    return re.sub(r"\s+", " ", code.strip()).casefold()


def duplicate_pairs(hunts: list[Hunt]) -> tuple[list[tuple[Hunt,Hunt]], list[tuple[float,Hunt,Hunt]]]:
    exact, near = [], []
    for a,b in combinations(hunts, 2):
        ca,cb=normalized_code(a.code),normalized_code(b.code)
        if ca == cb: exact.append((a,b)); continue
        if min(len(ca),len(cb)) < 140: continue
        if abs(len(ca)-len(cb))/max(len(ca),len(cb)) > 0.10: continue
        if a.events and b.events and not set(a.events).intersection(b.events): continue
        score = SequenceMatcher(None, ca, cb, autojunk=True).ratio()
        if score >= 0.94: near.append((score,a,b))
    near.sort(key=lambda t:(-t[0],t[1].query_id,t[2].query_id))
    return exact, near[:30]


def render_duplicates(hunts: list[Hunt]) -> str:
    exact, similar=duplicate_pairs(hunts)
    lines=["# CQL Duplicate Review", "",
           "[← Home](../README.md) · [All queries](../QUERY-CATALOG.md)", "",
           "Automated similarity checks are **advisory**. No query is deleted or modified. "
           "Legitimate reuse across tactics may be expected.", "",
           f"**{len(exact)} exact pairs** · **{len(similar)} high-similarity candidates shown**", "",
           "## Exact normalized-code matches", ""]
    if not exact: lines+=["No exact duplicate CQL blocks detected.", ""]
    else:
        for a,b in exact:
            lines.append(f"- [{a.query_id}](../{a.link}) and [{b.query_id}](../{b.link})")
        lines.append("")
    lines+=["## Similar candidates (≥ 0.94 similarity)", ""]
    if not similar: lines+=["No high-similarity candidate pairs detected.", ""]
    else:
        for score,a,b in similar:
            lines.append(f"- {score:.1%}: [{a.query_id}](../{a.link}) vs [{b.query_id}](../{b.link})")
        lines.append("")
    lines+=["The matcher uses normalized text and common event filters. A high score is not proof "
            "that two queries have equivalent hunting semantics.", ""]
    return "\n".join(lines)


def render_root(text: str, hunts: list[Hunt]) -> str:
    total=len(hunts); counts=Counter(q.folder for q in hunts)
    text = re.sub(r"(Documented%20queries-)\d+", rf"\g<1>{total}", text)
    text = re.sub(r"(\[Browse all )\d+( queries\])", rf"\g<1>{total}\2", text)
    def tactic_row(m: re.Match[str]) -> str:
        return f"{m.group(1)}{counts.get(m.group(2).split('/')[0],0)}{m.group(3)}"
    text = re.sub(r"(?m)^(\|\s*\d{2}\s*\|\s*\[[^\]]+\]\((\d{2}-[^)]+/README\.md)\)\s*\|\s*)\d+(\s*\|)", tactic_row,text)
    def module_row(m:re.Match[str]) -> str:
        folder=m.group(2).split("/")[0]
        return f"{m.group(1)}{counts[folder]} queries{m.group(3)}" if folder in counts else m.group(0)
    text=re.sub(r"(?m)^(\|\s*\[[^\]]+\]\((\d{2}-[^)]+/README\.md)\)\s*\|\s*)\d+ queries(\s*\|)$",module_row,text)
    start=text.find("## Validation at a glance\n");end=text.find("\n## ",start+3)
    if start<0 or end<0: raise CatalogError("Missing root validation table")
    statuses=Counter(q.status for q in hunts)
    rows=["## Validation at a glance","","| State | Entries | Meaning |","|:--|--:|:--|"]
    for st in ALLOWED:
        if statuses[st]: rows.append(f"| `{st}` | {statuses[st]} | {DESCRIPTIONS[st]} |")
    rows.extend([f"| **Total** | **{total}** | Documentation entries, not production-ready detections |",""])
    text=text[:start]+"\n".join(rows)+text[end:]
    text=text.replace("If you want to see more details","Show CrowdStrike query")
    text=text.replace("[**Contributing**]","[**Contributing**]")
    text=text.replace("| **Review telemetry coverage** | [Event & Field Reference](19-Event-and-Field-Reference/README.md) |",
        "| **Review telemetry coverage** | [Telemetry Index](TELEMETRY-INDEX.md) · [Event & Field Reference](19-Event-and-Field-Reference/README.md) |")
    if "[**Duplicate review**](docs/QUERY-DUPLICATES.md)" not in text:
        text=text.replace("[**Query template**](templates/QUERY_TEMPLATE.md)",
            "[**Query template**](templates/QUERY_TEMPLATE.md) · [**Duplicate review**](docs/QUERY-DUPLICATES.md)")
    return text


def local_link_errors(root:Path, output:dict[Path,str])->list[str]:
    errors=[]
    for path,content in output.items():
        for target in re.findall(r"\[[^\]]+\]\(([^)]+)\)",content):
            if target.startswith(("http://","https://","mailto:","#")): continue
            rel=target.split("#")[0].split("?")[0]
            dest=(path.parent/rel).resolve()
            if not dest.is_relative_to(root.resolve()) or (dest not in output and not dest.exists()):
                errors.append(f"{path.relative_to(root)}: broken link {target}")
    return errors


def build(root:Path)->dict[Path,str]:
    if (root/"15-Investigation-Timelines").exists():
        raise CatalogError("deprecated Investigation-Timelines folder is not permitted")
    output={};hunts=[]
    for path in sorted(root.glob("[0-9][0-9]-*/README.md")):
        source=path.read_text(encoding="utf-8")
        if not HEAD.search(source):continue
        folder=path.parent.name
        if folder[:2] not in PREFIX:raise CatalogError(f"Missing stable ID namespace for {folder}")
        normalized=normalize_category(source,folder)
        qs=parse_category(path,normalized)
        hunts.extend(qs);output[path]=render_category(normalized,qs)
        if cql_blocks(source)!=cql_blocks(output[path]):
            raise CatalogError(f"{path}: a CQL code block was modified")
    if not hunts:raise CatalogError("No query documents found")
    ids=[q.query_id for q in hunts]
    if len(ids)!=len(set(ids)):raise CatalogError("Duplicate stable ID across categories")
    output[root/"QUERY-CATALOG.md"]=render_catalog(hunts)
    output[root/"MITRE-TECHNIQUE-INDEX.md"]=render_techniques(hunts)
    output[root/"TELEMETRY-INDEX.md"]=render_telemetry(hunts)
    output[root/"docs/QUERY-DUPLICATES.md"]=render_duplicates(hunts)
    home=root/"README.md";output[home]=render_root(home.read_text(encoding="utf-8"),hunts)
    errors=local_link_errors(root,output)
    if errors:raise CatalogError("\n".join(errors[:20]))
    return output


def main()->int:
    ap=argparse.ArgumentParser(description=__doc__)
    mode=ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write",action="store_true")
    mode.add_argument("--check",action="store_true")
    ap.add_argument("--root",type=Path,default=ROOT)
    args=ap.parse_args()
    root=args.root.resolve()
    try:
        output=build(root)
    except (CatalogError,UnicodeDecodeError) as exc:
        print(f"Catalog QA error: {exc}",file=sys.stderr);return 2
    stale=[p for p,t in output.items() if not p.exists() or p.read_text(encoding="utf-8")!=t]
    if args.write:
        for p in stale:
            p.parent.mkdir(parents=True,exist_ok=True)
            p.write_text(output[p],encoding="utf-8",newline="\n")
        print(f"CQL catalog synchronized: {len(stale)} Markdown files; "
              f"{len(output)} tracked documents.")
        return 0
    if stale:
        print("Generated Markdown needs regeneration. Run python3 scripts/catalog.py --write",file=sys.stderr)
        for p in stale: print(" - "+str(p.relative_to(root)),file=sys.stderr)
        return 1
    print(f"CQL catalog QA passed: {len(output)} synchronized documents")
    return 0


if __name__=="__main__":
    raise SystemExit(main())
