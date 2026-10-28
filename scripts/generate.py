#!/usr/bin/env python3
"""Validate data/ and generate README.md.

Usage: generate.py [--check]
  --check  exit 1 if README.md is out of date instead of writing it
"""
import json
import sys
from collections import Counter
from pathlib import Path

import jsonschema
import yaml

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
README = ROOT / "README.md"


class Loader(yaml.SafeLoader):
    """SafeLoader that keeps dates as strings."""


Loader.yaml_implicit_resolvers = {
    k: [(tag, rx) for tag, rx in v if tag != "tag:yaml.org,2002:timestamp"]
    for k, v in yaml.SafeLoader.yaml_implicit_resolvers.items()
}

AUTHOR_KIND = {
    "research_lab": "research",
    "vendor_lab": "vendor research",
    "academic": "academic",
    "standards_body": "standards body",
    "project_maintainers": "maintainers",
    "independent": "independent",
}


def load_entries(schema):
    entries, errors = [], []
    for path in sorted((DATA / "entries").glob("*.yml")):
        entry = yaml.load(path.read_text(), Loader)
        for err in jsonschema.Draft202012Validator(schema).iter_errors(entry):
            errors.append(f"{path.name}: {err.message}")
        entry["slug"] = path.stem
        entries.append(entry)
    urls = Counter(e["url"] for e in entries)
    errors += [f"duplicate url: {u}" for u, n in urls.items() if n > 1]
    return entries, errors


def load_cves():
    cves = []
    for path in sorted((DATA / "cves").glob("*.json")):
        cves.append(json.loads(path.read_text()))
    return sorted(cves, key=lambda c: c.get("published", ""), reverse=True)


def by_line(e):
    who = e["author"]
    if e.get("org") and e["org"] != e["author"]:
        who += f" ({e['org']})"
    tags = [AUTHOR_KIND[e["author_kind"]]] if e["author_kind"] != "independent" else []
    tags += [e["kind"]] + e.get("threats", []) + e.get("tags", [])
    tag_str = " ".join(f"`{t}`" for t in tags)
    return f"- [{e['title']}]({e['url']}) by {who} · {e['published']} · {e['description']} {tag_str}".rstrip()


def advisory_url(c):
    refs = [r["url"] for r in c.get("references", []) if r.get("type") == "ADVISORY"]
    ghsa = [u for u in refs if "github.com/" in u and "/advisories/" in u]
    if ghsa:
        return ghsa[0]
    if c["id"].startswith(("GHSA-", "MAL-", "GO-", "PYSEC-")):
        return f"https://osv.dev/vulnerability/{c['id']}"
    return refs[0] if refs else ""


def cve_row(c, titles):
    db = c.get("database_specific", {})
    aliases = ", ".join(a for a in c.get("aliases", []) if a != c["id"])
    pkgs = ", ".join(sorted({a["package"]["name"] for a in c.get("affected", []) if "package" in a}))
    sev = db.get("severity", "").lower()
    ref = advisory_url(c)
    component = titles.get(db.get("component", ""), "")
    ident = f"[{c['id']}]({ref})" if ref else c["id"]
    return f"| {ident} | {aliases} | {pkgs} | {component} | {sev} | {c.get('published', '')[:10]} | {c.get('summary', '')} |"


def anchor(title):
    return title.lower().replace(" ", "-")


def render(sections, entries, cves):
    out = [
        "# MCP security compendium",
        "",
        "Curated, sourced resources on Model Context Protocol security, organized by component. "
        "Every entry names its author and links a primary source; inclusion rules are in "
        "[CONTRIBUTING.md](CONTRIBUTING.md). Threat tags `T1`–`T12` refer to the "
        "[CoSAI MCP security taxonomy](https://www.coalitionforsecureai.org/wp-content/uploads/2026/03/model-context-protocol-security-1.pdf).",
        "",
    ]
    counts = Counter(e["section"] for e in entries)
    start = [e for e in entries if e.get("start_here")]
    toc = (["Start here"] if start else []) + [s["title"] for s in sections] + (["CVE tracker"] if cves else [])
    out += ["## Contents", ""]
    for t in toc:
        n = next((counts[s["id"]] for s in sections if s["title"] == t), None)
        out.append(f"- [{t}](#{anchor(t)})" + (f" ({n})" if n else ""))
    out.append("")
    if start:
        out += ["## Start here", ""] + [by_line(e) for e in start] + [""]
    for s in sections:
        items = sorted((e for e in entries if e["section"] == s["id"]), key=lambda e: e["published"], reverse=True)
        out += [f"## {s['title']}", "", s["summary"], ""]
        out += [by_line(e) for e in items] or ["No entries yet."]
        out.append("")
    if cves:
        out += [
            "## CVE tracker",
            "",
            f"{len(cves)} advisories, stored as [OSV](https://ossf.github.io/osv-schema/) records in `data/cves/`.",
            "",
            "| ID | Aliases | Package | Component | Severity | Published | Summary |",
            "|---|---|---|---|---|---|---|",
        ] + [cve_row(c, {s['id']: s['title'] for s in sections}) for c in cves] + [""]
    verified = max((e["last_verified"] for e in entries), default="never")
    out += ["---", "", f"Last verified {verified}. Generated from `data/` by `scripts/generate.py`; do not edit by hand.", ""]
    return "\n".join(out)


def main():
    schema = json.loads((ROOT / "schema" / "entry.schema.json").read_text())
    sections = yaml.load((DATA / "sections.yml").read_text(), Loader)
    entries, errors = load_entries(schema)
    known = {s["id"] for s in sections}
    errors += [f"{e['slug']}: unknown section {e['section']}" for e in entries if e["section"] not in known]
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    text = render(sections, entries, load_cves())
    if "--check" in sys.argv:
        if not README.exists() or README.read_text() != text:
            print("README.md is out of date; run scripts/generate.py", file=sys.stderr)
            return 1
        return 0
    README.write_text(text)
    print(f"README.md: {len(entries)} entries")
    return 0


if __name__ == "__main__":
    sys.exit(main())
