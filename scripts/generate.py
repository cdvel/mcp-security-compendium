#!/usr/bin/env python3
"""Validate data/ and generate README.md and CVES.md.

Usage: generate.py [--check]
  --check  exit 1 if either file is out of date instead of writing it
"""
import json
import sys
from collections import Counter
from pathlib import Path
from urllib.parse import urlparse

import jsonschema
import yaml

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
README = ROOT / "README.md"
CVES_MD = ROOT / "CVES.md"
README_CVES = 20


class Loader(yaml.SafeLoader):
    """SafeLoader that keeps dates as strings."""


Loader.yaml_implicit_resolvers = {
    k: [(tag, rx) for tag, rx in v if tag != "tag:yaml.org,2002:timestamp"]
    for k, v in yaml.SafeLoader.yaml_implicit_resolvers.items()
}

AUTHOR_KIND = {
    "research_lab": "research",
    "vendor_lab": "vendor",
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


def check_cves(cves, sections):
    """Every advisory must be triaged: a known section, a short summary (except malware), not excluded."""
    known = {s["id"] for s in sections}
    excluded = set()
    for x in json.loads((DATA / "cve-exclusions.json").read_text()):
        excluded |= {x["id"], *x.get("aliases", [])}
    errors = []
    for c in cves:
        db = c.get("database_specific", {})
        if db.get("triage"):
            errors.append(f"{c['id']}: not triaged yet (database_specific.triage is set)")
        if db.get("component") not in known:
            errors.append(f"{c['id']}: component {db.get('component')!r} is not a section id")
        if not is_malware(c) and not db.get("summary_short"):
            errors.append(f"{c['id']}: missing database_specific.summary_short")
        if {c["id"], *c.get("aliases", [])} & excluded:
            errors.append(f"{c['id']}: also listed in data/cve-exclusions.json")
    return errors


def is_malware(c):
    return c["id"].startswith("MAL-")


def who(e):
    names = e["author"].split("; ")
    name = f"{names[0]} et al." if len(names) > 3 else ", ".join(names)
    if e.get("org") and e["org"] not in e["author"]:
        name += f" ({e['org']})"
    return name


def by_line(e):
    tags = [AUTHOR_KIND[e["author_kind"]]] if e["author_kind"] != "independent" else []
    threats = sorted(e.get("threats", []), key=lambda t: int(t[1:]))
    tags += [e["kind"]] + threats + e.get("tags", [])
    tag_str = " ".join(f"`{t}`" for t in tags)
    also = ", ".join(f"[{site(u)}]({u})" for u in e.get("sources", []))
    also = f" Also: {also}." if also else ""
    return f"- [{e['title']}]({e['url']}) by {who(e)} · {e['published']} · {e['description']}{also} {tag_str}".rstrip()


def site(url):
    host = urlparse(url).netloc.removeprefix("www.")
    if host == "web.archive.org":
        return "archived copy"
    if host == "github.com" and "/advisories/" in url:
        return url.rstrip("/").rsplit("/", 1)[-1]
    return host


def advisory_url(c):
    """OSV page for every record; repository-only advisories (not in OSV) link to their own page."""
    if "not in OSV" in c.get("database_specific", {}).get("source", ""):
        return next((r["url"] for r in c.get("references", []) if r.get("type") == "ADVISORY"), "")
    return f"https://osv.dev/vulnerability/{c['id']}"


def cve_row(c, titles):
    db = c.get("database_specific", {})
    aliases = ", ".join(a for a in c.get("aliases", []) if a.startswith("CVE-"))
    pkgs = ", ".join(sorted({a["package"]["name"] for a in c.get("affected", []) if "package" in a}))
    sev = db.get("severity", "").lower()
    ref = advisory_url(c)
    component = titles.get(db.get("component", ""), "")
    ident = f"[{c['id']}]({ref})" if ref else c["id"]
    return f"| {ident} | {aliases} | {pkgs} | {component} | {sev} | {c.get('published', '')[:10]} | {db.get('summary_short') or c.get('summary', '')} |"


GLOSSARY = [
    "<details>",
    "<summary>Terms and threat tags</summary>",
    "",
    "- **CIMD:** OAuth Client ID Metadata Document, a URL that identifies an OAuth client; preferred for client registration in the 2026-07-28 spec.",
    "- **DCR:** OAuth Dynamic Client Registration (RFC 7591), deprecated in the 2026-07-28 spec.",
    "- **PRM:** OAuth Protected Resource Metadata (RFC 9728), how an MCP server names its authorization server.",
    "- **DNS rebinding:** a web page reaching a server on localhost by changing what its domain resolves to.",
    "- **Tool poisoning:** instructions hidden in tool descriptions or output that an agent follows.",
    "- **CoSAI threat tags:** "
    "`T1` authentication and identity, `T2` access control, `T3` input validation, "
    "`T4` instruction and data boundary (prompt injection), `T5` data protection, `T6` integrity and verification, "
    "`T7` session and transport, `T8` network binding and isolation, `T9` trust boundaries and privilege, "
    "`T10` resource limits, `T11` supply chain and lifecycle, `T12` logging and audit.",
    "",
    "</details>",
    "",
]


def cve_table(cves, titles):
    return [
        "| ID | Aliases | Package | Component | Severity | Published | Summary |",
        "|---|---|---|---|---|---|---|",
    ] + [cve_row(c, titles) for c in cves]


def malware_row(c):
    pkgs = ", ".join(sorted({a["package"]["name"] for a in c.get("affected", []) if "package" in a}))
    return f"| [{c['id']}]({advisory_url(c)}) | {pkgs} | {c.get('published', '')[:10]} |"


def render_cves(sections, cves):
    titles = {s["id"]: s["title"] for s in sections}
    vulns = [c for c in cves if not is_malware(c)]
    malware = [c for c in cves if is_malware(c)]
    return "\n".join([
        "# MCP CVE tracker",
        "",
        f"{len(vulns)} advisories and {len(malware)} malicious packages that touch MCP, newest first, stored as "
        "[OSV](https://ossf.github.io/osv-schema/) records in `data/cves/`. Which advisories are in scope is in "
        "[CONTRIBUTING.md](CONTRIBUTING.md#cve-tracker); excluded ones are in `data/cve-exclusions.json`. "
        "Back to the [compendium](README.md).",
        "",
        "## Advisories",
        "",
    ] + cve_table(vulns, titles) + [
        "",
        "## Malicious packages",
        "",
        "Packages with MCP in the name or description that OSV reports as malicious.",
        "",
        "| ID | Package | Published |",
        "|---|---|---|",
    ] + [malware_row(c) for c in malware] + [""])


def anchor(title):
    return title.lower().replace(" ", "-")


def render(sections, entries, cves):
    verified = max((e["last_verified"] for e in entries), default="never")
    vulns = [c for c in cves if not is_malware(c)]
    malware = [c for c in cves if is_malware(c)]
    out = [
        '<div align="center">',
        "",
        "# MCP security compendium",
        "",
        "**Sourced, attributed resources and a CVE tracker for Model Context Protocol security.**",
        "",
        f"![Last verified {verified}](https://img.shields.io/badge/last_verified-{verified.replace('-', '--')}-2ea44f)",
        "",
        f"{len(entries)} entries · {len(vulns)} advisories · {len(malware)} malicious packages · CC BY 4.0",
        "",
        "[Start here](#start-here) · [Contents](#contents) · [CVE tracker](#cve-tracker) · "
        "[Methodology](METHODOLOGY.md) · [Contributing](CONTRIBUTING.md)",
        "",
        "</div>",
        "",
        "MCP security material is spread across spec pages, lab write-ups, papers and advisory databases, "
        "and some of it predates the 2026-07-28 spec. This list keeps the entries with a credible author "
        "and a primary source, organized by the component each one acts on. Every entry names its author "
        "and date.",
        "",
    ] + GLOSSARY
    counts = Counter(e["section"] for e in entries)
    start = [e for e in entries if e.get("start_here")]
    toc = (["Start here"] if start else []) + [s["title"] for s in sections] + (["CVE tracker"] if cves else [])
    out += ["## Contents", ""]
    for t in toc:
        n = next((counts[s["id"]] for s in sections if s["title"] == t), None)
        if t == "CVE tracker":
            n = len(vulns)
        out.append(f"- [{t}](#{anchor(t)})" + (f" ({n})" if n else ""))
    out.append("")
    if start:
        out += ["## Start here", ""] + [f"- [{e['title']}]({e['url']}) by {who(e)}" for e in start] + [""]
    for s in sections:
        items = sorted((e for e in entries if e["section"] == s["id"]), key=lambda e: e["published"], reverse=True)
        out += [f"## {s['title']}", "", s["summary"], ""]
        out += [by_line(e) for e in items] or ["No entries yet."]
        out.append("")
    if cves:
        out += [
            "## CVE tracker",
            "",
            f"The {min(README_CVES, len(vulns))} newest of {len(vulns)} advisories. The full list, and "
            f"{len(malware)} malicious packages, are in [CVES.md](CVES.md).",
            "",
        ] + cve_table(vulns[:README_CVES], {s["id"]: s["title"] for s in sections}) + [""]
    out += [
        "---",
        "",
        "Content is licensed under [CC BY 4.0](LICENSE); scripts under [MIT](LICENSE-CODE).",
        "",
    ]
    return "\n".join(out)


def main():
    schema = json.loads((ROOT / "schema" / "entry.schema.json").read_text())
    sections = yaml.load((DATA / "sections.yml").read_text(), Loader)
    entries, errors = load_entries(schema)
    known = {s["id"] for s in sections}
    errors += [f"{e['slug']}: unknown section {e['section']}" for e in entries if e["section"] not in known]
    cves = load_cves()
    errors += check_cves(cves, sections)
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    outputs = {README: render(sections, entries, cves), CVES_MD: render_cves(sections, cves)}
    if "--check" in sys.argv:
        stale = [p.name for p, text in outputs.items() if not p.exists() or p.read_text() != text]
        if stale:
            print(f"{', '.join(stale)} out of date; run scripts/generate.py", file=sys.stderr)
            return 1
        return 0
    for path, text in outputs.items():
        path.write_text(text)
    print(f"README.md: {len(entries)} entries")
    return 0


if __name__ == "__main__":
    sys.exit(main())
