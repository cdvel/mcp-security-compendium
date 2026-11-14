#!/usr/bin/env python3
"""Find new and changed MCP advisories in OSV and write them to data/cves/.

Usage: cve_watch.py [--since YYYY-MM-DD | --hours N] [--dry-run] [--report FILE]

New candidates are written with database_specific.triage = "pending"; scripts/generate.py --check
fails until a maintainer triages each one. Advisory text is stored as data and never executed.
"""
import argparse
import csv
import io
import json
import os
import re
import sys
import urllib.request
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
CVES = DATA / "cves"
OSV = "https://osv-vulnerabilities.storage.googleapis.com"
GITHUB_API = "https://api.github.com"
# Keys the compendium adds to database_specific; kept when an upstream record is refreshed.
OUR_KEYS = ("component", "summary_short", "source", "triage")


def http_json(url, headers=None):
    req = urllib.request.Request(url, headers={"User-Agent": "mcp-security-compendium", **(headers or {})})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.load(resp)


def packages(record):
    return {a["package"]["name"] for a in record.get("affected", []) if a.get("package", {}).get("name")}


def ids(record):
    return {record["id"], *record.get("aliases", [])}


class Matcher:
    def __init__(self, watch, tracked):
        self.scopes = tuple(watch.get("scopes", []))
        self.watched = set(watch.get("packages", [])).union(*(packages(r) for r in tracked.values()))
        self.text = [re.compile(p) for p in watch.get("text", [])]

    def match(self, record, use_watch=True):
        """Return the rule that matched, or None."""
        names = packages(record)
        if any(n.startswith(self.scopes) for n in names if self.scopes):
            return "scope"
        if any("mcp" in re.split(r"[^a-z0-9]+", n.lower()) for n in names):
            return "name"
        if use_watch and names & self.watched:
            return "watch"
        text = f"{record.get('summary') or ''} {record.get('details') or ''}"
        if any(p.search(text) for p in self.text):
            return "text"
        return None


def changed_ids(ecosystem, since):
    """IDs modified at or after `since` (ISO string), from OSV's newest-first modified_id.csv."""
    url = f"{OSV}/{urllib.request.quote(ecosystem)}/modified_id.csv"
    req = urllib.request.Request(url, headers={"User-Agent": "mcp-security-compendium"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        for row in csv.reader(io.TextIOWrapper(resp, encoding="utf-8")):
            if len(row) < 2:
                continue
            if row[0] < since:
                break
            yield row[1]


def repo_advisories(repo, package, since, token):
    """Published advisories of one repository, as OSV-shaped records."""
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    url = f"{GITHUB_API}/repos/{repo}/security-advisories?state=published&sort=updated&direction=desc&per_page=100"
    for a in http_json(url, headers):
        if (a.get("updated_at") or "") < since:
            break
        record = {
            "schema_version": "1.6.0",
            "id": a["ghsa_id"],
            "aliases": [a["cve_id"]] if a.get("cve_id") else [],
            "summary": a.get("summary") or "",
            "details": a.get("description") or "",
            "published": a.get("published_at"),
            "modified": a.get("updated_at"),
            "affected": [{"package": {"name": package}}],
            "severity": [{"type": "CVSS_V3", "score": a["cvss"]["vector_string"]}]
            if (a.get("cvss") or {}).get("vector_string") else [],
            "references": [{"type": "ADVISORY", "url": a["html_url"]}],
            "database_specific": {"severity": (a.get("severity") or "").upper(),
                                  "source": f"GitHub repository advisory ({repo}); not in OSV"},
        }
        if a.get("withdrawn_at"):
            record["withdrawn"] = a["withdrawn_at"]
        yield record


def guess_component(record, tracked):
    names = packages(record)
    seen = Counter(r["database_specific"].get("component") for r in tracked.values() if packages(r) & names)
    seen.pop(None, None)
    seen.pop("", None)
    return seen.most_common(1)[0][0] if seen else ""


def refresh(old, new):
    """The upstream record with the compendium's own keys carried over."""
    db = new.setdefault("database_specific", {})
    for key in OUR_KEYS:
        if key in old.get("database_specific", {}):
            db[key] = old["database_specific"][key]
    return new


def cell(text, limit=110):
    """Make untrusted advisory text safe for a Markdown table cell (no markup, links or mentions)."""
    text = " ".join(str(text or "").split())
    text = text[:limit] + ("…" if len(text) > limit else "")
    for a, b in (("&", "&amp;"), ("<", "&lt;"), (">", "&gt;"), ("|", "\\|"), ("`", "'"),
                 ("[", "&#91;"), ("]", "&#93;"), ("@", "@​"), ("#", "#​")):
        text = text.replace(a, b)
    return text


def is_malware(record):
    return record["id"].startswith("MAL-")


def scan(since, watch, tracked, excluded, token=None, log=sys.stderr):
    """Return (new, updated) records found since `since`."""
    matcher = Matcher(watch, tracked)
    known = {i: rid for rid, r in tracked.items() for i in ids(r)}
    seen, new, updated = set(), {}, {}

    def consider(record, ecosystem=None):
        rid = record["id"]
        if rid in seen:
            return
        seen.add(rid)
        if ids(record) & excluded:
            return
        match_id = next((known[i] for i in ids(record) if i in known), None)
        if match_id:
            old = tracked[match_id]
            if match_id == rid and (record.get("modified") or "") > (old.get("modified") or ""):
                updated[rid] = refresh(old, record)
            return
        if any(ids(record) & ids(r) for r in new.values()):
            return
        # GitHub re-files some advisories as "Duplicate Advisory" and withdraws them; neither is new.
        if record.get("withdrawn") or (record.get("summary") or "").startswith("Duplicate Advisory"):
            return
        rule = matcher.match(record)
        if rule:
            db = record.setdefault("database_specific", {})
            db["component"] = guess_component(record, tracked)
            db["triage"] = "pending"
            if is_malware(record):
                db.setdefault("severity", "MALICIOUS")
            record["_matched"] = rule
            new[rid] = record

    def fetch(item):
        ecosystem, vid = item
        try:
            return http_json(f"{OSV}/{urllib.request.quote(ecosystem)}/{vid}.json")
        except Exception as err:  # one bad record must not stop the run
            print(f"skip {ecosystem}/{vid}: {err}", file=log)
            return None

    for ecosystem in watch["ecosystems"]:
        todo = [(ecosystem, vid) for vid in dict.fromkeys(changed_ids(ecosystem, since))]
        with ThreadPoolExecutor(max_workers=16) as pool:
            for record in pool.map(fetch, todo):
                if record:
                    consider(record)
        print(f"{ecosystem}: {len(todo)} changed", file=log)
    for repo in watch.get("repos", []):
        for record in repo_advisories(repo["repo"], repo["package"], since, token):
            consider(record)
    return new, updated


def report(new, updated):
    vulns = sorted((r for r in new.values() if not is_malware(r)), key=lambda r: r.get("published", ""), reverse=True)
    malware = sorted((r for r in new.values() if is_malware(r)), key=lambda r: r.get("published", ""), reverse=True)
    out = ["## New advisories", ""]
    if vulns:
        out += ["| ID | Package | Severity | Published | Matched | Section guess | Upstream summary |",
                "|---|---|---|---|---|---|---|"]
        for r in vulns:
            out.append(f"| {r['id']} | {cell(', '.join(sorted(packages(r))), 50)} | "
                       f"{cell(r['database_specific'].get('severity', '')).lower()} | {r.get('published', '')[:10]} | "
                       f"{r['_matched']} | {r['database_specific']['component'] or '?'} | {cell(r.get('summary'))} |")
    else:
        out.append("None.")
    out += ["", "## New malicious packages", ""]
    if malware:
        out += ["| ID | Package | Published | Matched |", "|---|---|---|---|"]
        out += [f"| {r['id']} | {cell(', '.join(sorted(packages(r))), 60)} | {r.get('published', '')[:10]} | {r['_matched']} |"
                for r in malware]
    else:
        out.append("None.")
    out += ["", "## Updated records", ""]
    out += [f"- {r['id']}" + (" (withdrawn)" if r.get("withdrawn") else "") for r in updated.values()] or ["None."]
    out += ["", "To triage: for each new record, set `component` and write `summary_short` (not needed for malicious "
            "packages), then delete `triage`; or delete the file and add the ID with a reason to "
            "`data/cve-exclusions.json`. CI fails until every record is triaged.", ""]
    return "\n".join(out)


def write(new, updated):
    for r in list(new.values()) + list(updated.values()):
        r = {k: v for k, v in r.items() if not k.startswith("_")}
        (CVES / f"{r['id']}.json").write_text(json.dumps(r, indent=2, ensure_ascii=False) + "\n")


def load_state():
    watch = yaml.safe_load((DATA / "cve-watch.yml").read_text())
    tracked = {}
    for path in CVES.glob("*.json"):
        r = json.loads(path.read_text())
        tracked[r["id"]] = r
    excluded = set()
    for x in json.loads((DATA / "cve-exclusions.json").read_text()):
        excluded.add(x["id"])
        excluded.update(x.get("aliases", []))
    return watch, tracked, excluded


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--since", help="start date, YYYY-MM-DD (default: 72 hours ago)")
    parser.add_argument("--hours", type=int, default=72)
    parser.add_argument("--dry-run", action="store_true", help="print the report; write nothing")
    parser.add_argument("--report", help="also write the report to this file")
    args = parser.parse_args()
    start = (datetime.fromisoformat(args.since).replace(tzinfo=timezone.utc) if args.since
             else datetime.now(timezone.utc) - timedelta(hours=args.hours))
    since = start.strftime("%Y-%m-%dT%H:%M:%SZ")
    watch, tracked, excluded = load_state()
    new, updated = scan(since, watch, tracked, excluded, token=os.environ.get("GITHUB_TOKEN"))
    text = report(new, updated)
    if args.report:
        Path(args.report).write_text(text)
    if args.dry_run:
        print(text)
    else:
        write(new, updated)
    print(f"since {since}: {len(new)} new, {len(updated)} updated", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
