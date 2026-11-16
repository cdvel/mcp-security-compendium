#!/usr/bin/env python3
"""Refresh repository facts for entries whose URL is a GitHub repository.

Usage: refresh.py [--dry-run] [--report FILE]

For each repo entry: reads the GitHub API (GITHUB_TOKEN if set), records stars, contributors, pushed_at,
archived and license, follows renames, drops the stars / contributors / active signals that no longer meet
the thresholds in CONTRIBUTING.md, and sets last_verified to today. Archived projects stay listed and the
README marks them archived. Entries that are stale or below the inclusion bar are listed in the report for a
maintainer; nothing is deleted.
"""
import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ENTRIES = ROOT / "data" / "entries"
API = "https://api.github.com"
REPO_URL = re.compile(r"^https://github\.com/([^/\s]+)/([^/\s#?]+?)/?$")

# Thresholds from CONTRIBUTING.md.
STARS_STRONG, STARS_SUPPORTING = 300, 100
CONTRIB_STRONG, CONTRIB_SUPPORTING = 10, 3
ACTIVE_DAYS, MIN_AGE_DAYS, STALE_DAYS = 183, 90, 365
STRONG = {"research_lab", "standards_body", "spec_maintainers", "cve", "paper", "paper_with_code"}


def api(path, token):
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "mcp-security-compendium"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(f"{API}{path}", headers=headers)
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.load(resp), resp.headers


def repo_facts(owner, name, token):
    repo, _ = api(f"/repos/{owner}/{name}", token)
    try:
        people, headers = api(f"/repos/{owner}/{name}/contributors?per_page=1&anon=true", token)
        last = re.search(r'[?&]page=(\d+)>; rel="last"', headers.get("Link") or "")
        contributors = int(last.group(1)) if last else len(people)
    except urllib.error.HTTPError as err:
        if err.code != 403:  # GitHub refuses to list contributors for very large repos
            raise
        contributors = 500
    return {
        "full_name": repo["full_name"],
        "stars": repo["stargazers_count"],
        "contributors": contributors,
        "pushed_at": repo["pushed_at"],
        "created_at": repo["created_at"],
        "archived": repo["archived"],
        "license": (repo.get("license") or {}).get("spdx_id") or "NOASSERTION",
    }


def judge(signals, facts, today):
    """Return (signals that still hold, notes for the maintainer)."""
    pushed = datetime.fromisoformat(facts["pushed_at"].replace("Z", "+00:00"))
    created = datetime.fromisoformat(facts["created_at"].replace("Z", "+00:00"))
    active = today - pushed <= timedelta(days=ACTIVE_DAYS) and today - created >= timedelta(days=MIN_AGE_DAYS)
    keep, notes = [], []
    for s in signals:
        if s == "stars" and facts["stars"] < STARS_SUPPORTING:
            notes.append(f"dropped `stars` ({facts['stars']} stars)")
        elif s == "contributors" and facts["contributors"] < CONTRIB_SUPPORTING:
            notes.append(f"dropped `contributors` ({facts['contributors']} contributors)")
        elif s == "active" and not active:
            notes.append(f"dropped `active` (last push {facts['pushed_at'][:10]})")
        else:
            keep.append(s)
    strong = len(STRONG & set(keep))
    strong += "stars" in keep and facts["stars"] >= STARS_STRONG
    strong += "contributors" in keep and facts["contributors"] >= CONTRIB_STRONG
    supporting = ("stars" in keep and facts["stars"] < STARS_STRONG) + \
        ("contributors" in keep and facts["contributors"] < CONTRIB_STRONG) + \
        ("active" in keep) + ("cited_by_strong" in keep) + bool({"docs", "security_policy"} & set(keep))
    if facts["archived"]:  # marked in the README, not a question for the maintainer
        notes.append("archived")
    elif today - pushed > timedelta(days=STALE_DAYS):
        notes.append(f"**no push for 12 months** (last {facts['pushed_at'][:10]})")
    if not strong and supporting < 2:
        notes.append("**below the inclusion bar**")
    return keep, notes


def set_field(text, key, value):
    """Replace a top-level `key:` line, or add it before `description:`."""
    line = f"{key}: {value}"
    pattern = re.compile(rf"^{re.escape(key)}:.*$", re.M)
    if pattern.search(text):
        return pattern.sub(lambda _: line, text, count=1)
    return re.sub(r"^description:", lambda m: f"{line}\n{m.group(0)}", text, count=1, flags=re.M)


def refresh_entry(path, token, today):
    text = path.read_text()
    url = re.search(r"^url: (\S+)", text, re.M).group(1)
    m = REPO_URL.match(url)
    if not m:
        return None
    facts = repo_facts(m.group(1), m.group(2), token)
    signals = re.search(r"^signals: \[(.*)\]$", text, re.M).group(1)
    keep, notes = judge([s.strip() for s in signals.split(",") if s.strip()], facts, today)
    new = text
    if facts["full_name"].lower() != f"{m.group(1)}/{m.group(2)}".lower():
        notes.append(f"renamed to {facts['full_name']}")
        new = set_field(new, "url", f"https://github.com/{facts['full_name']}")
    new = set_field(new, "signals", f"[{', '.join(keep)}]")
    new = set_field(new, "last_verified", f"'{today.date().isoformat()}'")
    for key in ("stars", "contributors"):
        new = set_field(new, key, facts[key])
    new = set_field(new, "pushed_at", f"'{facts['pushed_at']}'")
    new = set_field(new, "archived", str(facts["archived"]).lower())
    new = set_field(new, "license", facts["license"])
    return {"slug": path.stem, "text": new, "changed": new != text, "facts": facts, "notes": notes}


def report(results, failed):
    out = ["## Repository facts", "",
           f"{len(results)} repository entries refreshed from the GitHub API; `last_verified` set to today.", "",
           "| Entry | Stars | Contributors | Last push | Notes |", "|---|---|---|---|---|"]
    for r in sorted(results, key=lambda r: r["slug"]):
        f = r["facts"]
        out.append(f"| {r['slug']} | {f['stars']} | {f['contributors']} | {f['pushed_at'][:10]} | "
                   f"{'; '.join(r['notes']) or ''} |")
    flagged = [r for r in results if any(n.startswith("**") for n in r["notes"])]
    out += ["", "## For the maintainer", ""]
    out += [f"- {r['slug']}: {'; '.join(n for n in r['notes'] if n.startswith('**'))}" for r in flagged] or ["Nothing flagged."]
    if failed:
        out += ["", "## Not refreshed", ""] + [f"- {slug}: {err}" for slug, err in failed]
    return "\n".join(out) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--dry-run", action="store_true", help="print the report; write nothing")
    parser.add_argument("--report", help="also write the report to this file")
    args = parser.parse_args()
    token = os.environ.get("GITHUB_TOKEN")
    today = datetime.now(timezone.utc)
    results, failed = [], []
    for path in sorted(ENTRIES.glob("*.yml")):
        try:
            r = refresh_entry(path, token, today)
        except Exception as err:  # one repo must not stop the run; its date stays unchanged
            failed.append((path.stem, err))
            continue
        if r:
            results.append(r)
    text = report(results, failed)
    if args.report:
        Path(args.report).write_text(text)
    if args.dry_run:
        print(text)
    else:
        for r in results:
            (ENTRIES / f"{r['slug']}.yml").write_text(r["text"])
    print(f"{len(results)} refreshed, {len(failed)} failed", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
