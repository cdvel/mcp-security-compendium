# Methodology

How entries in this compendium are found, checked and kept current. The inclusion rules themselves are in [CONTRIBUTING.md](CONTRIBUTING.md).

```mermaid
flowchart LR
    A[Gather candidates] --> B[Source map]
    B -->|human review| C[Seed entries]
    C --> D[Adversarial review]
    D -->|human approval| E[Publish]
    E --> F[Weekly link check]
    F -->|dead links| D
    E --> G[Nightly CVE watch]
    G -->|candidates| H[Human triage]
    H --> E
```

## Pipeline

1. **Gather.** Candidates come from the MCP specification and its maintainers, standards bodies (OWASP, CoSAI, IETF), government guidance (NSA), research labs, academic papers (arXiv, with peer-reviewed versions where they exist), and advisory databases (GitHub Security Advisories, OSV).
2. **Source map.** Every candidate is listed with its section, author, strongest signal and a proposed keep or drop. A maintainer decides each row before anything is written. Rows that depend on a check carry a condition, and the row is dropped if the check fails. `data/source-map.yml` lists the kept sources and the entry each became.
3. **Seed.** Each kept row becomes one entry file in `data/entries/`, checked against the schema in `schema/entry.schema.json`.
4. **Adversarial review.** A separate pass looks for reasons each entry should not be listed (see below). A maintainer approves every change.
5. **Publish.** `README.md` is generated from the data by `scripts/generate.py`. Nobody edits it by hand.

AI agents were used to gather candidates, draft entries and run the adversarial review. A maintainer made every keep, drop and wording decision.

## Verification

An entry is "verified" when its facts were read from the source itself, not from a summary of it:

- **Repositories:** the GitHub API for stars, contributors, creation and push dates, license, archived status and the current name (renamed repos link to their new path).
- **Pages and posts:** the page HTML for title, author and date.
- **Papers:** the arXiv record for authors and affiliations, and Crossref for the peer-reviewed version. A preprint counts as a strong signal only if it released its code.
- **Advisories:** the OSV record, or the GitHub repository advisory when OSV has none. Each record also carries a short summary written for this list.
- **Dead links:** an archived copy from the Wayback Machine, when the original page is gone or now redirects elsewhere.

Each entry records the date it was last verified. A monthly job (`scripts/refresh.py`) re-reads every repository entry from the GitHub API, and a monthly re-check repeats the page and paper checks; together they fix facts that changed and flag entries that no longer meet the bar for a maintainer to decide. The README shows the oldest verified date, so an entry that couldn't be checked keeps the badge honest.

## Adversarial review

Each entry is checked for:

- **Signal manipulation:** star spikes, sock-puppet or bot contributors, signals that don't meet the thresholds.
- **Impersonation:** forks, typosquats, lookalike domains, or a renamed repo whose old path now belongs to someone else.
- **Unsupported claims:** a description or date the source doesn't back up.
- **Status:** withdrawn advisories, vendor disputes, archived projects, or content made obsolete by the 2026-07-28 specification.
- **Install path:** what the documented install runs, and what the tool sends off the machine by default.
- **Marketing:** product pages presented as research.

## CVE tracker

A nightly job (`.github/workflows/cves.yml`) runs `scripts/cve_watch.py`, which reads OSV's lists of changed records for npm, PyPI, Go, crates.io, Maven, NuGet and GitHub Actions, plus repository advisories that never reach OSV. A record is a candidate when a package name contains `mcp` as a word, a package is already tracked, or its text mentions MCP (rules in `data/cve-watch.yml`). Records already tracked, excluded, known under another ID, withdrawn or marked as GitHub duplicates are skipped.

Candidates go to one open pull request. A maintainer decides each one under the CVE scope rule: in scope gets a section and a one-line summary, out of scope goes to `data/cve-exclusions.json` with a reason, so it is never proposed again. CI fails until every candidate is decided. Advisory text is stored as data; the job never runs it or sends it to a model.

## Topic rules

These differ from the defaults used across compendiums:

- **Star threshold:** 300 stars counts as a strong signal, not 500, because MCP tooling dates from late 2024.
- **CVE scope:** advisories in MCP SDKs, servers, clients and gateways are included. Advisories in general agent tools are included only when the root cause is in MCP handling (configuration, transport, authorization or tool output), not when MCP is only the payload.
- **Unreachable sources:** if a primary source can't be reached, the entry stays only when the issuer has very high reputation, such as a government agency or standards body. Other dead vendor posts are linked through an archived copy or replaced by the advisory; otherwise they are dropped.
- **Deprecated features:** research on features the 2026-07-28 specification deprecates (sampling, sessions, dynamic client registration) stays listed, and its description says so.
- **Threat tags:** entries carry [CoSAI](https://www.coalitionforsecureai.org/wp-content/uploads/2026/03/model-context-protocol-security-1.pdf) threat categories `T1`–`T12` as a shared vocabulary across sections.

## Numbers

| Stage | Result |
|---|---|
| Candidates gathered (2026-10-17) | 100 sources, 68 advisories |
| Source map review (2026-10-28) | 68 kept, 1 merged, 31 dropped |
| Seeding (2026-10-28) | 64 entries; 4 dropped on failed checks, 1 merged |
| CVE tracker (seeding) | 65 advisories; 3 excluded by the scope rule |
| Adversarial review (2026-10-28) | 54 findings: 2 entries dropped, 24 entries corrected, 1 exclusion reversed, 2 advisories added |
| Published set (2026-10-28) | 62 entries, 68 advisories; 2 excluded |
| CVE catch-up (2026-11-14) | 58 candidates since 2026-10-28: 29 advisories and 21 malicious packages added, 8 excluded |
| Current | 62 entries, 91 advisories, 27 malicious packages; 10 excluded (`data/cve-exclusions.json`) |

## Limits

- Star history could not be checked during seeding: GitHub's stargazer listing returned 404 for every repository on 2026-10-28. Where star history mattered, the stars signal was left out and the entry rests on its other signals.
- `published` for repositories is the creation date, since many projects have no dated release.
- The review relies on public sources. It can't detect undisclosed affiliations between authors and the projects they write about.
