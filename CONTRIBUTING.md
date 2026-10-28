# Contributing

## Scope

Security of the Model Context Protocol: specification and authorization, threats and research, defensive tools, vulnerabilities in MCP SDKs, servers, clients and gateways, and incidents.

Out of scope: general prompt injection or LLM security not tied to MCP, directories of MCP servers, other agent protocols unless the entry also covers MCP, vendor product pages, webinars and gated reports.

## Classification

Sections are by component: Specification and authorization; Clients and hosts; Servers; Gateways and proxies; Registries and supply chain; Threat models and research; Incidents. An entry goes in the section of the component it mainly acts on; runtime monitoring and audit tools go in *Gateways and proxies*. Material that spans components goes in *Threat models and research*.

Entries are also tagged with [CoSAI MCP threat categories](https://www.coalitionforsecureai.org/wp-content/uploads/2026/03/model-context-protocol-security-1.pdf) `T1`–`T12` where they apply.

Chosen 2026-10-17 because sections map to who acts on an entry. Changes to sections need maintainer approval and a `CHANGELOG.md` note.

## Inclusion criteria

An entry needs **one strong signal or two supporting signals**, plus at least one primary source.

| Strong | Supporting |
|---|---|
| Published by a research team, security lab or academic group | 100+ stars |
| Published by a standards body or the MCP spec maintainers | 3+ contributors |
| Backed by a CVE or GHSA | First release 90+ days ago and commits in the last 6 months |
| Peer-reviewed paper, or preprint with released code | Cited by an entry with a strong signal |
| 300+ stars or 10+ contributors | Clear docs, a license and a security policy |

The star threshold is lower than the 500 used for older topics because MCP tooling dates from late 2024.

If the primary source cannot be reached (dead link, redirect, 403), the entry stays only when the issuer has very high reputation, such as a government agency or standards body, with an archived copy linked where one exists. Otherwise it is dropped unless an archived copy or another primary source replaces it.

Not accepted: vendor marketing, gated content, AI-generated listicles, unverified claims, duplicates, and projects archived or without commits for 12 months (unless listed in `data/exemptions.yml`).

## CVE tracker

Advisories in MCP SDKs, servers, clients and gateways are included. Advisories in general agent tools are included only when the root cause is in MCP handling: configuration, transport, authorization or tool output.

## Attribution

Every entry records author, organization, kind of author, publication date, date added, date last verified, and whether its source is primary or secondary. A secondary write-up can be listed next to a primary source, never alone.

## Style

One objective sentence ending in a period. No emoji, no sales language.

## Review

Every new entry gets an adversarial review before approval: signal manipulation, impersonation, whether the source supports the claim, disputed or withdrawn advisories, and what the install step runs. A human approves every entry.

## Submissions

Submissions must come from a human. Agent-generated submissions are closed.
