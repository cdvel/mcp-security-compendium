# MCP CVE tracker

62 advisories and 6 malicious packages that touch MCP, newest first, stored as [OSV](https://ossf.github.io/osv-schema/) records in `data/cves/`. Which advisories are in scope is in [CONTRIBUTING.md](CONTRIBUTING.md#cve-tracker); excluded ones are in `data/cve-exclusions.json`. Back to the [compendium](README.md).

## Advisories

| ID | Aliases | Package | Component | Severity | Published | Summary |
|---|---|---|---|---|---|---|
| [GHSA-84m7-p3x7-pcfv](https://osv.dev/vulnerability/GHSA-84m7-p3x7-pcfv) | CVE-2026-59951 | mcp | Servers | moderate | 2026-10-15 | Streamable HTTP transport accumulated sessions without limit, exhausting resources. |
| [GHSA-w794-rj3p-xv45](https://osv.dev/vulnerability/GHSA-w794-rj3p-xv45) | CVE-2026-105697 | langflow, langflow-base, lfx | Clients and hosts | critical | 2026-10-07 | Arbitrary command in an MCP stdio server configuration led to code execution. |
| [GHSA-6qxp-vccf-f47h](https://osv.dev/vulnerability/GHSA-6qxp-vccf-f47h) | CVE-2026-104850 | @modelcontextprotocol/client, @modelcontextprotocol/sdk | Clients and hosts | high | 2026-10-06 | OAuth client could send credentials to an authorization server chosen by the MCP server. |
| [GHSA-qg2g-g9w3-m5h8](https://osv.dev/vulnerability/GHSA-qg2g-g9w3-m5h8) | CVE-2026-58197 | github.com/stacklok/toolhive | Clients and hosts | high | 2026-09-18 | Containerized MCP servers could reach host services through host.docker.internal. |
| [GHSA-33f5-2c5q-wgwj](https://osv.dev/vulnerability/GHSA-33f5-2c5q-wgwj) | CVE-2026-63127 | rmcp | Clients and hosts | high | 2026-09-16 | OAuth client did not validate the resource field in protected resource metadata. |
| [GHSA-xm98-3vcf-fph7](https://osv.dev/vulnerability/GHSA-xm98-3vcf-fph7) | CVE-2026-53710 | mcp-contextforge-gateway | Servers | critical | 2026-08-24 | Sandbox bypass in the bundled python_sandbox_server sample; the gateway itself was not affected. |
| [GHSA-w4q6-qw23-4rg7](https://osv.dev/vulnerability/GHSA-w4q6-qw23-4rg7) | CVE-2026-47427 | github.com/github/github-mcp-server | Servers | high | 2026-07-28 | Nil pointer dereference in the completion handler caused denial of service. |
| [GHSA-7488-6r32-c95q](https://osv.dev/vulnerability/GHSA-7488-6r32-c95q) | CVE-2026-59822 | litellm | Gateways and proxies | high | 2026-07-22 | MCP authentication bypass through an OAuth2 passthrough fallback. |
| [GHSA-jpw9-pfvf-9f58](https://osv.dev/vulnerability/GHSA-jpw9-pfvf-9f58) | CVE-2026-52869 | mcp | Servers | high | 2026-07-16 | HTTP transports served session requests without checking the authenticated principal. |
| [GHSA-hvrp-rf83-w775](https://osv.dev/vulnerability/GHSA-hvrp-rf83-w775) | CVE-2026-52870 | mcp | Servers | high | 2026-07-16 | Experimental task handlers let any client access and cancel other clients' tasks. |
| [GHSA-wmg3-h8mf-wgvr](https://osv.dev/vulnerability/GHSA-wmg3-h8mf-wgvr) | CVE-2026-61459 | mcp-server-kubernetes | Servers | critical | 2026-07-10 | Argument injection could expose Kubernetes cluster credentials. |
| [GHSA-pjp5-fpmr-3349](https://osv.dev/vulnerability/GHSA-pjp5-fpmr-3349) | CVE-2026-48529 | github.com/github/github-mcp-server | Servers | moderate | 2026-06-25 | Shared lockdown-mode state in the HTTP server mixed up GraphQL clients across users. |
| [GHSA-r2xf-7jw5-pjg6](https://osv.dev/vulnerability/GHSA-r2xf-7jw5-pjg6) | CVE-2026-55887 | github.com/docker/mcp-gateway | Gateways and proxies | high | 2026-06-18 | Argument injection through YAML in OCI image labels. |
| [GHSA-8q5r-mmjf-575q](https://osv.dev/vulnerability/GHSA-8q5r-mmjf-575q) | CVE-2026-47751 | anthropics/claude-code-action | Clients and hosts | moderate | 2026-06-10 | MCP server configuration in a pull request could run code and exfiltrate secrets. |
| [GHSA-g53w-w6mj-hrpp](https://osv.dev/vulnerability/GHSA-g53w-w6mj-hrpp) |  | github.com/Kuadrant/mcp-gateway | Gateways and proxies | critical | 2026-05-19 | Hardcoded shared header value let callers bypass JWT session checks and redirect upstream traffic. |
| [GHSA-4gph-2hhr-5mwg](https://osv.dev/vulnerability/GHSA-4gph-2hhr-5mwg) |  | github.com/envoyproxy/ai-gateway | Gateways and proxies | moderate | 2026-05-19 | Case-insensitive JSON-RPC parsing let altered MCP messages bypass security controls in layered setups. |
| [GHSA-2v5f-5r6w-p67r](https://osv.dev/vulnerability/GHSA-2v5f-5r6w-p67r) | CVE-2026-45781 | github.com/modelcontextprotocol/registry | Registries and supply chain | low | 2026-05-19 | OCI validator skipped the package ownership check when the upstream registry rate-limited. |
| [GHSA-r48c-v28r-pf6v](https://osv.dev/vulnerability/GHSA-r48c-v28r-pf6v) | CVE-2026-44430 | github.com/modelcontextprotocol/registry | Registries and supply chain | moderate | 2026-05-08 | Unauthenticated SSRF: namespace verification reached private IPv6 ranges past the allowlist. |
| [GHSA-rqv2-m695-f8j4](https://osv.dev/vulnerability/GHSA-rqv2-m695-f8j4) | CVE-2026-44429 | github.com/modelcontextprotocol/registry | Registries and supply chain | moderate | 2026-05-08 | Stored XSS in the catalogue UI through a publisher-set websiteUrl. |
| [GHSA-95c3-6vvw-4mrq](https://osv.dev/vulnerability/GHSA-95c3-6vvw-4mrq) | CVE-2026-44428 | github.com/modelcontextprotocol/registry | Registries and supply chain | low | 2026-05-08 | GitHub OIDC tokens could be replayed across registry deployments (shared audience). |
| [GHSA-v8vw-gw5j-w7m6](https://osv.dev/vulnerability/GHSA-v8vw-gw5j-w7m6) | CVE-2026-44427 | github.com/modelcontextprotocol/registry | Registries and supply chain | moderate | 2026-05-08 | Open redirect via protocol-relative paths. |
| [GHSA-89vp-x53w-74fx](https://osv.dev/vulnerability/GHSA-89vp-x53w-74fx) | CVE-2026-42559 | rmcp | Servers | high | 2026-05-06 | DNS rebinding in the Streamable HTTP server transport. |
| [GHSA-v4p8-mg3p-g94g](https://osv.dev/vulnerability/GHSA-v4p8-mg3p-g94g) | CVE-2026-42271 | litellm | Gateways and proxies | high | 2026-04-25 | Authenticated users could run commands through MCP stdio test endpoints. |
| [GHSA-xrxf-jgv3-qmrm](https://osv.dev/vulnerability/GHSA-xrxf-jgv3-qmrm) | CVE-2025-61260 | @openai/codex | Clients and hosts | critical | 2026-04-14 | MCP configuration files in a repository could run code. |
| [GHSA-8jxr-pr72-r468](https://osv.dev/vulnerability/GHSA-8jxr-pr72-r468) | CVE-2026-35568 | io.modelcontextprotocol.sdk:mcp-core | Servers | high | 2026-04-07 | DNS rebinding in the Java SDK. |
| [GHSA-xw59-hvm2-8pj6](https://osv.dev/vulnerability/GHSA-xw59-hvm2-8pj6) | CVE-2026-34742 | github.com/modelcontextprotocol/go-sdk | Servers | high | 2026-04-01 | DNS rebinding protection was off by default for localhost servers. |
| [GHSA-vv7q-7jx5-f767](https://osv.dev/vulnerability/GHSA-vv7q-7jx5-f767) | CVE-2026-32871 | fastmcp | Servers | critical | 2026-03-31 | SSRF and path traversal in the OpenAPI provider. |
| [GHSA-rww4-4w9c-7733](https://osv.dev/vulnerability/GHSA-rww4-4w9c-7733) | CVE-2026-27124 | fastmcp | Servers | high | 2026-03-31 | OAuth proxy callback skipped consent checks, enabling confused deputy attacks. |
| [GHSA-hv2w-8mjj-jw22](https://osv.dev/vulnerability/GHSA-hv2w-8mjj-jw22) | CVE-2026-34237 | io.modelcontextprotocol.sdk:mcp-core | Servers | moderate | 2026-03-30 | Hardcoded wildcard CORS (Access-Control-Allow-Origin: *). |
| [GHSA-89xv-2j6f-qhc8](https://osv.dev/vulnerability/GHSA-89xv-2j6f-qhc8) | CVE-2026-33252 | github.com/modelcontextprotocol/go-sdk | Servers | high | 2026-03-19 | HTTP servers without authorization allowed cross-site tool execution. |
| [GHSA-q382-vc8q-7jhj](https://osv.dev/vulnerability/GHSA-q382-vc8q-7jhj) |  | github.com/modelcontextprotocol/go-sdk | Servers | high | 2026-03-19 | JSON parser treated keys with a trailing null character as the same key. |
| [GHSA-5h2m-4q8j-pqpj](https://osv.dev/vulnerability/GHSA-5h2m-4q8j-pqpj) | CVE-2025-69196 | fastmcp | Servers | high | 2026-03-16 | OAuth proxy accepted tokens issued for one MCP server at another. |
| [GHSA-hhfx-wfvq-7g9c](https://osv.dev/vulnerability/GHSA-hhfx-wfvq-7g9c) | CVE-2026-26118 | @azure/mcp, Azure.Mcp, msmcp-azure | Servers | high | 2026-03-10 | Server-side request forgery let an authorized attacker elevate privileges. |
| [GHSA-v2x6-wwfw-r2rq](https://osv.dev/vulnerability/GHSA-v2x6-wwfw-r2rq) | CVE-2026-29791 | github.com/agentgateway/agentgateway | Gateways and proxies | moderate | 2026-03-05 | Missing parameter sanitization when converting MCP calls to OpenAPI requests. |
| [GHSA-wvj2-96wp-fq3f](https://osv.dev/vulnerability/GHSA-wvj2-96wp-fq3f) | CVE-2026-27896 | github.com/modelcontextprotocol/go-sdk | Servers | high | 2026-02-26 | Case-insensitive JSON key matching let altered protocol messages through. |
| [GHSA-vjqx-cfc4-9h6v](https://osv.dev/vulnerability/GHSA-vjqx-cfc4-9h6v) | CVE-2026-27735 | mcp-server-git | Servers | moderate | 2026-02-26 | Path traversal in git_add staged files outside the repository. |
| [GHSA-345p-7cg4-v4c7](https://osv.dev/vulnerability/GHSA-345p-7cg4-v4c7) | CVE-2026-25536 | @modelcontextprotocol/sdk | Servers | high | 2026-02-04 | Reusing one server or transport instance across clients leaked data between them. |
| [GHSA-232v-j27c-5pp6](https://osv.dev/vulnerability/GHSA-232v-j27c-5pp6) | CVE-2026-23744 | @mcpjam/inspector | Clients and hosts | critical | 2026-01-16 | Unauthenticated HTTP endpoint lets a crafted request install an MCP server, leading to code execution. |
| [GHSA-6fg3-hvw7-2fwq](https://osv.dev/vulnerability/GHSA-6fg3-hvw7-2fwq) | CVE-2025-9611 | @playwright/mcp | Servers | high | 2026-01-07 | DNS rebinding gave web pages access to all server tools. |
| [GHSA-8r9q-7v3j-jr4g](https://osv.dev/vulnerability/GHSA-8r9q-7v3j-jr4g) | CVE-2026-0621 | @modelcontextprotocol/sdk | Servers | high | 2026-01-05 | Regular expression denial of service (ReDoS). |
| [GHSA-j22h-9j4x-23w5](https://osv.dev/vulnerability/GHSA-j22h-9j4x-23w5) | CVE-2025-68145 | mcp-server-git | Servers | moderate | 2025-12-17 | Missing path validation with the --repository flag. |
| [GHSA-9xwc-hfwc-8w59](https://osv.dev/vulnerability/GHSA-9xwc-hfwc-8w59) | CVE-2025-68144 | mcp-server-git | Servers | moderate | 2025-12-17 | Argument injection in git_diff and git_checkout could overwrite local files. |
| [GHSA-5cgr-j3jf-jw3v](https://osv.dev/vulnerability/GHSA-5cgr-j3jf-jw3v) | CVE-2025-68143 | mcp-server-git | Servers | moderate | 2025-12-17 | git_init tool could create repositories anywhere on the filesystem. |
| [GHSA-46gc-mwh4-cc5r](https://osv.dev/vulnerability/GHSA-46gc-mwh4-cc5r) | CVE-2025-64443 | github.com/docker/mcp-gateway | Gateways and proxies | high | 2025-12-03 | DNS rebinding in SSE and streaming modes. |
| [GHSA-9h52-p55h-vw2f](https://osv.dev/vulnerability/GHSA-9h52-p55h-vw2f) | CVE-2025-66416 | mcp | Servers | high | 2025-12-02 | DNS rebinding protection was off by default. |
| [GHSA-w48q-cv73-mx4w](https://osv.dev/vulnerability/GHSA-w48q-cv73-mx4w) | CVE-2025-66414 | @modelcontextprotocol/sdk | Servers | high | 2025-12-02 | DNS rebinding protection was off by default. |
| [GHSA-c2jp-c369-7pvx](https://osv.dev/vulnerability/GHSA-c2jp-c369-7pvx) |  | fastmcp | Servers | high | 2025-10-29 | Auth integration allowed confused deputy account takeover. |
| [GHSA-xcwh-rrwj-gxc7](https://github.com/cursor/cursor/security/advisories/GHSA-xcwh-rrwj-gxc7) | CVE-2025-59944 | Cursor | Clients and hosts | high | 2025-10-02 | Case-sensitive checks let prompt injection overwrite .cursor/mcp.json on case-insensitive filesystems. |
| [GHSA-gxw4-4fc5-9gr5](https://osv.dev/vulnerability/GHSA-gxw4-4fc5-9gr5) | CVE-2025-15061, CVE-2025-53967 | figma-developer-mcp | Servers | high | 2025-09-30 | Command injection in the get_figma_data tool. |
| [GHSA-g9hg-qhmf-q45m](https://osv.dev/vulnerability/GHSA-g9hg-qhmf-q45m) | CVE-2025-58444 | @modelcontextprotocol/inspector | Clients and hosts | high | 2025-09-08 | XSS from an untrusted server's OAuth redirect URL could lead to command execution. |
| [GHSA-4cxx-hrm3-49rm](https://github.com/cursor/cursor/security/advisories/GHSA-4cxx-hrm3-49rm) | CVE-2025-54135 | Cursor | Clients and hosts | high | 2025-08-02 | Prompt injection could create .cursor/mcp.json without approval and run an attacker MCP server (CurXecute). |
| [GHSA-24mc-g4xr-4395](https://github.com/cursor/cursor/security/advisories/GHSA-24mc-g4xr-4395) | CVE-2025-54136 | Cursor | Clients and hosts | high | 2025-08-01 | Changing an approved MCP server definition did not trigger re-approval (MCPoison). |
| [GHSA-6xpm-ggf7-wc3p](https://osv.dev/vulnerability/GHSA-6xpm-ggf7-wc3p) | CVE-2025-6514 | mcp-remote | Gateways and proxies | critical | 2025-07-09 | Untrusted server's authorization endpoint URL led to OS command injection. |
| [GHSA-gjv4-ghm7-q58q](https://osv.dev/vulnerability/GHSA-gjv4-ghm7-q58q) | CVE-2025-53355 | mcp-server-kubernetes | Servers | high | 2025-07-08 | Command injection in several tools. |
| [GHSA-3qhf-m339-9g5v](https://osv.dev/vulnerability/GHSA-3qhf-m339-9g5v) | CVE-2025-53366 | mcp | Servers | high | 2025-07-04 | Malformed input to a FastMCP server raised an unhandled validation error, causing denial of service. |
| [GHSA-j975-95f5-7wqh](https://osv.dev/vulnerability/GHSA-j975-95f5-7wqh) | CVE-2025-53365 | mcp | Servers | high | 2025-07-04 | Unhandled exception in the Streamable HTTP transport caused denial of service. |
| [GHSA-hc55-p739-j48w](https://osv.dev/vulnerability/GHSA-hc55-p739-j48w) | CVE-2025-53110 | @modelcontextprotocol/server-filesystem | Servers | high | 2025-07-01 | Path validation bypass via colliding path prefixes. |
| [GHSA-q66q-fx2p-7w4m](https://osv.dev/vulnerability/GHSA-q66q-fx2p-7w4m) | CVE-2025-53109 | @modelcontextprotocol/server-filesystem | Servers | high | 2025-07-01 | Path validation bypass via prefix matching and symlinks. |
| [GHSA-9f65-56v6-gxw7](https://osv.dev/vulnerability/GHSA-9f65-56v6-gxw7) | CVE-2025-52882 | @anthropic-ai/claude-code | Clients and hosts | high | 2025-06-23 | IDE extensions' local MCP WebSocket server accepted connections from any website. |
| [GHSA-7f8r-222p-6f5g](https://osv.dev/vulnerability/GHSA-7f8r-222p-6f5g) | CVE-2025-49596 | @modelcontextprotocol/inspector | Clients and hosts | critical | 2025-06-13 | Inspector proxy had no authentication, so requests (including from browsers) could launch stdio commands. |
| [GHSA-qgp8-v765-qxx9](https://osv.dev/vulnerability/GHSA-qgp8-v765-qxx9) | CVE-2025-4144 | @cloudflare/workers-oauth-provider | Servers | moderate | 2025-05-01 | PKCE bypass via downgrade. |
| [GHSA-4pc9-x2fx-p7vj](https://osv.dev/vulnerability/GHSA-4pc9-x2fx-p7vj) | CVE-2025-4143 | @cloudflare/workers-oauth-provider | Servers | moderate | 2025-05-01 | Authorize endpoint did not validate redirect_uri. |

## Malicious packages

Packages with MCP in the name or description that OSV reports as malicious.

| ID | Package | Published |
|---|---|---|
| [MAL-2026-5478](https://osv.dev/vulnerability/MAL-2026-5478) | mcp-server-git | 2026-06-09 |
| [MAL-2026-5479](https://osv.dev/vulnerability/MAL-2026-5479) | mcp-server-github | 2026-06-09 |
| [MAL-2025-191788](https://osv.dev/vulnerability/MAL-2025-191788) | mcp-runcmd-server | 2025-10-13 |
| [MAL-2025-191647](https://osv.dev/vulnerability/MAL-2025-191647) | mcp-runcommand-server | 2025-10-10 |
| [MAL-2025-47838](https://osv.dev/vulnerability/MAL-2025-47838) | @lanyer640/mcp-runcommand-server | 2025-09-29 |
| [MAL-2025-47604](https://osv.dev/vulnerability/MAL-2025-47604) | postmark-mcp | 2025-09-26 |
