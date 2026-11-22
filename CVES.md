# MCP CVE tracker

112 advisories and 34 malicious packages that touch MCP, newest first, stored as [OSV](https://ossf.github.io/osv-schema/) records in `data/cves/`. Which advisories are in scope is in [CONTRIBUTING.md](CONTRIBUTING.md#cve-tracker); excluded ones are in `data/cve-exclusions.json`. Back to the [compendium](README.md).

## Advisories

| ID | Aliases | Package | Component | Severity | Published | Summary |
|---|---|---|---|---|---|---|
| [GHSA-9x8x-crjq-g64h](https://osv.dev/vulnerability/GHSA-9x8x-crjq-g64h) | CVE-2026-77359 | jupyter-mcp-server | Servers | critical | 2026-11-20 | Management routes lacked Host and Origin validation, so DNS rebinding let websites hijack the Jupyter backend. |
| [GHSA-24pw-rf5p-mgp7](https://osv.dev/vulnerability/GHSA-24pw-rf5p-mgp7) | CVE-2026-77318 | jupyter-mcp-server | Servers | high | 2026-11-20 | Management routes on the HTTP transport skipped token authentication, letting unauthenticated callers redirect the Jupyter backend. |
| [GHSA-m932-63jc-4jqq](https://osv.dev/vulnerability/GHSA-m932-63jc-4jqq) | CVE-2026-130007 | github.com/reza-gholizade/k8s-mcp-server | Servers | high | 2026-11-19 | The default SSE transport had no authentication, letting any client invoke Kubernetes tools. |
| [GHSA-qx49-fqc8-xw99](https://osv.dev/vulnerability/GHSA-qx49-fqc8-xw99) | CVE-2026-115563 | mcp | Clients and hosts | high | 2026-11-19 | The OAuth client let the MCP server choose where credentials were sent, leaking client secrets and authorization codes. |
| [GHSA-q433-mp6c-8v4f](https://osv.dev/vulnerability/GHSA-q433-mp6c-8v4f) | CVE-2026-130008 | github.com/StacklokLabs/sqlite-mcp | Servers | high | 2026-11-19 | Read-only mode checked only for a leading SELECT, so statement chaining and ATTACH allowed database writes. |
| [GHSA-4rj4-rcrq-gr92](https://osv.dev/vulnerability/GHSA-4rj4-rcrq-gr92) |  | safari-mcp | Servers | moderate | 2026-11-19 | Unescaped backslashes in tool arguments let attackers break out of JavaScript string literals and run code in the page. |
| [GHSA-mx6p-3fg7-v6pj](https://osv.dev/vulnerability/GHSA-mx6p-3fg7-v6pj) | CVE-2026-77283 | obsidian-sync-mcp | Servers | high | 2026-11-19 | Missing Host and Origin validation let a public website drive the user's vault through DNS rebinding. |
| [GHSA-833v-v58w-294h](https://osv.dev/vulnerability/GHSA-833v-v58w-294h) | CVE-2026-76807 | @doist/todoist-mcp | Servers | critical | 2026-11-19 | HTTP server accepted attacker-controlled Host and Origin headers, so DNS rebinding let websites invoke tools. |
| [GHSA-w42c-h7hr-f67p](https://osv.dev/vulnerability/GHSA-w42c-h7hr-f67p) | CVE-2026-62964 | github.com/zzet/gortex | Servers | high | 2026-11-19 | Write tools exempted absolute paths from repository confinement, allowing arbitrary file writes and code execution. |
| [GHSA-vg83-hcp4-5qcc](https://osv.dev/vulnerability/GHSA-vg83-hcp4-5qcc) | CVE-2026-75518 | @apireno/domshell | Servers | moderate | 2026-11-19 | A tool that evaluates JavaScript was classed read-only, so it ran without write permission and misled approval prompts. |
| [GHSA-2m9m-6cr5-9x25](https://osv.dev/vulnerability/GHSA-2m9m-6cr5-9x25) | CVE-2026-63129 | @connorbritain/mssql-mcp-core, @connorbritain/mssql-mcp-reader, @connorbritain/mssql-mcp-server, @connorbritain/mssql-mcp-writer | Servers | high | 2026-11-19 | Write tools interpolated table names and WHERE clauses into T-SQL, allowing SQL injection. |
| [GHSA-gj7r-p794-hhq5](https://osv.dev/vulnerability/GHSA-gj7r-p794-hhq5) | CVE-2026-129235 | github.com/kubeshark/kubeshark | Servers | moderate | 2026-11-16 | The download tool wrote fetched bytes to an unvalidated destination path, allowing arbitrary file writes. |
| [GHSA-8vf2-hxg5-crqh](https://osv.dev/vulnerability/GHSA-8vf2-hxg5-crqh) | CVE-2026-129236 | github.com/kubeshark/kubeshark | Servers | high | 2026-11-16 | The start tool passed an unvalidated pod_regex into a command line, allowing argument injection and cluster takeover. |
| [GHSA-jq3q-62jc-fqq9](https://osv.dev/vulnerability/GHSA-jq3q-62jc-fqq9) | CVE-2026-68934 | code-review-mcp-server | Servers | high | 2026-11-16 | Tool parameters were interpolated into shell commands, allowing arbitrary command execution on the host. |
| [GHSA-q6jf-24jf-m3cg](https://osv.dev/vulnerability/GHSA-q6jf-24jf-m3cg) | CVE-2026-120792 | @microsoft/aspire-cli, @microsoft/aspire-cli-linux-arm64, @microsoft/aspire-cli-linux-musl-x64, @microsoft/aspire-cli-linux-x64, @microsoft/aspire-cli-osx-arm64, @microsoft/aspire-cli-osx-x64, Aspire.Cli, Aspire.Cli.linux-arm64, Aspire.Cli.linux-musl-x64, Aspire.Cli.linux-x64, Aspire.Cli.osx-arm64, Aspire.Cli.osx-x64 | Clients and hosts | high | 2026-11-11 | Deprecated MCP configuration scanner wrote configuration content to insecure temporary files. |
| [GHSA-5m6c-38r8-5w76](https://osv.dev/vulnerability/GHSA-5m6c-38r8-5w76) | CVE-2026-102943 | github.com/dagu-org/dagu/v2 | Servers | moderate | 2026-11-10 | MCP tools bypassed the path containment fix, allowing YAML file reads outside the workspace. |
| [GHSA-85gg-2gfq-q95m](https://osv.dev/vulnerability/GHSA-85gg-2gfq-q95m) | CVE-2026-87008 | code-graph-rag | Servers | high | 2026-11-09 | Structural search and replace tools followed symlinks out of the project, allowing file reads and overwrites. |
| [GHSA-9vhv-g5hf-m7m7](https://osv.dev/vulnerability/GHSA-9vhv-g5hf-m7m7) | CVE-2026-102610 | fast-agent-mcp | Servers | moderate | 2026-11-09 | The serve command bound to all interfaces without authentication; with shell access enabled, that allowed remote command execution. |
| [GHSA-wchh-mrv2-5h4q](https://osv.dev/vulnerability/GHSA-wchh-mrv2-5h4q) | CVE-2026-86041 | github.com/mayswind/ezbookkeeping | Servers | moderate | 2026-11-09 | Spoofed X-Forwarded-For headers bypassed the MCP and API token IP allowlist. |
| [GHSA-vvr2-h2jp-838m](https://osv.dev/vulnerability/GHSA-vvr2-h2jp-838m) | CVE-2026-77604 | code-graph-rag | Servers | high | 2026-11-09 | Paginated read_file MCP tool allowed path traversal and arbitrary file reads. |
| [GHSA-h7c4-q426-7jh9](https://osv.dev/vulnerability/GHSA-h7c4-q426-7jh9) | CVE-2026-76893 | @tsparticles/mcp-server | Servers | moderate | 2026-11-09 | One anonymous client could take the shared HTTP session and lock out all other clients. |
| [GHSA-4p8p-pjpq-2w7h](https://osv.dev/vulnerability/GHSA-4p8p-pjpq-2w7h) | CVE-2026-76892 | @tsparticles/mcp-server | Servers | high | 2026-11-09 | One malformed JSON request crashed the HTTP server process. |
| [GHSA-447x-qqwf-m7xq](https://osv.dev/vulnerability/GHSA-447x-qqwf-m7xq) | CVE-2026-63655 | @tsparticles/mcp-server | Servers | high | 2026-11-09 | HTTP mode buffered request bodies without a size limit, allowing remote denial of service. |
| [GO-2026-6911](https://osv.dev/vulnerability/GO-2026-6911) |  | github.com/mark3labs/mcp-go | Clients and hosts |  | 2026-11-05 | Client followed redirects to any host and sent OAuth tokens and custom headers along. |
| [RUSTSEC-2026-0462](https://osv.dev/vulnerability/RUSTSEC-2026-0462) |  | rmcp | Clients and hosts |  | 2026-11-05 | Streamable HTTP clients buffered response bodies without limit. |
| [GHSA-q344-5v34-gm84](https://osv.dev/vulnerability/GHSA-q344-5v34-gm84) | CVE-2026-62264 | @sylphx/pdf-reader-mcp | Servers | high | 2026-10-29 | HTTP transport ignored the configured API key and accepted unauthenticated requests. |
| [GHSA-4mfg-r38w-w8fg](https://osv.dev/vulnerability/GHSA-4mfg-r38w-w8fg) |  | mcp-sanitizer | Servers | high | 2026-10-28 | URL sanitizer let localhost and IPv6 loopback addresses through, enabling SSRF from MCP tools. |
| [GHSA-7w82-6f9j-v9jp](https://osv.dev/vulnerability/GHSA-7w82-6f9j-v9jp) |  | mcp-sanitizer | Servers | high | 2026-10-28 | File path sanitizer allowed any path under user home directories. |
| [GHSA-c8r8-95hg-mp34](https://osv.dev/vulnerability/GHSA-c8r8-95hg-mp34) | CVE-2026-60083 | github.com/siyuan-note/siyuan/kernel | Servers | moderate | 2026-10-27 | MCP file tool's blocklist missed sensitive files the HTTP API protects, exposing publish-mode passwords. |
| [GHSA-fq6x-j3g6-xx83](https://osv.dev/vulnerability/GHSA-fq6x-j3g6-xx83) | CVE-2026-106765 | @rog0x/mcp-docker-tools | Servers | high | 2026-10-23 | Arbitrary code execution through the image list handler. |
| [GHSA-2vq3-mpmf-9xgr](https://osv.dev/vulnerability/GHSA-2vq3-mpmf-9xgr) | CVE-2026-106763 | @justice8096/sagemath-mcp-server | Servers | high | 2026-10-23 | Arbitrary code execution through its shell-escaping and code-sanitizing functions. |
| [GHSA-jwc4-922r-f2rw](https://osv.dev/vulnerability/GHSA-jwc4-922r-f2rw) | CVE-2026-106764 | @rog0x/mcp-git-tools | Servers | high | 2026-10-23 | Arbitrary code execution through base branch resolution. |
| [RUSTSEC-2026-0457](https://osv.dev/vulnerability/RUSTSEC-2026-0457) |  | rmcp | Clients and hosts |  | 2026-10-22 | OAuth client SSRF filter checked host strings, not resolved addresses. |
| [RUSTSEC-2026-0461](https://osv.dev/vulnerability/RUSTSEC-2026-0461) |  | rmcp | Servers |  | 2026-10-20 | Server transport cached tool lookups without limit, including unknown tool names. |
| [GHSA-84m7-p3x7-pcfv](https://osv.dev/vulnerability/GHSA-84m7-p3x7-pcfv) | CVE-2026-59951 | mcp | Servers | moderate | 2026-10-15 | Streamable HTTP transport accumulated sessions without limit, exhausting resources. |
| [GHSA-w794-rj3p-xv45](https://osv.dev/vulnerability/GHSA-w794-rj3p-xv45) | CVE-2026-105697 | langflow, langflow-base, lfx | Clients and hosts | critical | 2026-10-07 | Arbitrary command in an MCP stdio server configuration led to code execution. |
| [GHSA-6qxp-vccf-f47h](https://osv.dev/vulnerability/GHSA-6qxp-vccf-f47h) | CVE-2026-104850 | @modelcontextprotocol/client, @modelcontextprotocol/sdk | Clients and hosts | high | 2026-10-06 | OAuth client could send credentials to an authorization server chosen by the MCP server. |
| [GHSA-c9xm-49cp-xcr9](https://osv.dev/vulnerability/GHSA-c9xm-49cp-xcr9) |  | rmcp | Clients and hosts | moderate | 2026-10-02 | OAuth client fetched server-supplied resource_metadata URLs without origin or private-network checks. |
| [GHSA-qg2g-g9w3-m5h8](https://osv.dev/vulnerability/GHSA-qg2g-g9w3-m5h8) | CVE-2026-58197 | github.com/stacklok/toolhive | Clients and hosts | high | 2026-09-18 | Containerized MCP servers could reach host services through host.docker.internal. |
| [GHSA-33f5-2c5q-wgwj](https://osv.dev/vulnerability/GHSA-33f5-2c5q-wgwj) | CVE-2026-63127 | rmcp | Clients and hosts | high | 2026-09-16 | OAuth client did not validate the resource field in protected resource metadata. |
| [GHSA-wcjj-9m6g-2fr2](https://osv.dev/vulnerability/GHSA-wcjj-9m6g-2fr2) | CVE-2026-59176 | functype-mcp-server | Servers | high | 2026-09-09 | Version tool passed an unchecked package alias to pnpm install, allowing code execution. |
| [GHSA-hvfh-5mj3-5f3j](https://osv.dev/vulnerability/GHSA-hvfh-5mj3-5f3j) | CVE-2026-120492, CVE-2026-45019 | chainlit | Clients and hosts | high | 2026-08-25 | MCP SSE and streamable HTTP connections allowed unauthenticated SSRF to internal networks when MCP is enabled. |
| [GHSA-xm98-3vcf-fph7](https://osv.dev/vulnerability/GHSA-xm98-3vcf-fph7) | CVE-2026-53710 | mcp-contextforge-gateway | Servers | critical | 2026-08-24 | Sandbox bypass in the bundled python_sandbox_server sample; the gateway itself was not affected. |
| [GHSA-p7w7-4929-vpj5](https://osv.dev/vulnerability/GHSA-p7w7-4929-vpj5) | CVE-2026-123811 | @dynatrace-oss/dynatrace-mcp-server | Servers | high | 2026-07-31 | HTTP transport ran MCP tool calls without any authentication. |
| [GHSA-xrmj-5g4g-8987](https://osv.dev/vulnerability/GHSA-xrmj-5g4g-8987) | CVE-2026-123809 | @dynatrace-oss/dynatrace-mcp-server | Servers | moderate | 2026-07-31 | Workflow tool allowed template injection that exfiltrates event data. |
| [GHSA-pqh8-p93p-2rx7](https://osv.dev/vulnerability/GHSA-pqh8-p93p-2rx7) | CVE-2026-123810 | @dynatrace-oss/dynatrace-mcp-server | Servers | moderate | 2026-07-31 | DQL injection through parameters typed as identifiers bypassed the read tools' limits. |
| [GHSA-pc2w-4mq8-32qw](https://osv.dev/vulnerability/GHSA-pc2w-4mq8-32qw) | CVE-2026-123812 | @dynatrace-oss/dynatrace-mcp-server | Servers | low | 2026-07-29 | Notebook tool skipped the human-approval prompt the other write tools use. |
| [GHSA-w4q6-qw23-4rg7](https://osv.dev/vulnerability/GHSA-w4q6-qw23-4rg7) | CVE-2026-47427 | github.com/github/github-mcp-server | Servers | high | 2026-07-28 | Nil pointer dereference in the completion handler caused denial of service. |
| [GHSA-7488-6r32-c95q](https://osv.dev/vulnerability/GHSA-7488-6r32-c95q) | CVE-2026-59822 | litellm | Gateways and proxies | high | 2026-07-22 | MCP authentication bypass through an OAuth2 passthrough fallback. |
| [GHSA-jpw9-pfvf-9f58](https://osv.dev/vulnerability/GHSA-jpw9-pfvf-9f58) | CVE-2026-52869 | mcp | Servers | high | 2026-07-16 | HTTP transports served session requests without checking the authenticated principal. |
| [GHSA-hvrp-rf83-w775](https://osv.dev/vulnerability/GHSA-hvrp-rf83-w775) | CVE-2026-52870 | mcp | Servers | high | 2026-07-16 | Experimental task handlers let any client access and cancel other clients' tasks. |
| [GHSA-wmg3-h8mf-wgvr](https://osv.dev/vulnerability/GHSA-wmg3-h8mf-wgvr) | CVE-2026-61459 | mcp-server-kubernetes | Servers | critical | 2026-07-10 | Argument injection could expose Kubernetes cluster credentials. |
| [GHSA-h9f9-h6gm-wc85](https://osv.dev/vulnerability/GHSA-h9f9-h6gm-wc85) | CVE-2026-55786 | flyto-core | Servers | high | 2026-07-06 | The HTTP MCP endpoint accepted unauthenticated tool calls and executed modules, allowing remote command execution. |
| [GHSA-73cv-556c-w3g6](https://osv.dev/vulnerability/GHSA-73cv-556c-w3g6) | CVE-2026-49257 | mcp-pinot-server | Servers | critical | 2026-06-26 | Default HTTP mode bound to all interfaces with authentication disabled, exposing tools to unauthenticated callers. |
| [GHSA-pjp5-fpmr-3349](https://osv.dev/vulnerability/GHSA-pjp5-fpmr-3349) | CVE-2026-48529 | github.com/github/github-mcp-server | Servers | moderate | 2026-06-25 | Shared lockdown-mode state in the HTTP server mixed up GraphQL clients across users. |
| [GHSA-r2xf-7jw5-pjg6](https://osv.dev/vulnerability/GHSA-r2xf-7jw5-pjg6) | CVE-2026-55887 | github.com/docker/mcp-gateway | Gateways and proxies | high | 2026-06-18 | Argument injection through YAML in OCI image labels. |
| [GHSA-8q5r-mmjf-575q](https://osv.dev/vulnerability/GHSA-8q5r-mmjf-575q) | CVE-2026-47751 | anthropics/claude-code-action | Clients and hosts | moderate | 2026-06-10 | MCP server configuration in a pull request could run code and exfiltrate secrets. |
| [GHSA-g53w-w6mj-hrpp](https://osv.dev/vulnerability/GHSA-g53w-w6mj-hrpp) |  | github.com/Kuadrant/mcp-gateway | Gateways and proxies | critical | 2026-05-19 | Hardcoded shared header value let callers bypass JWT session checks and redirect upstream traffic. |
| [GHSA-4gph-2hhr-5mwg](https://osv.dev/vulnerability/GHSA-4gph-2hhr-5mwg) |  | github.com/envoyproxy/ai-gateway | Gateways and proxies | moderate | 2026-05-19 | Case-insensitive JSON-RPC parsing let altered MCP messages bypass security controls in layered setups. |
| [GHSA-2v5f-5r6w-p67r](https://osv.dev/vulnerability/GHSA-2v5f-5r6w-p67r) | CVE-2026-45781 | github.com/modelcontextprotocol/registry | Registries and supply chain | low | 2026-05-19 | OCI validator skipped the package ownership check when the upstream registry rate-limited. |
| [GHSA-9mqq-jqxf-grvw](https://osv.dev/vulnerability/GHSA-9mqq-jqxf-grvw) | CVE-2026-44336 | praisonai | Servers | critical | 2026-05-11 | Rules and workflow tools joined caller-supplied paths without containment, enabling path traversal and code execution through .pth files. |
| [GHSA-r48c-v28r-pf6v](https://osv.dev/vulnerability/GHSA-r48c-v28r-pf6v) | CVE-2026-44430 | github.com/modelcontextprotocol/registry | Registries and supply chain | moderate | 2026-05-08 | Unauthenticated SSRF: namespace verification reached private IPv6 ranges past the allowlist. |
| [GHSA-rqv2-m695-f8j4](https://osv.dev/vulnerability/GHSA-rqv2-m695-f8j4) | CVE-2026-44429 | github.com/modelcontextprotocol/registry | Registries and supply chain | moderate | 2026-05-08 | Stored XSS in the catalogue UI through a publisher-set websiteUrl. |
| [GHSA-95c3-6vvw-4mrq](https://osv.dev/vulnerability/GHSA-95c3-6vvw-4mrq) | CVE-2026-44428 | github.com/modelcontextprotocol/registry | Registries and supply chain | low | 2026-05-08 | GitHub OIDC tokens could be replayed across registry deployments (shared audience). |
| [GHSA-v8vw-gw5j-w7m6](https://osv.dev/vulnerability/GHSA-v8vw-gw5j-w7m6) | CVE-2026-44427 | github.com/modelcontextprotocol/registry | Registries and supply chain | moderate | 2026-05-08 | Open redirect via protocol-relative paths. |
| [GHSA-89vp-x53w-74fx](https://osv.dev/vulnerability/GHSA-89vp-x53w-74fx) | CVE-2026-42559 | rmcp | Servers | high | 2026-05-06 | DNS rebinding in the Streamable HTTP server transport. |
| [GHSA-v4p8-mg3p-g94g](https://osv.dev/vulnerability/GHSA-v4p8-mg3p-g94g) | CVE-2026-42271 | litellm | Gateways and proxies | high | 2026-04-25 | Authenticated users could run commands through MCP stdio test endpoints. |
| [GHSA-9qhq-v63v-fv3j](https://osv.dev/vulnerability/GHSA-9qhq-v63v-fv3j) | CVE-2026-41497 | praisonai | Clients and hosts | critical | 2026-04-17 | The fix for MCP command injection added no executable allowlist, so arbitrary commands still ran. |
| [GHSA-xrxf-jgv3-qmrm](https://osv.dev/vulnerability/GHSA-xrxf-jgv3-qmrm) | CVE-2025-61260 | @openai/codex | Clients and hosts | critical | 2026-04-14 | MCP configuration files in a repository could run code. |
| [GHSA-8jxr-pr72-r468](https://osv.dev/vulnerability/GHSA-8jxr-pr72-r468) | CVE-2026-35568 | io.modelcontextprotocol.sdk:mcp-core | Servers | high | 2026-04-07 | DNS rebinding in the Java SDK. |
| [GHSA-98f9-fqg5-hvq5](https://osv.dev/vulnerability/GHSA-98f9-fqg5-hvq5) | CVE-2026-34953 | praisonai | Servers | critical | 2026-04-01 | Token validation returned true for unknown tokens, giving any bearer token full access to the MCP HTTP server. |
| [GHSA-9gm9-c8mq-vq7m](https://osv.dev/vulnerability/GHSA-9gm9-c8mq-vq7m) | CVE-2026-34935 | praisonai | Clients and hosts | critical | 2026-04-01 | The --mcp argument was split and run as a process without validation, allowing arbitrary command execution. |
| [GHSA-xw59-hvm2-8pj6](https://osv.dev/vulnerability/GHSA-xw59-hvm2-8pj6) | CVE-2026-34742 | github.com/modelcontextprotocol/go-sdk | Servers | high | 2026-04-01 | DNS rebinding protection was off by default for localhost servers. |
| [GHSA-vv7q-7jx5-f767](https://osv.dev/vulnerability/GHSA-vv7q-7jx5-f767) | CVE-2026-32871 | fastmcp | Servers | critical | 2026-03-31 | SSRF and path traversal in the OpenAPI provider. |
| [GHSA-rww4-4w9c-7733](https://osv.dev/vulnerability/GHSA-rww4-4w9c-7733) | CVE-2026-27124 | fastmcp | Servers | high | 2026-03-31 | OAuth proxy callback skipped consent checks, enabling confused deputy attacks. |
| [GHSA-hv2w-8mjj-jw22](https://osv.dev/vulnerability/GHSA-hv2w-8mjj-jw22) | CVE-2026-34237 | io.modelcontextprotocol.sdk:mcp-core | Servers | moderate | 2026-03-30 | Hardcoded wildcard CORS (Access-Control-Allow-Origin: *). |
| [GHSA-89xv-2j6f-qhc8](https://osv.dev/vulnerability/GHSA-89xv-2j6f-qhc8) | CVE-2026-33252 | github.com/modelcontextprotocol/go-sdk | Servers | high | 2026-03-19 | HTTP servers without authorization allowed cross-site tool execution. |
| [GHSA-q382-vc8q-7jhj](https://osv.dev/vulnerability/GHSA-q382-vc8q-7jhj) |  | github.com/modelcontextprotocol/go-sdk | Servers | high | 2026-03-19 | JSON parser treated keys with a trailing null character as the same key. |
| [GHSA-5h2m-4q8j-pqpj](https://osv.dev/vulnerability/GHSA-5h2m-4q8j-pqpj) | CVE-2025-69196 | fastmcp | Servers | high | 2026-03-16 | OAuth proxy accepted tokens issued for one MCP server at another. |
| [GHSA-hhfx-wfvq-7g9c](https://osv.dev/vulnerability/GHSA-hhfx-wfvq-7g9c) | CVE-2026-26118 | @azure/mcp, Azure.Mcp, msmcp-azure | Servers | high | 2026-03-10 | Server-side request forgery let an authorized attacker elevate privileges. |
| [GHSA-v2x6-wwfw-r2rq](https://osv.dev/vulnerability/GHSA-v2x6-wwfw-r2rq) | CVE-2026-29791 | github.com/agentgateway/agentgateway | Gateways and proxies | moderate | 2026-03-05 | Missing parameter sanitization when converting MCP calls to OpenAPI requests. |
| [GHSA-p9x3-w98f-7j3q](https://osv.dev/vulnerability/GHSA-p9x3-w98f-7j3q) | CVE-2026-28361 | nocodb | Servers | moderate | 2026-03-02 | MCP token operations skipped the ownership check, letting users in the same base read, regenerate or delete each other's tokens. |
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
| [GHSA-6933-jpx5-q87q](https://osv.dev/vulnerability/GHSA-6933-jpx5-q87q) | CVE-2025-71336 | flowise | Clients and hosts | critical | 2025-09-15 | Custom MCP feature ran OS commands without sandboxing, allowing remote code execution. |
| [GHSA-4hqq-7q79-932p](https://osv.dev/vulnerability/GHSA-4hqq-7q79-932p) | CVE-2025-59377 | mcp-kubernetes-server | Servers | critical | 2025-09-15 | The kubectl endpoint built shell commands from user input, allowing OS command injection even in read-only mode. |
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
| [MAL-2026-20295](https://osv.dev/vulnerability/MAL-2026-20295) | @guicai777/mcp-doctor | 2026-11-20 |
| [MAL-2026-20187](https://osv.dev/vulnerability/MAL-2026-20187) | @fdcasj_dfew/md-doc-mcp | 2026-11-18 |
| [MAL-2026-20068](https://osv.dev/vulnerability/MAL-2026-20068) | mcp-aevo-server | 2026-11-17 |
| [MAL-2026-20061](https://osv.dev/vulnerability/MAL-2026-20061) | vamp-mcp | 2026-11-17 |
| [MAL-2026-20008](https://osv.dev/vulnerability/MAL-2026-20008) | @shadowdqj/image-mcp | 2026-11-16 |
| [MAL-2026-20009](https://osv.dev/vulnerability/MAL-2026-20009) | @shadowdu/memos-mcp | 2026-11-16 |
| [MAL-2026-20011](https://osv.dev/vulnerability/MAL-2026-20011) | mem0-mcp-server | 2026-11-16 |
| [MAL-2026-19235](https://osv.dev/vulnerability/MAL-2026-19235) | karma365-mcp | 2026-11-13 |
| [MAL-2026-19204](https://osv.dev/vulnerability/MAL-2026-19204) | my-mcp-server-driving-license-ocr | 2026-11-13 |
| [MAL-2026-19159](https://osv.dev/vulnerability/MAL-2026-19159) | @go-gost/mcp-darwin-x64 | 2026-11-12 |
| [MAL-2026-19148](https://osv.dev/vulnerability/MAL-2026-19148) | @rfewqa-fes/mnm-doc-mcp | 2026-11-12 |
| [MAL-2026-19085](https://osv.dev/vulnerability/MAL-2026-19085) | @lemili9804/mcp-weather-server | 2026-11-10 |
| [MAL-2026-19082](https://osv.dev/vulnerability/MAL-2026-19082) | mcp-contract-tester | 2026-11-10 |
| [MAL-2026-19052](https://osv.dev/vulnerability/MAL-2026-19052) | @bestcoolman/dev-mcp | 2026-11-09 |
| [MAL-2026-18780](https://osv.dev/vulnerability/MAL-2026-18780) | @massnerder/x402-scraper-mcp | 2026-11-09 |
| [MAL-2026-18706](https://osv.dev/vulnerability/MAL-2026-18706) | mcp-teamviewer | 2026-11-05 |
| [MAL-2026-18705](https://osv.dev/vulnerability/MAL-2026-18705) | teamviewer-mcp-server | 2026-11-05 |
| [MAL-2026-18603](https://osv.dev/vulnerability/MAL-2026-18603) | @ifasn/ms-doc-mcp | 2026-11-04 |
| [MAL-2026-18488](https://osv.dev/vulnerability/MAL-2026-18488) | @ifasn/mmd-doc-mcp | 2026-11-02 |
| [MAL-2026-18486](https://osv.dev/vulnerability/MAL-2026-18486) | @ifasn/md-doc-mcp | 2026-11-02 |
| [MAL-2026-18489](https://osv.dev/vulnerability/MAL-2026-18489) | @ifasn/mmdd-doc-mcp | 2026-11-02 |
| [MAL-2026-18487](https://osv.dev/vulnerability/MAL-2026-18487) | @ifasn/mdd-doc-mcp | 2026-11-02 |
| [MAL-2026-18358](https://osv.dev/vulnerability/MAL-2026-18358) | @testsecuiitytestme/cache-helper | 2026-10-29 |
| [MAL-2026-17924](https://osv.dev/vulnerability/MAL-2026-17924) | @apexacc/cli | 2026-10-26 |
| [MAL-2026-18322](https://osv.dev/vulnerability/MAL-2026-18322) | numbors | 2026-10-26 |
| [MAL-2026-16355](https://osv.dev/vulnerability/MAL-2026-16355) | gemini-computer-use | 2026-09-21 |
| [MAL-2026-5478](https://osv.dev/vulnerability/MAL-2026-5478) | mcp-server-git | 2026-06-09 |
| [MAL-2026-5479](https://osv.dev/vulnerability/MAL-2026-5479) | mcp-server-github | 2026-06-09 |
| [MAL-2026-4675](https://osv.dev/vulnerability/MAL-2026-4675) | supership-scan | 2026-05-20 |
| [MAL-2026-3679](https://osv.dev/vulnerability/MAL-2026-3679) | @2oolkit/hyperliquid-cli | 2026-05-12 |
| [MAL-2025-191788](https://osv.dev/vulnerability/MAL-2025-191788) | mcp-runcmd-server | 2025-10-13 |
| [MAL-2025-191647](https://osv.dev/vulnerability/MAL-2025-191647) | mcp-runcommand-server | 2025-10-10 |
| [MAL-2025-47838](https://osv.dev/vulnerability/MAL-2025-47838) | @lanyer640/mcp-runcommand-server | 2025-09-29 |
| [MAL-2025-47604](https://osv.dev/vulnerability/MAL-2025-47604) | postmark-mcp | 2025-09-26 |
