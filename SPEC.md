# Zirah — Project Spec (v1)

> Renamed from "MCP Sentinel" (already used by 5+ GitHub repos and by Microsoft Sentinel's MCP server). Zirah (زرہ) means armor. Confirm "zirah" is free on PyPI before the first release.

**One line:** An open-source, offline-first trust layer for the AI agent supply chain. It scans MCP servers, Agent Skills and A2A agent cards with static, semantic *and dynamic (sandbox detonation)* analysis. It turns each result into a **signed, reproducible attestation** published to a public registry that tracks every version over time.

---

## 1. Does this already exist? (Landscape, Sept 2026)

Yes, parts of it do. The space is crowded, so we cannot win with "another scanner". Here is what is out there:

| Tool | What it does | Weakness we exploit |
|---|---|---|
| **Snyk Agent Scan** (ex-Invariant mcp-scan) | Auto-discovers IDE configs, scans MCP + skills, toxic-flow detection | Needs a Snyk account; **sends data to Snyk's cloud API**; detection logic is closed |
| **Cisco mcp-scanner** | YARA, LLM judge, Cisco API, behavioral *code* analysis, package/binary checks | Complex setup; no public registry; no version history; static only (no detonation) |
| **mcptrustchecker / AgentSeal / Glama scores** | Public trust scores per server | Static/deterministic scoring (as far as their public pages show); a single score, no drift timeline, no verifiable evidence |
| **Pipelock, Lasso, Docker MCP Gateway, Runlayer** | Runtime gateway/firewall | Runtime only; nothing checks a server *before* install |
| **MCP-SandboxScan (research), HoneyMCP, canary-mcp** | WASM sandbox / honeypot tools | Research prototypes or single-purpose tools, not part of a pipeline |
| **MCPSecBench, MCP-SafetyBench** | Academic benchmarks | Benchmarks only; no product publishes precision/recall against them |

**Gaps named by industry reviews (PipeLab "State of MCP Security 2026"):**
cross-session drift/rug-pull detection, behavioral baselining, A2A security, context-oversharing metrics, a standard audit/finding schema, and supply-chain provenance (SBOM, hash-pinning).

## 2. How we're different (the 6 pillars)

1. **Hybrid analysis in one open pipeline:** static + LLM-semantic + **dynamic detonation**. We run the server in a locked container, plant canary secrets, fuzz its tools from their JSON schemas and watch for egress, file changes and canary leaks. Competitors do one or two of these, not all three.
2. **Verifiable evidence, not just a score:** every scan produces a signed attestation (Ed25519 → later Sigstore/in-toto) that anyone can reproduce and verify. The registry is an append-only, hash-chained transparency log.
3. **Version timeline and rug-pull detection:** the registry stores a manifest hash for every version and diffs tool descriptions across versions. A server that turns malicious in v1.0.16 (like postmark-mcp) gets flagged at the exact version.
4. **Composition analysis (attack graph):** we scan a user's *whole* agent config and build a graph of data flows across servers. It finds "lethal trifecta" paths (private data + untrusted input + exfil channel) and renders them visually.
5. **Offline-first, provider-agnostic:** works with no account and no cloud. The LLM judge can run on Ollama (local), OpenAI or Anthropic. The opposite of Snyk's approach.
6. **Published detection metrics:** a `bench/` harness reports precision/recall against public benchmarks plus our own labelled corpus, and CI publishes a badge. Almost no tool does this, and it's the thing that earns credibility on GitHub.

Beyond MCP: **Agent Skills** (SKILL.md bundles) and **A2A Agent Cards** use the same engine. A2A coverage is nearly empty in the market.

## 3. Detection modules (14, mapped to OWASP MCP Top 10)

| # | Module | OWASP | Engine | Phase |
|---|---|---|---|---|
| D1 | Tool poisoning: hidden instructions, invisible Unicode/ANSI, HTML/markdown smuggling in descriptions & schemas | MCP03 | static + LLM | v0.1 |
| D2 | Prompt injection patterns in prompts/resources | MCP06 | static + LLM | v0.1 |
| D3 | Tool shadowing / cross-server interference (description references other tools) | MCP03 | static + LLM | v0.1 |
| D4 | Secrets & token mismanagement (hard-coded keys, tokens in args/logs) | MCP01 | static | v0.1 |
| D5 | Dangerous sinks in source: shell/eval/path traversal/SSRF dataflow | MCP05 | code analysis (Semgrep rules) | v0.2 |
| D6 | Capability profile & blast radius (fs/network/exec/cred access → score) | MCP02 | static + dynamic | v0.2 |
| D7 | Supply chain: dependency CVEs (OSV), typosquats, install scripts, maintainer change, provenance | MCP04 | metadata | v0.2 |
| D8 | **Dynamic detonation:** canary leaks, unexpected egress, fs writes, process spawn | MCP03/04/05 | sandbox | v0.3 |
| D9 | Response poisoning: tool outputs that carry injection (fetches untrusted content) | MCP06 | sandbox + LLM | v0.3 |
| D10 | **Rug-pull / manifest drift** across versions and sessions | MCP03/04 | registry diff | v0.3 |
| D11 | **Toxic-flow composition graph** across a full agent config | MCP02/10 | graph | v0.4 |
| D12 | Context over-sharing metric (sensitive-data share of the context, memory-write tools) | MCP10 | static + LLM | v0.4 |
| D13 | Remote-server auth checks: no auth, OAuth misconfig, metadata endpoint exposure | MCP07 | live probe | v0.4 |
| D14 | Shadow MCP discovery: local configs across Claude/Cursor/VS Code/Windsurf | MCP09 | local discovery | v0.1 |
| — | Standard finding schema + SARIF + signed attestations (audit story) | MCP08 | platform | v0.1 → v0.3 |
| — | Agent Skills + A2A Agent Card scanning | beyond | same engine | v0.5 |

## 4. Architecture

Decision: **use Python for all backend code, not NestJS + FastAPI.** Two backend languages double the work for a solo builder and add nothing a user can see. Serious OSS security tools ship one CLI package. Next.js stays for the web.

```
zirah/                      (monorepo)
├── core/                    Python package → PyPI `zirah` (the heart)
│   ├── zirah/
│   │   ├── models.py        Target, Manifest, Finding, ScanResult (pydantic)
│   │   ├── loaders/         stdio / http / sse / static JSON / git repo / npm / pypi
│   │   ├── analyzers/       plugin per module (D1..D14), common Analyzer interface
│   │   ├── rules/           YAML rule packs (regex, unicode, keywords) — community editable
│   │   ├── llm/             provider abstraction: ollama | openai | anthropic | none
│   │   ├── scoring.py       risk score + grade, explainable (every point traces to a finding)
│   │   ├── attest.py        canonical JSON → sha256 → Ed25519 signature
│   │   ├── report/          json | sarif | markdown | html
│   │   └── cli.py           typer: scan, discover, graph, verify, bench
│   └── tests/
├── sandbox/                 detonation runner
│   ├── Dockerfile.runner    node + python base, non-root, no caps
│   ├── canaries.py          fake HOME, .env, ~/.ssh, AWS creds with unique tokens
│   ├── egress/              mitmproxy addon logging all traffic
│   └── fuzz.py              args from JSON schema (hypothesis-jsonschema)
├── api/                     FastAPI service
│   ├── routes/              /scans, /registry, /attestations, /verify
│   ├── worker.py            arq (Redis) job queue for scans & detonation
│   └── db/                  SQLAlchemy + Alembic, Postgres + pgvector
├── web/                     Next.js: registry browser, server page with version
│                            timeline, findings, attack-graph view (React Flow)
├── action/                  GitHub Action: scan on PR, upload SARIF to code scanning
├── bench/                   corpus (malicious/benign fixtures) + eval harness
├── docs/                    mkdocs site
└── docker-compose.yml       postgres, redis, api, worker, web
```

**Scan pipeline:**
`load target → extract manifest (tools/prompts/resources) → hash manifest → run analyzers in parallel → (optional) detonate in sandbox → dedupe findings → score → sign attestation → output / publish to registry`

**Core data contract** (everything depends on this, so build it first):
```
Finding { id, module (D1..), rule_id, severity, confidence, owasp, title,
          evidence {location, snippet}, remediation, engine (static|llm|dynamic) }
ScanResult { target, manifest_sha256, zirah_version, rulepack_version,
             findings[], score, grade, started_at, signature }
```

**Sandbox safety:** runs with `--network none` except through the mitmproxy sidecar, read-only root filesystem, CPU/memory/time limits, no host mounts and a disposable container per scan. Never detonate on the API host in production; use a separate worker.

## 5. What already exists from the prototype

| Piece | Status | Decision |
|---|---|---|
| D1/D2 static + LLM scanner, FastAPI `/scan` | Prototype worked | **Port rules & prompts** into `core/analyzers`, rewrite to the new interface |
| Self-exposed MCP server (`check_tool_trust`) | Prototype worked | Keep; move into `core/zirah/mcp_server.py` (v0.2) |
| Registry (SQLite, GitHub metadata signal) | Prototype worked | Rebuild on Postgres with versions + attestations (v0.3) |
| Next.js dashboard (navy/white, IBM Plex) | Prototype worked | Keep the design system; rebuild pages for the new API |
| Rate limiting on public submit/flag | **Missing (security gap)** | Built into api from day 1 (slowapi) |
| NestJS auth layer | Not built | **Dropped** (see §4) |
| Vector-DB pattern matching | Not built | pgvector similarity to known-malicious descriptions (v0.2) |

The prototype code lives in the old session's zip. Start a **fresh repo** and port only the rules, prompts and UI design. The architecture changed enough that a rewrite is cleaner.

## 6. Roadmap

| Release | Scope | Target |
|---|---|---|
| **v0.1 — CLI that's useful on day one** | core models, loaders (stdio/http/static), D1–D4, D14 discover, scoring, JSON/SARIF/markdown output, rule packs, Ollama/OpenAI/Anthropic/none LLM, 60%+ test coverage, README with GIF | Weeks 1–3 |
| **v0.2 — Deep static** | D5 (Semgrep), D6, D7 (OSV + npm/PyPI metadata), pgvector similarity, MCP server mode, GitHub Action + SARIF upload | Weeks 4–6 |
| **v0.3 — Differentiators** | Sandbox detonation D8/D9, API + worker, Postgres registry with versions, D10 drift, Ed25519 attestations + hash-chained log, `zirah verify` | Weeks 7–10 |
| **v0.4 — Platform** | Web registry + timeline + attack graph (D11), D12, D13, bench harness + published metrics | Weeks 11–14 |
| **v0.5 — Beyond MCP** | Agent Skills, A2A Agent Cards, Sigstore signing, docs site, launch | Weeks 15–16 |

Ship v0.1 publicly as soon as it works. An early release that works beats a late perfect one.

## 7. GitHub "top-tier" checklist

- Apache-2.0 license, `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, issue/PR templates
- CI: ruff, mypy, pytest, coverage badge, bench-metrics badge, CodeQL, Dependabot
- Releases through GitHub Actions → PyPI (trusted publishing), Docker image to GHCR
- README: 30-second GIF, one-command install (`pipx install zirah`), comparison table, OWASP mapping, architecture diagram
- `examples/`: a deliberately malicious demo MCP server that people can scan themselves
- Conventional commits, semantic versioning, CHANGELOG

## 8. Non-goals (for now)

A full runtime gateway (Pipelock/Lasso already do this well; we integrate later through a lightweight pin-and-verify shim), enterprise SSO/RBAC, and a paid tier.
