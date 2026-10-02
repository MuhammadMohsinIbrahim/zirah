# Zirah — Project Spec (v2)

> Renamed from "MCP Sentinel" (already used by 5+ GitHub repos and by Microsoft Sentinel's MCP server). Zirah (زرہ) means armor. The PyPI distribution is `zirah-mcp` (free on PyPI, checked Oct 2026); the import package and the command stay `zirah`. 0.1.0 shipped on PyPI on 2026-10-02.
>
> **v2 changes:** applies the architecture review (Sept 2026): loaders and execution modes per release, two verification levels, attestation trust model, registry abuse policy, `trust_score` replaces the risk score, multi-target `ScanSession`, and a six-release roadmap. Build progress is tracked in `docs/PLAN.md`.

**One line:** An open-source, offline-first trust layer for the AI agent supply chain. It scans MCP servers, Agent Skills and A2A agent cards with static, semantic *and dynamic (sandbox detonation)* analysis. It turns each result into a **signed attestation** published to a public registry that tracks every version over time.

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
2. **Verifiable evidence, not just a score:** every registry scan produces a signed attestation (Ed25519 → later Sigstore/in-toto). Static findings are reproducible bit-for-bit; LLM and dynamic findings are evidence-attested (see §4.4). The registry is an append-only, hash-chained transparency log.
3. **Version timeline and rug-pull detection:** the registry stores a manifest hash for every version and diffs tool descriptions across versions. A server that turns malicious in v1.0.16 (like postmark-mcp) gets flagged at the exact version.
4. **Composition analysis (attack graph):** we scan a user's *whole* agent config and build a graph of data flows across servers. It finds "lethal trifecta" paths (private data + untrusted input + exfil channel) and renders them visually.
5. **Offline-first, provider-agnostic:** works with no account and no cloud. The LLM judge can run on Ollama (local), OpenAI or Anthropic, or not at all (`--llm none`). The opposite of Snyk's approach.
6. **Published detection metrics:** a `bench/` harness reports precision/recall against public benchmarks plus our own labelled corpus, and CI publishes a badge. Almost no tool does this, and it's the thing that earns credibility on GitHub.

Beyond MCP: **Agent Skills** (SKILL.md bundles) and **A2A Agent Cards** use the same engine. A2A coverage is nearly empty in the market.

## 3. Detection modules (14, mapped to OWASP MCP Top 10)

| # | Module | OWASP | Engine | Phase |
|---|---|---|---|---|
| D1 | Tool poisoning: hidden instructions, invisible Unicode/ANSI, HTML/markdown smuggling in descriptions & schemas | MCP03 | static + LLM | v0.1 |
| D2 | Prompt injection patterns in prompts/resources | MCP06 | static + LLM | v0.1 |
| D3 | Tool shadowing / interference. **Single-manifest** (a description references or overrides other tools): v0.1. **Cross-server** (runs in the `graph` stage over a `ScanSession`): v0.5 | MCP03 | static + LLM | v0.1 / v0.5 |
| D4 | Secrets & token mismanagement (hard-coded keys, tokens in args/logs) | MCP01 | static | v0.1 |
| D5 | Dangerous sinks in source: shell/eval/path traversal/SSRF dataflow | MCP05 | code analysis (Semgrep rules) | v0.2 |
| D6 | Capability profile & blast radius (fs/network/exec/cred access → score). **Static half** v0.2, **dynamic half** with the sandbox in v0.4 | MCP02 | static / dynamic | v0.2 / v0.4 |
| D7 | Supply chain: dependency CVEs (OSV), typosquats, install scripts, maintainer change, provenance | MCP04 | metadata | v0.2 |
| D8 | **Dynamic detonation:** canary leaks, unexpected egress, fs writes, process spawn | MCP03/04/05 | sandbox | v0.4 |
| D9 | Response poisoning: tool outputs that carry injection (fetches untrusted content) | MCP06 | sandbox + LLM | v0.4 |
| D10 | **Rug-pull / manifest drift** across versions and sessions | MCP03/04 | registry diff | v0.3 |
| D11 | **Toxic-flow composition graph** across a full agent config | MCP02/10 | graph | v0.5 |
| D12 | Context over-sharing metric (sensitive-data share of the context, memory-write tools) | MCP10 | graph + LLM | v0.5 |
| D13 | Remote-server auth checks: no auth, OAuth misconfig, metadata endpoint exposure | MCP07 | live probe | v0.5 |
| D14 | Shadow MCP discovery: local configs across Claude Desktop/Claude Code/Cursor/VS Code/Windsurf | MCP09 | local discovery | v0.1 |
| — | Standard finding schema + SARIF (v0.1) + signed attestations (v0.3) (audit story) | MCP08 | platform | v0.1 → v0.3 |
| — | Agent Skills + A2A Agent Card scanning | beyond | same engine | v0.6 |

A finding may map to several OWASP categories (`Finding.owasp` is a non-empty list).

## 4. Architecture

Decision: **use Python for all backend code, not NestJS + FastAPI.** Two backend languages double the work for a solo builder and add nothing a user can see. Serious OSS security tools ship one CLI package. Next.js stays for the web.

```
zirah/                      (monorepo)
├── core/                    Python package → PyPI `zirah-mcp` (the heart)
│   ├── zirah/
│   │   ├── models.py        Target, Manifest, Finding, ScanResult, ScanSession (pydantic)
│   │   ├── loaders/         v0.1: stdio / streamable-http / sse / static JSON
│   │   │                    v0.2: git repo / npm / pypi (download source only, never execute)
│   │   ├── runners/         v0.2: docker (minimal isolated runner for stdio targets)
│   │   ├── analyzers/       plugin per module (D1..D14), common Analyzer interface
│   │   ├── rules/           YAML rule packs (regex, unicode, keywords) — community editable
│   │   ├── similarity/      v0.2: bundled known-bad corpus, lexical similarity; [embed] extra
│   │   ├── llm/             provider abstraction: ollama | openai | anthropic | none
│   │   ├── scoring.py       trust score + grade, explainable (every point traces to a finding)
│   │   ├── graph.py         v0.5: graph stage over a ScanSession (D3 cross-server, D11, D12)
│   │   ├── attest.py        v0.3: canonical JSON → sha256 → Ed25519 signature
│   │   ├── mcp_server.py    v0.2: `zirah mcp` exposing check_tool_trust
│   │   ├── report/          json | sarif | markdown | terminal (rich)
│   │   └── cli.py           typer: scan, discover, mcp, verify, graph, bench
│   └── tests/
├── sandbox/                 v0.4: detonation runner
│   ├── Dockerfile.runner    node + python base, non-root, no caps
│   ├── canaries.py          fake HOME, .env, ~/.ssh, AWS creds with unique tokens
│   ├── egress/              mitmproxy addon logging all traffic
│   └── fuzz.py              args from JSON schema (hypothesis-jsonschema)
├── api/                     v0.3: FastAPI service
│   ├── routes/              /submissions, /registry, /attestations, /.well-known/zirah-keys.json
│   ├── worker.py            arq (Redis) job queue for registry scans (& detonation from v0.4)
│   └── db/                  SQLAlchemy + Alembic, Postgres + pgvector
├── web/                     v0.3 basic registry pages; v0.5 attack-graph view (React Flow)
├── action/                  v0.2: GitHub Action: scan on PR, upload SARIF to code scanning
├── bench/                   v0.5: corpus (malicious/benign fixtures) + eval harness
├── docs/                    PLAN.md (build plan, not published); mkdocs site in v0.6 (excludes PLAN.md)
├── DISPUTES.md              v0.3: how maintainers claim listings and respond to findings
└── docker-compose.yml       postgres, redis, api, worker, web
```

**MCP client:** Runtime uses a minimal in-house MCP client for a small, auditable dependency footprint; the official SDK is used for conformance tests. The client only negotiates (protocol 2024-11-05 and newer: `initialize` for 2024- and 2025-era servers, `server/discover` for 2026-07-28) and lists tools, prompts and resources. It never calls a tool, and it enforces limits on message size, items, pages, per-request time and total time.

### 4.1 Scan pipeline

`load target → extract manifest (tools/prompts/resources/instructions) → hash manifest → run analyzers in parallel → (optional) detonate in sandbox → dedupe findings → score → (optional) sign attestation → output / publish to registry`

**Multi-target:** `zirah scan --all` (every server found by `discover`) or several targets produce a **`ScanSession`**: a list of `ScanResult`s from one run. Cross-server analysis (D3 cross-server, D11, D12) is a separate **`graph` stage** that consumes a `ScanSession`; it never runs inside a single-target scan.

### 4.2 Core data contract

Everything depends on this; it lives in `core/zirah/models.py`.
```
Finding     { id, module (D1..D14), rule_id, severity, confidence, owasp[1..],
              title, evidence {location, snippet≤2000 chars}, remediation,
              engine (static|llm|dynamic) }
ScanResult  { schema_version, target, manifest_sha256, zirah_version, rulepack_version,
              findings[], trust_score (0–100, 100 = no findings), grade (A–F),
              started_at, finished_at, engines_used[],
              llm {provider, model, prompt_sha256, temperature} | null,
              score_breakdown {deductions[], total_points, deducted_points,
                               uncapped_score, cap} | null,
              signature }                                  (schema_version "0.2")
ScanSession { results[] }                                   (v0.1, for scan --all)
```
**Trust score:** 0–100, where 100 means no findings. Grades: **A ≥ 90, B ≥ 75, C ≥ 60, D ≥ 40, F < 40**. Thresholds and weights are defined in `scoring.py` only.

**Added in v0.3 with `attest.py`** (not before): `key_id` and `attestation_level: self | registry`. The LLM prompt hash and temperature are already recorded in `llm` since v0.1 (temperature is 0, or `null` for models that accept no sampling parameters).

### 4.3 Execution modes (running untrusted server code)

| Mode | Release | Isolation | Use |
|---|---|---|---|
| Static manifest / downloaded source | v0.1 / v0.2 | none needed: nothing executes | Default and preferred |
| `--allow-exec` (stdio) | v0.1 | **none**: runs on the host with the user's permissions | Required flag; prints a red warning: *"This runs the server's code on your machine with your user permissions. Prefer --docker or a static manifest."* |
| `--docker` | v0.2 | container, no host mounts, read-only fs; no canaries, no egress capture | Safer manifest extraction for stdio servers |
| `--detonate` (sandbox) | v0.4 | full sandbox (below) with canaries + mitmproxy | D8, D9, D6-dynamic |

Git, npm and PyPI loaders only download source and metadata; they never run install scripts or code.

**Sandbox safety (v0.4):** runs with `--network none` except through the mitmproxy sidecar, read-only root filesystem, CPU/memory/time limits, no host mounts and a disposable container per scan. Never detonate on the API host in production; use a separate worker. On the registry, detonation only runs on registry-queued jobs, never on demand.

### 4.4 Verification levels

`zirah verify <attestation>` does two different things depending on the engine that produced each finding:

1. **Reproducible (static findings):** check the signature and `key_id` against the published keys and revocation list, recompute the manifest hash, and re-run the static analyzers with the recorded `zirah_version` and `rulepack_version`. The static findings **must match exactly**.
2. **Evidence-attested (LLM and dynamic findings):** LLM output and sandbox behaviour are not deterministic. The signed result stores their evidence, prompt hash, model and temperature (0). `verify` checks that this evidence exists and is covered by the signature, but does **not** require identical re-output.

### 4.5 Attestation trust model

- The **registry holds its own Ed25519 key**. Public keys and a **revocation list** are published at `/.well-known/zirah-keys.json`. Every attestation carries a `key_id`.
- The registry **never accepts submitted results**. Users submit a target identifier; the registry worker scans it itself and signs the result (`attestation_level: registry`).
- Local CLI results can be signed with a **user key**, labelled **"self-attested"** (`attestation_level: self`), and are never shown as registry-verified.
- Sigstore/in-toto replaces or complements Ed25519 in the last release (v0.6).

### 4.6 Registry policy (privacy, abuse, legal)

- **D14 results never leave the machine.** `discover` has no upload path.
- The registry only accepts **public identifiers**: npm or PyPI `package@version`, or a public GitHub `repo@commit`. No arbitrary URLs, no private servers.
- Scans are **deduped by identifier@version**: scan once, serve many.
- Submitting requires **GitHub login** plus per-user and global quotas. Public endpoints are rate limited (slowapi).
- **Wording:** we publish "findings" and a "trust score". We never publish the verdict "malicious".
- **Disputes** (`DISPUTES.md`): maintainers can claim a listing, respond to findings and request a re-scan.

### 4.7 Similarity to known-bad descriptions

- **v0.2 (offline CLI):** a bundled known-bad corpus with lexical similarity (rapidfuzz / MinHash). Optional local embeddings via the `zirah-mcp[embed]` extra.
- **v0.3 (registry):** pgvector similarity in Postgres.

### 4.8 MCP server mode

`zirah mcp` runs Zirah as an MCP server exposing `check_tool_trust`. **v0.2:** answers from a local scan. **v0.3:** adds registry lookup (registry attestation first, local scan as fallback).

## 5. Decisions carried over from the prototype

The old prototype is **not ported**. Rules and prompts are written fresh from this spec.

| Piece | Decision |
|---|---|
| Next.js design (navy/white, IBM Plex, no gradients) | Keep the design system; build pages fresh for the new API |
| Rate limiting on public endpoints | **Was missing in the prototype (security gap).** Built into the API from day 1 (slowapi) |
| NestJS auth layer | **Dropped** (see §4) |

## 6. Roadmap

| Release | Scope | Target |
|---|---|---|
| **v0.1 — CLI core** | Models, loaders (stdio with `--allow-exec`, streamable-http, sse, static JSON), D1–D4 single-manifest, D14 discover, `scan --all` → ScanSession, scoring, rule packs, LLM judge (ollama/openai/anthropic/none), terminal/JSON/SARIF/markdown reports, 95% coverage floor in CI, README with GIF, publish 0.1.0 to PyPI | Weeks 1–3 |
| **v0.2 — Deep static** | Git/npm/PyPI loaders (source only), D5 (Semgrep), D6-static, D7 (OSV + npm/PyPI metadata), `--docker` runner, bundled similarity corpus (+ `zirah-mcp[embed]`), MCP server mode (local), GitHub Action + SARIF upload. **Minimum portfolio-ready release.** | Weeks 4–7 |
| **v0.3 — Registry** | FastAPI + Postgres/pgvector + arq, registry-side scanning of public identifiers, Ed25519 attestations + key endpoint, hash-chained log, D10 drift, `zirah verify`, registry lookup in MCP mode, DISPUTES.md, basic Next.js registry pages | Weeks 8–11 |
| **v0.4 — Sandbox** | Detonation sandbox with canaries + mitmproxy, D8, D9, D6-dynamic | Weeks 12–14 |
| **v0.5 — Graph & proof** | `graph` stage over ScanSession, D3 cross-server, D11, D12, D13, attack-graph UI, bench harness + published metrics badge | Weeks 15–18 |
| **v0.6 — Beyond MCP & launch** | Agent Skills, A2A Agent Cards, Sigstore signing, mkdocs site, launch | Weeks 19–20 |

Ship v0.1 publicly as soon as it works. An early release that works beats a late perfect one.

## 7. GitHub "top-tier" checklist

- Apache-2.0 license, `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, issue/PR templates
- CI: ruff, mypy, pytest. Planned: coverage badge, CodeQL (v0.2), bench-metrics badge (v0.5)
- Releases through GitHub Actions → PyPI (trusted publishing), Docker image to GHCR
- README: 30-second GIF, one-command install (`pipx install zirah-mcp`), comparison table, OWASP mapping, architecture diagram
- `examples/`: a deliberately malicious demo MCP server that people can scan themselves
- Conventional commits, semantic versioning, CHANGELOG

## 8. Non-goals (for now)

A full runtime gateway (Pipelock/Lasso already do this well; we integrate later through a lightweight pin-and-verify shim), enterprise SSO/RBAC, and a paid tier.
