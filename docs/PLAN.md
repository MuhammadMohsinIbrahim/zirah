# Zirah build plan

Ordered checklist from v0.1 to v0.6, derived from `SPEC.md` (the source of truth; if they disagree, fix this file).

**How to use it**
- Work top to bottom inside the current release. Each task is one session and one PR on its own branch (`feat/<id>-<slug>`, e.g. `feat/0.1.7-d1-unicode`).
- Tick `[x]` in the same PR that completes the task.
- Every task's "done when" also implies the standing rules: tests (at least one malicious and one benign fixture per analyzer), `ruff`, `mypy --strict` and `pytest` green, and coverage ≥ 95% (CI floor).
- `[Dn]` names the detection module; `[—]` is infrastructure.

---

## v0.1 — CLI core (weeks 1–3)

Goal: `pipx install zirah && zirah scan server.json` finds D1–D4 issues offline and prints an explainable trust score.

### Foundation
- [x] **0.1.1 Monorepo skeleton** `[—]`: uv workspace (root + `core/`), ruff, mypy strict, pytest with a coverage floor, LICENSE, README stub, `.env.example`, `.gitignore`, `.gitattributes`, `.python-version`.
  *Done when:* `uv sync && uv run pytest` works on a clean clone.
- [x] **0.1.2 Data contract** `[—]`: `models.py` with Target, Manifest (canonical sha256), Evidence (2000-char cap), Finding (deterministic id, multi-OWASP), LlmInfo, ScanResult (`trust_score`, `finished_at`, `engines_used`).
  *Done when:* contract tests cover validation, normalization and JSON round-trips.
- [x] **0.1.3 CI workflow** `[—]`: GitHub Actions running ruff, ruff format, mypy and pytest on Ubuntu and Windows for every PR to `main`; Dependabot for uv and Actions.
  *Done when:* a PR shows a green required check and branch protection on `main` requires it.
- [x] **0.1.4 ScanSession model** `[—]`: `ScanSession { results[] }` in `models.py`, plus tests.
  *Done when:* it round-trips through JSON and rejects two results for the same target.
- [x] **0.1.5 Analyzer interface** `[—]`: `analyzers/base.py` with an `Analyzer` protocol (`module`, `engine`, `analyze(manifest, ctx) -> list[Finding]`) and an analyzer registry.
  *Done when:* a dummy analyzer is discovered, run and tested through the interface.
- [x] **0.1.6 Rule-pack loader** `[—]`: a YAML rule schema (id, module, severity, confidence, owasp, pattern type, patterns, title, remediation), a loader with validation, and a `rulepack_version` read from the pack.
  *Done when:* a malformed rule file fails with a clear error naming the file and rule, and the pack version is available to analyzers via `ScanContext.rules` (writing it into `ScanResult` is part of 0.1.14).
- [x] **0.1.7 Static JSON loader** `[—]`: `loaders/static.py` reads a manifest JSON file (MCP `tools/list`, `prompts/list` and `resources/list` shapes) into a `Manifest` + `Target`.
  *Done when:* fixtures from real servers load, and a bad file gives a readable error rather than a traceback.

### Detection (static)
- [x] **0.1.8 D1 invisible characters** `[D1]`: rules for zero-width, bidi override, tag characters, ANSI escapes and homoglyph-mixed names, applied to every string in descriptions, titles and `input_schema` (recursive walk).
  *Done when:* malicious fixtures are caught with JSON-pointer locations and benign non-English descriptions (Urdu, CJK, emoji) are not flagged.
- [x] **0.1.9 D1 hidden instructions & smuggling** `[D1]`: rules for model-directed instructions (`<IMPORTANT>`, "ignore previous", "do not tell the user", file/secret requests), HTML comments, and markdown/HTML smuggling.
  *Done when:* the postmark-style and "read ~/.ssh" fixtures are caught and a corpus of benign descriptions stays clean.
- [x] **0.1.10 D2 prompt injection** `[D2]`: injection patterns in prompts, prompt arguments, resources and server `instructions`.
  *Done when:* malicious and benign fixtures pass, and findings point at the exact prompt/resource.
- [x] **0.1.11 D3 single-manifest shadowing** `[D3]`: a description references or overrides other tools ("instead of", "before using X", "always call this first"), including tool names not in this manifest.
  *Done when:* shadowing fixtures are caught, while a tool legitimately mentioning its own name or siblings in plain usage is not.
- [x] **0.1.12 D4 secrets** `[D4]`: key/token patterns (AWS, GitHub, OpenAI, Anthropic, Slack, private keys, JWTs, high-entropy strings) in the manifest and target args. **Snippets are redacted** (prefix + `****`).
  *Done when:* no finding, report or test output contains a full secret, and the test fixtures use obviously fake keys.

### Scoring & pipeline
- [x] **0.1.13 Scoring** `[—]`: `scoring.py` holds the severity × confidence weights, grouping by evidence location (heaviest finding in full, the rest as a small bonus), diminishing returns across locations, hard caps (critical + high confidence → ≤ 39, high + high confidence → ≤ 74), the grade thresholds (A ≥ 90, B ≥ 75, C ≥ 60, D ≥ 40, F < 40) and a per-finding deduction breakdown.
  *Done when:* no findings gives 100/A, every deducted point is listed against a finding id, and boundary scores (90, 75, 60, 40), both caps and same-location grouping have tests.
- [x] **0.1.14 Scan pipeline** `[—]`: `scan.py` loads the target, hashes the manifest, runs the analyzers concurrently, dedupes by finding id, scores and builds the `ScanResult`. One analyzer crashing is reported and does not kill the scan.
  *Done when:* an end-to-end test from fixture file to `ScanResult` is deterministic (same input, same JSON apart from timestamps), and `rulepack_version` comes from the loaded pack.

### Output & CLI
- [x] **0.1.15 CLI `scan` + JSON + terminal report** `[—]`: typer `zirah scan <target> [--format terminal|json] [--output FILE] [--fail-on SEVERITY]` and a rich terminal report (grade, score, findings grouped by severity, remediation). Exit codes are documented.
  *Done when:* `uv run zirah scan examples/...json` prints the report and `--fail-on high` exits non-zero on the malicious fixture.
- [x] **0.1.16 SARIF report** `[—]`: SARIF 2.1.0 with rules, results, OWASP tags, severity mapping and stable fingerprints (finding id).
  *Done when:* the output validates against the official SARIF schema in tests.
- [x] **0.1.17 Markdown report** `[—]`: a markdown summary suitable for PR comments and READMEs.
  *Done when:* snapshot tests pass and invisible characters in snippets are rendered visibly escaped (`\u200b`).

### LLM judge (optional)
- [x] **0.1.18 LLM provider abstraction** `[—]`: `llm/` with the provider interface, `none` (default) and `ollama`; configured by `--llm` and `ZIRAH_LLM`; temperature 0; timeouts.
  *Done when:* everything passes with `--llm none` and no network, and Ollama is covered with a mocked HTTP test.
- [x] **0.1.19 OpenAI + Anthropic providers** `[—]`: keys come only from env vars; there are no provider imports outside `llm/`.
  *Done when:* mocked tests cover the success, rate-limit and malformed-response paths.
- [x] **0.1.20 LLM judge for D1–D3** `[D1][D2][D3]`: a prompt that classifies descriptions and returns structured output; findings get `engine=llm` and `LlmInfo` is recorded. Untrusted text is fenced and the judge is told it is data.
  *Done when:* the judge adds findings on semantic fixtures that the static rules miss, and an injection aimed at the judge itself is a test case.
  *Note:* re-check D2-EXFIL borderline cases semantically (e.g. "send a summary of the chat to <fixed address>", sensitive content named after the destination).

### Live loaders
- [x] **0.1.21 stdio loader** `[—]`: in-house MCP client (official `mcp` SDK only in conformance tests); requires `--allow-exec` and prints the red host-execution warning from SPEC §4.3; applies a timeout and kills the process tree.
  *Done when:* without the flag the loader refuses with the warning text, and with it a test server's manifest is extracted and the process is gone afterwards.
- [x] **0.1.22 Streamable HTTP + SSE loaders** `[—]`: fetch the manifest from remote servers with timeouts and no auth by default.
  *Done when:* both transports are tested against in-process test servers.

### Discovery & multi-target
- [x] **0.1.23 D14 discover** `[D14]`: parse MCP configs for Claude Desktop, Claude Code, Cursor, VS Code and Windsurf (Windows/macOS/Linux paths); list servers; flag servers missing from the user's approved list (`~/.config/zirah/approved.yaml`). No upload path exists.
  *Done when:* fixture configs for all 5 clients parse, secrets in configs are redacted in output, and no network access happens in `discover` (asserted in a test).
- [x] **0.1.24 `scan --all` → ScanSession** `[—]`: scan every discovered or listed server; stdio servers are skipped with a notice unless `--allow-exec` is given.
  *Done when:* a multi-target run produces one ScanSession JSON and one summary table.

### Release
- [x] **0.1.25 Demo server & examples** `[—]`: `examples/` with a deliberately malicious demo MCP server (static manifest + a stdio version) and a benign one.
  *Done when:* the README commands against the examples produce the documented findings.
- [ ] **0.1.26 Repo hygiene** `[—]`: SECURITY.md, CONTRIBUTING.md, CODE_OF_CONDUCT.md, issue/PR templates, CHANGELOG.
  *Done when:* the files are present and linked from the README.
- [ ] **0.1.27 README** `[—]`: 30-second GIF, `pipx install zirah`, quickstart, comparison table, OWASP mapping, architecture diagram, `--allow-exec` safety note.
  *Done when:* a new user can go from install to their first report using only the README.
- [ ] **0.1.28 Release 0.1.0** `[—]`: PyPI trusted publishing workflow on tag.
  *Done when:* `pipx install zirah==0.1.0` works on a clean machine.

---

## v0.2 — Deep static (weeks 4–7) · minimum portfolio-ready release

- [ ] **0.2.1 npm + PyPI loaders** `[—]`: download the package tarball or wheel/sdist for `name@version`, extract safely (reject path traversal, symlinks, size bombs), never run install scripts, record metadata.
  *Done when:* tests cover the malicious-archive cases and the extracted source feeds a `ScanContext`.
- [ ] **0.2.2 Git repo loader** `[—]`: shallow clone at a commit/tag with hooks disabled; size and time limits.
  *Done when:* it clones a fixture repo at a pinned commit and no repo hook runs (asserted).
- [ ] **0.2.3 Source-aware analyzer context** `[—]`: extend `ScanContext` with an optional source tree and package metadata; analyzers declare what they need.
  *Done when:* manifest-only analyzers are unaffected and source analyzers are skipped cleanly when there is no source.
- [ ] **0.2.4 D5 dangerous sinks** `[D5]`: Semgrep rules (YAML under `rules/`) for shell/exec, eval, path traversal and SSRF flows from tool arguments, in JS/TS and Python.
  *Done when:* malicious and benign fixtures pass in both languages, and a missing Semgrep install gives a clear skip notice.
- [ ] **0.2.5 D6 static capability profile** `[D6]`: infer fs/network/exec/credential capabilities from the manifest and source, and report the blast radius.
  *Done when:* the capability profile appears in the result and reports, and fixtures cover each capability.
- [ ] **0.2.6 D7 dependency CVEs** `[D7]`: OSV lookup for lockfile/manifest deps; online opt-in (`--online`) with a local cache, and offline runs skip it with a notice.
  *Done when:* a fixture with a known-vulnerable dep is flagged from a recorded OSV response.
- [ ] **0.2.7 D7 package risk signals** `[D7]`: typosquat distance to popular MCP packages, install scripts, maintainer change between versions, provenance/attestation presence.
  *Done when:* each signal has malicious and benign fixtures.
- [ ] **0.2.8 `--docker` runner** `[—]`: run stdio servers in a container with no host mounts, a read-only fs and resource limits, for manifest extraction only.
  *Done when:* the demo stdio server scans via `--docker` and a test proves the host filesystem is not visible.
- [ ] **0.2.9 Bundled similarity** `[D1][D2]`: a known-bad description corpus shipped with the package, lexical similarity via rapidfuzz/MinHash, and an optional `zirah[embed]` extra for local embeddings.
  *Done when:* near-duplicates of corpus entries are flagged with the matched entry as evidence and the base install has no embedding dependency.
- [ ] **0.2.10 MCP server mode (local)** `[—]`: `zirah mcp` exposing `check_tool_trust`, which answers from a local scan.
  *Done when:* an MCP client test calls the tool and gets a trust score and findings.
- [ ] **0.2.11 GitHub Action** `[—]`: `action/` runs `zirah scan` in a repo and uploads SARIF to code scanning.
  *Done when:* a demo repo shows Zirah alerts in its Security tab.
  *Note:* compute SARIF line/column for static JSON targets from the source file (results only carry JSON Pointers today).
- [ ] **0.2.12 Release 0.2.0** `[—]`: CodeQL workflow, Docker image to GHCR, README update, CHANGELOG, "Current focus" update.
  *Done when:* 0.2.0 is on PyPI and GHCR and the Action is tagged `v0`.

---

## v0.3 — Registry (weeks 8–11)

- [ ] **0.3.1 Attestation contract** `[—]`: add `key_id`, `attestation_level: self | registry`, and the LLM prompt hash and temperature to the contract, with tests (deliberate contract change).
  *Done when:* old results fail validation with a clear schema-version error and `SCHEMA_VERSION` is bumped.
- [ ] **0.3.2 `attest.py`** `[—]`: canonical JSON → sha256 → Ed25519 sign/verify; user key generation; self-attested signing from the CLI.
  *Done when:* sign/verify round-trips and tampering with any byte fails verification.
- [ ] **0.3.3 `zirah verify`** `[—]`: the two levels from SPEC §4.4 (static re-run must match exactly; LLM/dynamic evidence present and signed), with key and revocation-list checks.
  *Done when:* tests cover a valid result, a tampered result, a revoked key and a changed rule pack.
- [ ] **0.3.4 API skeleton** `[—]`: FastAPI app, slowapi rate limits on every public route, settings from env, docker-compose (Postgres 16 + pgvector, Redis), health route.
  *Done when:* `docker compose up` serves `/health` and a rate-limit test returns 429.
- [ ] **0.3.5 DB schema** `[—]`: SQLAlchemy 2 models and Alembic migration for servers, versions, scans, attestations and log entries.
  *Done when:* migrations run up and down cleanly in CI against Postgres.
- [ ] **0.3.6 Hash-chained log** `[—]`: an append-only log where each entry holds the previous entry's hash; a verification routine; no UPDATE/DELETE path.
  *Done when:* a test detects a modified or removed entry.
- [ ] **0.3.7 Registry keys endpoint** `[—]`: `/.well-known/zirah-keys.json` with public keys, key ids and a revocation list; key loaded from a secret, never from code.
  *Done when:* `zirah verify` fetches and uses it, and key rotation is documented.
- [ ] **0.3.8 Submissions** `[—]`: GitHub OAuth login; accepts only public identifiers (`npm:pkg@ver`, `pypi:pkg@ver`, `github:owner/repo@commit`); per-user and global quotas; dedupe by identifier@version.
  *Done when:* arbitrary URLs and private repos are rejected, and resubmitting returns the existing scan.
- [ ] **0.3.9 arq worker** `[—]`: the worker scans queued submissions with the core pipeline and signs results as `registry`; runs on its own container.
  *Done when:* submission → queued → scanned → attested → logged works end to end in compose.
- [ ] **0.3.10 pgvector similarity** `[D1][D2]`: embeddings of descriptions in Postgres; similarity to known-bad entries at scan time.
  *Done when:* registry scans cite the nearest known-bad match as evidence.
- [ ] **0.3.11 D10 manifest drift** `[D10]`: diff each new version's manifest against the previous one (tool added/removed, description or schema changed) and raise findings on risky changes.
  *Done when:* a postmark-style fixture sequence flags the exact version that turned malicious.
- [ ] **0.3.12 Registry lookup in MCP mode** `[—]`: `check_tool_trust` prefers a registry attestation and falls back to a local scan; works offline.
  *Done when:* tests cover the registry-hit, registry-miss and offline cases.
- [ ] **0.3.13 Disputes** `[—]`: `DISPUTES.md` plus endpoints for maintainers to claim a listing (GitHub ownership proof), respond to findings and request a re-scan.
  *Done when:* a claimed listing shows the maintainer response next to the findings.
- [ ] **0.3.14 Basic web registry** `[—]`: Next.js (App Router, TS, IBM Plex, navy/white): search, and a server page with grade, trust score, findings and version list. "Findings" and "trust score" wording only.
  *Done when:* pages render from the API in compose, pass Lighthouse accessibility ≥ 90, and the word "malicious" is absent from the UI (tested).
- [ ] **0.3.15 Release 0.3.0** `[—]`.
  *Done when:* the registry is deployed with a separate worker host and the CHANGELOG and "Current focus" are updated.

---

## v0.4 — Sandbox (weeks 12–14)

- [ ] **0.4.1 Runner image** `[—]`: `sandbox/Dockerfile.runner`, node + python, non-root, no capabilities, read-only root, CPU/memory/time limits, `--network none`.
  *Done when:* a test proves no network, no host mounts and a non-root user.
- [ ] **0.4.2 Canaries** `[D8]`: fake HOME, `.env`, `~/.ssh`, AWS creds with unique per-scan tokens.
  *Done when:* each canary token is unique per scan and traceable back to its location.
- [ ] **0.4.3 Egress capture** `[D8]`: mitmproxy sidecar as the only network path; an addon logging all requests.
  *Done when:* traffic from the runner appears in the log and direct egress fails.
- [ ] **0.4.4 Schema fuzzing** `[D8]`: `fuzz.py` generating args from each tool's JSON schema (hypothesis-jsonschema) and calling every tool with limits.
  *Done when:* every tool of the demo server is called with valid args, with bounded run time.
- [ ] **0.4.5 D8 findings** `[D8]`: canary leaks (in egress, outputs or files), unexpected egress, fs writes and process spawns become findings with `engine=dynamic` and stored evidence.
  *Done when:* the malicious demo server triggers each finding type and the benign one triggers none.
- [ ] **0.4.6 D9 response poisoning** `[D9]`: scan tool outputs with the D1/D2 rules and the LLM judge.
  *Done when:* a server returning injection in its output is flagged.
- [ ] **0.4.7 D6 dynamic half** `[D6]`: observed capabilities merged into the capability profile, and differences between declared and observed behaviour flagged.
  *Done when:* an under-declared capability is flagged in a fixture.
- [ ] **0.4.8 `--detonate` + registry jobs** `[—]`: CLI flag for local use; on the registry, detonation runs only as queued worker jobs on the separate host.
  *Done when:* there is no API route that triggers detonation directly (tested).
- [ ] **0.4.9 Release 0.4.0** `[—]`.
  *Done when:* the sandbox security notes are documented and the CHANGELOG and "Current focus" are updated.

---

## v0.5 — Graph & proof (weeks 15–18)

- [ ] **0.5.1 Graph stage** `[—]`: `graph.py` builds a data-flow graph from a ScanSession (nodes = tools, edges = possible flows using capability tags); `zirah graph` CLI.
  *Done when:* the graph is exported as JSON and a fixture session yields the expected nodes and edges.
- [ ] **0.5.2 D3 cross-server shadowing** `[D3]`: tool name collisions and descriptions referencing another server's tools.
  *Done when:* a two-server fixture is flagged and single-server scans are unchanged.
- [ ] **0.5.3 D11 lethal trifecta** `[D11]`: paths combining private data + untrusted input + an exfil channel.
  *Done when:* fixture configs yield the expected paths as findings with the path as evidence.
- [ ] **0.5.4 D12 context over-sharing** `[D12]`: sensitive-data share of the context and memory-write tools.
  *Done when:* the metric appears in reports with fixtures at each end.
- [ ] **0.5.5 D13 remote auth checks** `[D13]`: no auth, OAuth misconfiguration, metadata endpoint exposure; opt-in live probe.
  *Done when:* each check is tested against local test servers and it never probes without an explicit flag.
- [ ] **0.5.6 Attack-graph UI** `[D11]`: React Flow view of the graph and the version timeline with drift highlights on the server page.
  *Done when:* the views render fixture data and trifecta paths are highlighted.
- [ ] **0.5.7 Bench corpus & harness** `[—]`: `bench/` with a labelled corpus, adapters for MCPSecBench and MCP-SafetyBench, and a precision/recall report per module.
  *Done when:* `uv run zirah bench` prints per-module precision/recall reproducibly.
- [ ] **0.5.8 Metrics badge** `[—]`: CI runs bench and publishes the badge in the README.
  *Done when:* the badge updates on `main`.
- [ ] **0.5.9 Release 0.5.0** `[—]`.

---

## v0.6 — Beyond MCP & launch (weeks 19–20)

- [ ] **0.6.1 Agent Skills** `[—]`: loader for SKILL.md bundles; D1/D2/D4/D5 applied to skills.
  *Done when:* malicious and benign skill fixtures pass.
- [ ] **0.6.2 A2A Agent Cards** `[—]`: loader for agent cards; applicable analyzers.
  *Done when:* malicious and benign card fixtures pass.
- [ ] **0.6.3 Sigstore signing** `[—]`: Sigstore/in-toto attestations alongside Ed25519, with `zirah verify` support.
  *Done when:* a registry result verifies through Sigstore.
- [ ] **0.6.4 Docs site** `[—]`: mkdocs site from `docs/`, excluding `PLAN.md`.
  *Done when:* the site is published and `PLAN.md` is not in the build output.
- [ ] **0.6.5 Launch** `[—]`: launch post, demo video, and a submission to awesome-lists and the MCP registry.
  *Done when:* 1.0 readiness is reviewed against SPEC §7.
