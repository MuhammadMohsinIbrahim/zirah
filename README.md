# Zirah

> **Zirah** (زرہ) means *armor*.

Open-source, offline-first security scanner and trust registry for MCP servers.
Zirah finds tool poisoning, prompt injection, tool shadowing and leaked secrets in an
MCP server's manifest and reports them with evidence, an OWASP MCP Top 10 mapping and
a fix. No account and no cloud required.

**Status:** pre-alpha, working towards v0.1. Not ready for use yet.

## Usage

```bash
zirah scan server.json                          # terminal report: grade, trust score, findings
zirah scan server.json --format json -o out.json
zirah scan server.json --format sarif -o zirah.sarif   # GitHub code scanning
zirah scan server.json --format markdown -o report.md # PR comments, READMEs
zirah scan server.json --fail-on medium         # CI: also fail on medium findings (default: high)
zirah scan server.json --llm ollama:llama3.1:8b  # optional LLM judge (local); also openai, anthropic
zirah scan https://mcp.example.com/mcp          # remote server (Streamable HTTP or SSE)
zirah scan --allow-exec npx -y some-mcp-server  # run a stdio server (no isolation!)
```

`--allow-exec` runs the server's code on your machine with your user permissions to read its
manifest; Zirah prints a warning, applies time and size limits and kills the whole process
tree afterwards. Prefer a static manifest when you can.

`server.json` is an MCP manifest: the output of `tools/list`, `prompts/list` and
`resources/list` (optionally with `serverInfo` and `instructions`), a JSON-RPC response, or a
list of those.

| Exit code | Meaning |
|---|---|
| 0 | No findings at or above `--fail-on` (default `high`; `info` fails on any finding, `none` never fails) |
| 1 | At least one finding at or above `--fail-on` |
| 2 | Usage error, target not loadable, report not writable, or an analyzer failed |

## Troubleshooting

**`zirah` is blocked on Windows** ("An Application Control policy has blocked this file",
os error 4551). Windows Application Control or Smart App Control can block the small
`zirah.exe` launcher that pip, pipx or uv create. Run the same CLI through Python instead:

```bash
python -m zirah scan server.json
uv run python -m zirah scan server.json   # from a clone of this repository
```

## Development

Requires Python 3.12 and [uv](https://docs.astral.sh/uv/).

```bash
uv sync                                  # install
uv run pytest                            # tests
uv run ruff check . && uv run mypy core  # lint + types
```

## License

[Apache-2.0](LICENSE)
