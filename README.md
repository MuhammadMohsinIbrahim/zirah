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
zirah scan server.json --fail-on high           # CI: fail only on high or critical findings
```

`server.json` is an MCP manifest: the output of `tools/list`, `prompts/list` and
`resources/list` (optionally with `serverInfo` and `instructions`), a JSON-RPC response, or a
list of those.

| Exit code | Meaning |
|---|---|
| 0 | No findings at or above `--fail-on` (default `info`: any finding; `none` never fails) |
| 1 | At least one finding at or above `--fail-on` |
| 2 | Usage error, target not loadable, report not writable, or an analyzer failed |

## Development

Requires Python 3.12 and [uv](https://docs.astral.sh/uv/).

```bash
uv sync                                  # install
uv run pytest                            # tests
uv run ruff check . && uv run mypy core  # lint + types
```

## License

[Apache-2.0](LICENSE)
