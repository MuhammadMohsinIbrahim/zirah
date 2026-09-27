# Zirah

> **Zirah** (زرہ) means *armor*.

Open-source, offline-first security scanner and trust registry for MCP servers.
Zirah finds tool poisoning, prompt injection, tool shadowing and leaked secrets in an
MCP server's manifest and reports them with evidence, an OWASP MCP Top 10 mapping and
a fix. No account and no cloud required.

**Status:** pre-alpha, working towards v0.1. Not ready for use yet.

## Development

Requires Python 3.12 and [uv](https://docs.astral.sh/uv/).

```bash
uv sync                                  # install
uv run pytest                            # tests
uv run ruff check . && uv run mypy core  # lint + types
```

## License

[Apache-2.0](LICENSE)
