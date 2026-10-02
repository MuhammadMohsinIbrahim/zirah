# Zirah

**Find tool poisoning, prompt injection, tool shadowing and leaked secrets in MCP servers before your agent trusts them. Offline, no account, every finding explained.**

Zirah reads an MCP server's manifest (its tools, prompts, resources and instructions), runs
detection rules over every string the model will see, and gives the server an explainable
trust score from 0 to 100. Each finding carries the exact location (a JSON pointer), the
evidence, an [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/) mapping and a fix.
It works fully offline; an LLM judge is optional.

![Zirah scanning a benign and a malicious demo MCP server](https://raw.githubusercontent.com/MuhammadMohsinIbrahim/zirah/main/docs/demo.gif)

## Install

```bash
pipx install zirah
```

Zirah needs Python 3.12 or newer. `uv tool install zirah` and `pip install zirah` work too.
On Windows, if Application Control blocks the `zirah` launcher, run `python -m zirah`.

## Quickstart

```bash
zirah scan server.json                          # a manifest: tools/list, prompts/list, resources/list
zirah scan https://mcp.example.com/mcp          # a remote server (Streamable HTTP or SSE)
zirah discover                                  # MCP servers configured on this machine (offline)
zirah scan --all                                # every configured server, one session
zirah scan server.json --format sarif -o zirah.sarif   # GitHub code scanning
```

Exit code 1 means a finding at or above `--fail-on` (default `high`), so Zirah drops into CI
as is. Reports come as terminal output, JSON, SARIF 2.1.0 or markdown.

Try it on the harmless
[demo servers](https://github.com/MuhammadMohsinIbrahim/zirah/tree/main/examples): the
malicious one gets grade F with 12 findings, the benign one 100/100.

## What it detects

| Module | Finds | OWASP MCP Top 10 |
|---|---|---|
| D1 Tool poisoning | Invisible Unicode, ANSI escapes, homoglyphs, hidden instructions, credential-file requests, covert forwarding, HTML/markdown smuggling, text aimed at the scanner | MCP03 |
| D2 Prompt injection | Instruction overrides, forged delimiters, jailbreaks, system-prompt extraction, exfiltration, markdown image beacons, scanner evasion in prompts, resources and instructions | MCP06 |
| D3 Tool shadowing | Tools claiming priority over, overriding or ordering around other tools | MCP03 |
| D4 Secrets | API keys, tokens, private keys, JWTs, credentials in URLs (always redacted) | MCP01 |
| D14 Shadow MCP | Configured servers in Claude Desktop, Claude Code, Cursor, VS Code and Windsurf, checked against an approved list | MCP09 |

Rules are YAML, so they can be read, reviewed and extended. The optional LLM judge
(`--llm ollama|openai|anthropic`) adds semantic checks and never removes a static finding.

## Running stdio servers

`zirah scan --allow-exec <command>` starts a local server to read its manifest. **This runs
the server's code on your machine with your user permissions, with no isolation.** Zirah
prints a warning, never calls a tool, applies time and size limits and kills the whole
process tree afterwards. Prefer a static manifest when you can.

## Links

- [Documentation and comparison with other scanners](https://github.com/MuhammadMohsinIbrahim/zirah#readme)
- [Changelog](https://github.com/MuhammadMohsinIbrahim/zirah/blob/main/CHANGELOG.md)
- [Security policy](https://github.com/MuhammadMohsinIbrahim/zirah/blob/main/SECURITY.md)
- [Contributing](https://github.com/MuhammadMohsinIbrahim/zirah/blob/main/CONTRIBUTING.md)

Written and maintained by
[Muhammad Mohsin Ibrahim](https://github.com/MuhammadMohsinIbrahim). Licensed under
Apache-2.0.
