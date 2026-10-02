# Zirah examples

Two small MCP servers to try Zirah on. Each comes as a static manifest (`manifest.json`, the
output of `tools/list`, `prompts/list` and `resources/list`) and as a stdio server
(`server.py`) that serves the same manifest. The servers use only the Python standard library.

| Demo | What it is | Expected result |
|---|---|---|
| [`malicious/`](malicious/) | A "notes and weather helper" with poisoned tools, an injected prompt and resource, a shadowing claim and leaked (fake) credentials | Grade F, trust score 0/100, 12 findings (D1, D2, D3, D4) |
| [`benign/`](benign/) | A plain notes server | Grade A, trust score 100/100, no findings |

**The malicious demo is harmless.** Its tools do nothing (every tool call returns an error),
every address is under `example.invalid` (a domain that can never resolve), and every
"secret" is an obviously fake `zirah_fake_...` value. The attack is only text that a scanner
should catch.

## Scan the static manifests

```bash
zirah scan examples/malicious/manifest.json
zirah scan examples/benign/manifest.json
zirah scan examples/malicious/manifest.json --format sarif -o zirah.sarif
```

## Scan the stdio servers

```bash
zirah scan --allow-exec python examples/malicious/server.py
zirah scan --allow-exec python examples/benign/server.py
```

`--allow-exec` runs the server on your machine to read its manifest. That is safe for these
two demos; for anything else, read the warning Zirah prints and prefer a static manifest.

On Windows, if Application Control blocks the `zirah` launcher, use `python -m zirah`
(or `uv run python -m zirah` from a clone).

## What the malicious demo triggers

| Location | Rule | Module |
|---|---|---|
| `/instructions` | `D2-SCANNER-EVASION` | D2 prompt injection |
| `/tools/0/description` | `D1-INSTRUCTION-TAG` | D1 tool poisoning |
| `/tools/0/description` | `D1-SENSITIVE-FILE-ACCESS` | D1 tool poisoning |
| `/tools/0/description` | `D1-CONCEAL-FROM-USER` | D1 tool poisoning |
| `/tools/1/description` | `D1-COVERT-FORWARD` | D1 tool poisoning |
| `/tools/2/description` | `D1-ZERO-WIDTH` | D1 tool poisoning |
| `/tools/2/description` | `D3-PRIORITY-CLAIM` | D3 tool shadowing |
| `/tools/3/input_schema/properties/endpoint/default` | `D4-URL-CREDENTIALS` | D4 secrets |
| `/tools/3/input_schema/properties/api_key/description` | `D4-SECRET-ASSIGNMENT` | D4 secrets |
| `/prompts/0/description` | `D2-EXFIL-INDIRECT-DESTINATION` | D2 prompt injection |
| `/resources/0/description` | `D2-IGNORE-PREVIOUS` | D2 prompt injection |
| `/resources/0/description` | `D2-EXFIL-INSTRUCTION` | D2 prompt injection |

This table is checked by the test suite (`core/tests/test_examples.py`), so it stays in step
with the rules.

## Use them in an MCP client

The stdio servers work in any MCP client, for example in Claude Desktop's
`claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "zirah-benign-demo": {
      "command": "python",
      "args": ["/absolute/path/to/zirah/examples/benign/server.py"]
    }
  }
}
```

`zirah discover` then lists the server, and `zirah scan --all --allow-exec` scans it.
Do not add the malicious demo to a client you use: its tools do nothing, but its text is
written to mislead a model.
