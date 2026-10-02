# Security policy

Zirah is a security tool, so a flaw in it can put the people who rely on it at risk. Thank
you for reporting responsibly.

## Reporting a vulnerability

**Please do not open a public issue, discussion or pull request for a vulnerability.**

Report it privately through GitHub's private vulnerability reporting:

1. Go to the [Security tab](https://github.com/MuhammadMohsinIbrahim/zirah-mcp/security) of
   this repository.
2. Click **Report a vulnerability**.
3. Describe the problem, the affected version (`zirah --version`) and the steps or input
   that reproduce it. A minimal manifest or command line is ideal. Use harmless test data:
   no real secrets and no live attack infrastructure.

You can expect an acknowledgement within 7 days and a first assessment within 14 days. We
will keep you informed while a fix is prepared, agree on a disclosure date with you, and
credit you in the advisory and the CHANGELOG unless you prefer to stay anonymous.

## What counts as a vulnerability

Report privately anything that harms a person *running* Zirah, for example:

- code from a scanned target running without `--allow-exec` (static manifests, URLs,
  `discover` and `scan --all` must never execute anything)
- `--allow-exec` limits that can be escaped: a server process that survives the scan, or
  time and size limits that can be bypassed
- secrets from a manifest, a target's arguments or a client config appearing unredacted in
  any report, log or error message
- report output that can inject terminal escape sequences, markup or links into the user's
  terminal, a markdown renderer or GitHub code scanning
- network access during `discover` or with `--llm none`, or data sent anywhere the user
  did not configure
- crashes or hangs that a hostile manifest or server can trigger on purpose

## What is not a vulnerability

A malicious text that Zirah does **not** detect (a false negative) is a detection gap, not
a vulnerability in Zirah. Please open a
[new rule request](https://github.com/MuhammadMohsinIbrahim/zirah-mcp/issues/new?template=new_rule.yml)
for it, with harmless example text. If the gap is being exploited in the wild against a
real MCP server and you would rather not describe it publicly, report it privately as above.

Wrong findings on benign servers are
[false positives](https://github.com/MuhammadMohsinIbrahim/zirah-mcp/issues/new?template=false_positive.yml).

## Supported versions

Zirah is pre-1.0. Security fixes go into the latest release only.

| Version | Supported |
|---|---|
| latest 0.x release | yes |
| older releases | no |
