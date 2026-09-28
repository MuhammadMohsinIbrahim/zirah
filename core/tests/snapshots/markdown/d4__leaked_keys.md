## Zirah scan: grade F, trust score 0/100

Severe findings. Do not use this server until they are fixed.

| | |
|---|---|
| Target | `d4/leaked_keys.json` |
| Server | ops-helper 0.4.2 |
| Findings | 9 at 8 locations: 5 critical, 4 high |
| Rule pack | 2026.09.7 |
| Engines | static |
| Zirah | 0.1.0.dev0 |

### Critical

#### prompt "summarize" › description

`/prompts/0/description`

- **CRITICAL** Anthropic API key (`D4-ANTHROPIC-KEY`, -40 pts)
  - Evidence: `sk-a****`
  - Fix: Revoke the key in the Anthropic Console and pass a new one through the environment.

#### resource "report" › description

`/resources/0/description`

- **CRITICAL** Slack token or webhook (`D4-SLACK-TOKEN`, -32 pts)
  - Evidence: `xoxb****`
  - Fix: Revoke the token or webhook in the Slack app settings and pass a new one through the environment.

#### tool "deploy" › description

`/tools/0/description`

- **CRITICAL** AWS access key ID (`D4-AWS-ACCESS-KEY`, -25.6 pts)
  - Evidence: `AKIA****`
  - Fix: Remove the key and rotate it in AWS IAM. Pass credentials through the environment or a credential provider, never in tool text or arguments.

#### tool "deploy" › input schema › token › default

`/tools/0/input_schema/properties/token/default`

- **CRITICAL** GitHub token (`D4-GITHUB-TOKEN`, -20.48 pts)
  - Evidence: `ghp_****`
  - Fix: Revoke the token in GitHub settings and pass a new one through the environment.

#### tool "ask\_model" › input schema › key › examples › 0

`/tools/1/input_schema/properties/key/examples/0`

- **CRITICAL** OpenAI API key (`D4-OPENAI-KEY`, -16.38 pts)
  - Evidence: `sk-p****`
  - Fix: Revoke the key in the OpenAI dashboard and pass a new one through the environment.

### High

#### server instructions

`/instructions`

- **HIGH** Credentials in a URL (`D4-URL-CREDENTIALS`, -6.55 pts)
  - Evidence: `postgres://app:zira****@`
  - Fix: Remove the credentials from the URL and rotate them.
- **HIGH** High-entropy value assigned to a secret-named key (`D4-SECRET-ASSIGNMENT`, -0.49 pts)
  - Evidence: `client_secret = zira****`
  - Fix: Remove the value and rotate it. Read secrets from the environment or a secret manager at run time.

#### resource "report" › uri

`/resources/0/uri`

- **HIGH** Credentials in a URL (`D4-URL-CREDENTIALS`, -5.24 pts)
  - Evidence: `?api_key=zira****`
  - Fix: Remove the credentials from the URL and rotate them.

#### tool "status" › description

`/tools/2/description`

- **HIGH** High-entropy value assigned to a secret-named key (`D4-SECRET-ASSIGNMENT`, -3.15 pts)
  - Evidence: `Bearer zira****`
  - Fix: Remove the value and rotate it. Read secrets from the environment or a secret manager at run time.

<details>
<summary>How the trust score was computed</summary>

Each finding's weight is its severity weight times its confidence multiplier. At one location the heaviest finding counts in full and each other one adds 10% of its weight (share). Locations are ranked heaviest first and each further one counts 0.8 times the one before (decay).

| Finding | Rule | Location | Weight | Share | Decay | Points |
|---|---|---|---:|---:|---:|---:|
| `086f97a99a3813fe` | `D4-ANTHROPIC-KEY` | `/prompts/0/description` | 40 | 1 | 1 | 40 |
| `04c1d6808b653b35` | `D4-SLACK-TOKEN` | `/resources/0/description` | 40 | 1 | 0.8 | 32 |
| `a0774afe8d466dcd` | `D4-AWS-ACCESS-KEY` | `/tools/0/description` | 40 | 1 | 0.64 | 25.6 |
| `7ab06d3445c9f666` | `D4-GITHUB-TOKEN` | `/tools/0/input_schema/properties/token/default` | 40 | 1 | 0.512 | 20.48 |
| `97e2ad0332e82367` | `D4-OPENAI-KEY` | `/tools/1/input_schema/properties/key/examples/0` | 40 | 1 | 0.41 | 16.38 |
| `a9591e644ff47d46` | `D4-URL-CREDENTIALS` | `/instructions` | 20 | 1 | 0.328 | 6.55 |
| `7c269f7fb6246f17` | `D4-SECRET-ASSIGNMENT` | `/instructions` | 15 | 0.1 | 0.328 | 0.49 |
| `cfcb51159a513c47` | `D4-URL-CREDENTIALS` | `/resources/0/uri` | 20 | 1 | 0.262 | 5.24 |
| `f9dd28746ebd1f71` | `D4-SECRET-ASSIGNMENT` | `/tools/2/description` | 15 | 1 | 0.21 | 3.15 |
| | | | | | **Total** | **149.89** |

Trust score: 100 - 150 points (deductions rounded up) = 0 (floored at 0).

</details>
