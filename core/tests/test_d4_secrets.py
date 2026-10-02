"""D4 secrets.

Key-shaped values are assembled at run time from visibly fake parts, so the repository never
holds a literal that secret scanners would flag. Test ids name the case, never the value,
so no secret reaches test output either.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest
from conftest import squashed

from zirah.analyzers.base import ScanContext, discover_analyzers
from zirah.analyzers.common import iter_text, redact
from zirah.analyzers.d4_secrets import Secrets, shannon_entropy
from zirah.loaders import load_static
from zirah.models import Finding, Manifest, Module, Prompt, Target, TargetKind, Tool
from zirah.rulepack import load_rulepack

PACK = load_rulepack()
TARGET = Target(kind=TargetKind.STATIC, location="m.json")
CTX = ScanContext(target=TARGET, rules=PACK)
FIXTURES = Path(__file__).parent / "fixtures" / "analyzers"


def b64url(data: dict[str, str]) -> str:
    return base64.urlsafe_b64encode(json.dumps(data).encode("utf-8")).decode("ascii").rstrip("=")


AWS_ID = "AKIA" + "ZIRAHFAKE7Q2M4X9"
AWS_SECRET = "zirahFAKEsecret/KEY+" + "0123456789abcdefghij"
GITHUB = "ghp_" + "ZirahFakeTokenNotReal7f3a9c1e2b4d608"
FINE_GRAINED = "github_" + "pat_" + "zirah_fake_11AAAAAAA0123456789"
OPENAI = "sk-" + "proj-zirah_fake_openai_4c8e1a93d07b52f6"
ANTHROPIC = "sk-" + "ant-api03-zirah_fake_anthropic_9b2f7c41e06d3a58"
SLACK = "xoxb-" + "zirah-fake-slack-token-7d41"
SLACK_HOOK_PATH = "TZIRAHFAKE/BZIRAHFAKE/" + "zirahFakeWebhook0123"
PEM_BODY = "zirahFakeKeyMaterialNotARealKey0123456789"
PRIVATE_KEY = (
    "-----BEGIN RSA " + "PRIVATE KEY-----\n" + PEM_BODY + "\n-----END RSA " + "PRIVATE KEY-----"
)
JWT = b64url({"alg": "none"}) + "." + b64url({"sub": "zirah_fake_user"}) + "."
GENERIC = "zirah_fake_4f9c2e71b8d3a605"
URL_CREDENTIAL = "zirah_fake_pw_71c3"

CASES = [
    ("aws-id", f"Uses {AWS_ID} for uploads.", "D4-AWS-ACCESS-KEY", "AKIA****", AWS_ID),
    (
        "aws-secret",
        f"aws_secret_access_key = {AWS_SECRET}",
        "D4-AWS-SECRET-KEY",
        "aws_secret_access_key = zira****",
        AWS_SECRET,
    ),
    ("github", f"token {GITHUB}", "D4-GITHUB-TOKEN", "ghp_****", GITHUB),
    ("github-fine-grained", f"use {FINE_GRAINED}", "D4-GITHUB-TOKEN", "gith****", FINE_GRAINED),
    ("openai", f"key={OPENAI}", "D4-OPENAI-KEY", "sk-p****", OPENAI),
    ("anthropic", f"key: {ANTHROPIC}", "D4-ANTHROPIC-KEY", "sk-a****", ANTHROPIC),
    ("slack", f"post with {SLACK}", "D4-SLACK-TOKEN", "xoxb****", SLACK),
    (
        "slack-webhook",
        "hook https://hooks.slack.com/services/" + SLACK_HOOK_PATH,
        "D4-SLACK-TOKEN",
        "https://hooks.slack.com/services/TZIR****",
        SLACK_HOOK_PATH,
    ),
    (
        "private-key",
        f"Key:\n{PRIVATE_KEY}",
        "D4-PRIVATE-KEY",
        "-----BEGIN RSA " + "PRIVATE KEY-----\nzira****",
        PEM_BODY,
    ),
    ("jwt", f"Authorization uses {JWT} today.", "D4-JWT", "eyJh****", JWT),
    (
        "url-password",
        f"postgres://app:{URL_CREDENTIAL}@db.example.invalid/app",
        "D4-URL-CREDENTIALS",
        "postgres://app:zira****@",
        URL_CREDENTIAL,
    ),
    (
        "url-query",
        f"https://api.example.invalid/v1?x=1&token={GENERIC}",
        "D4-URL-CREDENTIALS",
        "&token=zira****",
        GENERIC,
    ),
    (
        "assignment",
        f'{{"client_secret": "{GENERIC}"}}',
        "D4-SECRET-ASSIGNMENT",
        'client_secret": "zira****',
        GENERIC,
    ),
    (
        "bearer",
        f"Authorization: Bearer {GENERIC}",
        "D4-SECRET-ASSIGNMENT",
        "Bearer zira****",
        GENERIC,
    ),
]


def scan(manifest: Manifest, target: Target = TARGET) -> list[Finding]:
    return Secrets().run(manifest, ScanContext(target=target, rules=PACK))


def test_analyzer_is_discovered() -> None:
    assert Secrets in discover_analyzers()


@pytest.mark.parametrize(
    ("text", "rule", "snippet", "secret"),
    [case[1:] for case in CASES],
    ids=[case[0] for case in CASES],
)
def test_detects_and_redacts(text: str, rule: str, snippet: str, secret: str) -> None:
    findings = scan(Manifest(instructions=text))
    assert [f.rule_id for f in findings] == [rule]
    assert findings[0].evidence.snippet == snippet
    assert squashed(secret) not in squashed(findings[0].model_dump_json())


@pytest.mark.parametrize(
    "text",
    [
        pytest.param("Set EXAMPLE_API_KEY before starting. api_key: ${EXAMPLE_API_KEY}", id="env"),
        pytest.param("token: YOUR_TOKEN_GOES_HERE_1234", id="your-placeholder"),
        pytest.param("password: <password>, secret = changeme12345678", id="changeme"),
        pytest.param("placeholder sk-" + "x" * 28, id="low-entropy-openai"),
        pytest.param("AKIA" + "X" * 16, id="low-entropy-aws"),
        pytest.param("AWS docs key AKIAIOSFODNN7EXAMPLE", id="aws-docs-example"),
        pytest.param("Keys start with sk- or sk-proj-.", id="prefix-only"),
        pytest.param("The access token expires after 3600 seconds.", id="prose"),
        pytest.param("Send Authorization: Bearer <token>.", id="bearer-placeholder"),
        pytest.param("postgres://user:password@localhost/db", id="url-placeholder"),
        pytest.param("https://example.invalid/cb?token={access_token}", id="url-template"),
        pytest.param("Commit 4f9c2e71b8d3a6054f9c2e71b8d3a6054f9c2e71", id="commit-sha"),
        pytest.param("secret_name: prod/db", id="short-value"),
        pytest.param("tokens: 1234567890123456", id="digits-only"),
    ],
)
def test_placeholders_and_docs_are_clean(text: str) -> None:
    assert scan(Manifest(instructions=text)) == []


def test_target_args_and_location_are_scanned() -> None:
    target = Target(
        kind=TargetKind.STDIO,
        location="https://mcp.example.invalid/sse?token=" + GENERIC,
        args=("-y", "example-server", "--api-key", GENERIC),
    )
    findings = scan(Manifest(), target)
    assert [(f.rule_id, f.evidence.location, f.evidence.snippet) for f in findings] == [
        ("D4-URL-CREDENTIALS", "target:/location", "?token=zira****"),
        ("D4-SECRET-ASSIGNMENT", "target:/args", "api-key zira****"),
    ]
    assert all(GENERIC not in squashed(f.model_dump_json()) for f in findings)


def test_secrets_are_found_across_the_manifest() -> None:
    manifest = Manifest(
        server_name="srv",
        tools=(Tool(name="t", input_schema={"properties": {"k": {"default": GITHUB}}}),),
        prompts=(Prompt(name="p", description=f"Use {OPENAI}."),),
    )
    found = [(f.rule_id, f.evidence.location) for f in scan(manifest)]
    assert found == [
        ("D4-GITHUB-TOKEN", "/tools/0/input_schema/properties/k/default"),
        ("D4-OPENAI-KEY", "/prompts/0/description"),
    ]


def test_other_modules_redact_secrets_in_their_evidence() -> None:
    # A D1 finding whose context would show a token, including one cut by the context edge.
    near = "Zero\U0000200bwidth next to " + GITHUB
    far = "\U0000200b" + "a" * 50 + " " + ANTHROPIC + " tail"
    manifest = Manifest(tools=(Tool(name="t", description=near, title=far),))
    ctx = ScanContext(target=TARGET, rules=PACK)
    findings = [f for cls in discover_analyzers() for f in cls().run(manifest, ctx)]
    d1 = [f for f in findings if f.module is Module.D1]
    assert {f.evidence.location for f in d1} == {"/tools/0/description", "/tools/0/title"}
    for finding in findings:
        dumped = squashed(finding.model_dump_json())
        assert GITHUB not in dumped
        assert ANTHROPIC[:20] not in dumped


def test_no_finding_on_any_fixture_holds_a_whole_secret() -> None:
    secret_rules = PACK.for_module(Module.D4)
    ctx_rules = ScanContext(target=TARGET, rules=PACK)
    for path in sorted(FIXTURES.glob("*/*.json")):
        manifest = load_static(path).manifest
        secrets = {
            m.group(0)
            for field in iter_text(manifest)
            for rule in secret_rules
            for m in rule.finditer(field.text)
        }
        findings = [f for cls in discover_analyzers() for f in cls().run(manifest, ctx_rules)]
        for finding in findings:
            dumped = squashed(finding.model_dump_json())
            leaked = [s for s in secrets if len(s) >= 8 and squashed(s) in dumped]
            assert leaked == [], f"{path.name}: {finding.rule_id} leaks a secret"


def test_redact_keeps_at_most_a_quarter() -> None:
    assert redact("abcdefghijklmnopqrstuvwxyz") == "abcd****"
    assert redact("abcdefgh") == "ab****"
    assert redact("abc") == "****"
    assert redact("") == "****"


def test_shannon_entropy() -> None:
    assert shannon_entropy("") == 0.0
    assert shannon_entropy("aaaa") == 0.0
    assert shannon_entropy("abab") == 1.0
    assert shannon_entropy("abcd") == 2.0
