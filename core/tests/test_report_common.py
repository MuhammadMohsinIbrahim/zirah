from __future__ import annotations

import pytest

from zirah.models import (
    Confidence,
    Engine,
    Evidence,
    Finding,
    Manifest,
    Module,
    Owasp,
    Prompt,
    PromptArgument,
    Resource,
    Severity,
    Tool,
)
from zirah.report.common import (
    REMEDIATION_CHARS,
    cap_explanation,
    describe_location,
    display_snippet,
    escape_text,
    group_by_location,
    one_line,
    severity_counts,
    shorten,
)
from zirah.scoring import score

MANIFEST = Manifest(
    tools=(Tool(name="add", input_schema={"properties": {"note": {"type": "string"}}}),),
    prompts=(Prompt(name="review", arguments=(PromptArgument(name="diff"),)),),
    resources=(Resource(uri="file:///r", name="handbook"),),
)


@pytest.mark.parametrize(
    ("text", "shown"),
    [
        ("a\U0000200bb", "a\\u200bb"),
        ("x\U0000202ey", "x\\u202ey"),
        ("tag\U000e0041", "tag\\U000e0041"),
        ("line\nnext\ttab\r", "line\\nnext\\ttab\\r"),
        ("esc\x1b[31m", "esc\\u001b[31m"),
        ("nb\U000000a0sp", "nb\\u00a0sp"),
        ("vs\U0000fe0f", "vs\\ufe0f"),
        ("ls\U00002028", "ls\\u2028"),
        ("plain text, 1 + 1", "plain text, 1 + 1"),
        ("اردو 中文 日本語 👍 é", "اردو 中文 日本語 👍 é"),
    ],
)
def test_escape_text(text: str, shown: str) -> None:
    assert escape_text(text) == shown


def test_shorten() -> None:
    assert shorten("abc", 3) == "abc"
    assert shorten("abcdef", 4) == "abc…"


def test_display_snippet_escapes_before_shortening() -> None:
    finding = _finding(snippet="\U0000200b" * 100)
    assert display_snippet(finding, limit=20) == "\\u200b\\u200b\\u200b…"


@pytest.mark.parametrize(
    ("text", "line"),
    [
        ("Remove it.", "Remove it."),
        (
            "Remove the text. It tells the model to ignore rules. More.",
            "Remove the text. It tells the model to ignore rules.",
        ),
        (
            "A long first sentence that is already over forty chars. Second.",
            "A long first sentence that is already over forty chars.",
        ),
        ("Remove\n  the text. Why\nit matters.", "Remove the text. Why it matters."),
    ],
)
def test_one_line(text: str, line: str) -> None:
    assert one_line(text) == line


def test_one_line_is_capped() -> None:
    assert len(one_line("x" * 500)) == REMEDIATION_CHARS


@pytest.mark.parametrize(
    ("location", "label"),
    [
        ("/tools/0/description", 'tool "add" › description'),
        (
            "/tools/0/input_schema/properties/note/description",
            'tool "add" › input schema › note › description',
        ),
        ("/tools/0/name", 'tool "add" › name'),
        ("/prompts/0/arguments/0/description", 'prompt "review" › argument "diff" › description'),
        ("/prompts/0/description", 'prompt "review" › description'),
        ("/resources/0/uri", 'resource "handbook" › uri'),
        ("/instructions", "server instructions"),
        ("/server_name", "server name"),
        ("target:/args", "target arguments"),
        ("target:/location", "target location"),
        ("target:/other", "target:/other"),
        ("/tools/9/description", "/tools/9/description"),
        ("/tools/x/description", "/tools/x/description"),
        ("/prompts/0/arguments/5/description", "/prompts/0/arguments/5/description"),
        ("/unknown/0", "/unknown/0"),
        ("", ""),
    ],
)
def test_describe_location(location: str, label: str) -> None:
    assert describe_location(location, MANIFEST) == label


def test_describe_location_escapes_names() -> None:
    manifest = Manifest(tools=(Tool(name="a\U0000200bb/c"),))
    assert describe_location("/tools/0/name", manifest) == 'tool "a\\u200bb/c" › name'
    assert describe_location("/tools/0/input_schema/a~1b~0c", manifest).endswith("a/b~c")


def _finding(
    severity: Severity = Severity.LOW,
    location: str = "/tools/0/description",
    rule: str = "D1-TEST",
    snippet: str = "x",
    confidence: Confidence = Confidence.MEDIUM,
) -> Finding:
    return Finding(
        module=Module.D1,
        rule_id=rule,
        severity=severity,
        confidence=confidence,
        owasp=(Owasp.MCP03,),
        title="Test",
        evidence=Evidence(location=location, snippet=snippet),
        remediation="Fix it.",
        engine=Engine.STATIC,
    )


def test_group_by_location_orders_by_worst_severity_then_points() -> None:
    findings = [
        _finding(Severity.LOW, "/a", "D1-A"),
        _finding(Severity.HIGH, "/b", "D1-B"),
        _finding(Severity.CRITICAL, "/a", "D1-C"),
        _finding(Severity.HIGH, "/c", "D1-D", confidence=Confidence.HIGH),
    ]
    groups = group_by_location(findings, score(findings))
    assert [g.location for g in groups] == ["/a", "/c", "/b"]
    assert [f.rule_id for f in groups[0].findings] == ["D1-C", "D1-A"]
    assert groups[0].severity is Severity.CRITICAL
    assert groups[0].points == pytest.approx(
        sum(score(findings).points_for(f.id) for f in groups[0].findings)
    )


def test_severity_counts_worst_first_without_zeros() -> None:
    findings = [_finding(Severity.LOW, rule="D1-A"), _finding(Severity.HIGH, rule="D1-B")]
    assert severity_counts(findings) == [(Severity.HIGH, 1), (Severity.LOW, 1)]


def test_cap_explanation() -> None:
    assert cap_explanation(score([])) is None
    one = [_finding(Severity.CRITICAL, confidence=Confidence.HIGH)]
    assert cap_explanation(score(one)) == (
        "Capped at 39 (from 60): 1 critical finding with high confidence."
    )
    two = [
        _finding(Severity.HIGH, rule="D1-A", confidence=Confidence.HIGH),
        _finding(Severity.HIGH, rule="D1-B", confidence=Confidence.HIGH),
    ]
    assert cap_explanation(score(two)) == (
        "Capped at 74 (from 78): 2 high findings with high confidence."
    )
