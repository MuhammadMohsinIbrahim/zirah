"""Markdown report tests.

Snapshots live in ``snapshots/markdown``. After an intended change to the report (or to the
rules or versions it prints), regenerate them with ``ZIRAH_UPDATE_SNAPSHOTS=1 uv run pytest``
and review the diff.
"""

from __future__ import annotations

import json
import os
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

import pytest
from typer.testing import CliRunner

from zirah.analyzers.base import Analyzer, ScanContext
from zirah.analyzers.d1_tool_poisoning import ToolPoisoning
from zirah.cli import app
from zirah.loaders import Loaded, load_static
from zirah.models import Engine, Finding, Manifest, Module, Target, TargetKind, Tool
from zirah.report import markdown
from zirah.report.markdown import md_code, md_text
from zirah.scan import Scan, scan_loaded

FIXTURES = Path(__file__).parent / "fixtures" / "analyzers"
SNAPSHOTS = Path(__file__).parent / "snapshots" / "markdown"
UPDATE = os.environ.get("ZIRAH_UPDATE_SNAPSHOTS") == "1"
START = datetime(2026, 9, 28, 12, 0, tzinfo=UTC)
CASES = [
    "d1/hidden_instructions",
    "d1/invisible_unicode",
    "d2/prompt_injection",
    "d4/leaked_keys",
    "benign/everyday_tools",
]


def fixture_scan(case: str, analyzers: Sequence[type[Analyzer]] | None = None) -> Scan:
    loaded = load_static(FIXTURES / f"{case}.json")
    # A fixed, OS-independent location keeps snapshots identical on Windows and Linux.
    target = Target(kind=TargetKind.STATIC, location=f"{case}.json", name=loaded.target.name)
    return scan_loaded(
        Loaded(target=target, manifest=loaded.manifest), analyzers=analyzers, clock=lambda: START
    )


@pytest.mark.parametrize("case", CASES)
def test_snapshot(case: str) -> None:
    text = markdown.render(fixture_scan(case))
    path = SNAPSHOTS / f"{case.replace('/', '__')}.md"
    if UPDATE:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8", newline="\n")
    assert path.exists(), f"missing snapshot {path.name}; run with ZIRAH_UPDATE_SNAPSHOTS=1"
    assert text == path.read_text(encoding="utf-8")


def test_invisible_characters_are_rendered_visibly_escaped() -> None:
    text = markdown.render(fixture_scan("d1/invisible_unicode"))
    assert "\\u200b" in text
    assert "\\u202e" in text
    assert "\U0000200b" not in text
    assert "\U0000202e" not in text


def test_secrets_stay_redacted() -> None:
    text = markdown.render(fixture_scan("d4/leaked_keys"))
    assert "ghp_ZirahFakeTokenNotReal7f3a9c1e2b4d608" not in text
    assert "zirah_fake_4f9c2e71b8d3a605" not in text
    assert "****" in text


def test_grade_and_score_come_first() -> None:
    text = markdown.render(fixture_scan("d1/hidden_instructions"))
    assert text.startswith("## Zirah scan: grade F, trust score 13/100\n")


def test_every_finding_is_in_the_breakdown() -> None:
    outcome = fixture_scan("d4/leaked_keys")
    text = markdown.render(outcome)
    breakdown = text[text.index("<details>") :]
    for finding in outcome.result.findings:
        assert f"`{finding.id}`" in breakdown
    assert f"**{outcome.score.total_points:g}**" in breakdown


def test_no_breakdown_without_findings() -> None:
    text = markdown.render(fixture_scan("benign/everyday_tools"))
    assert "<details>" not in text
    assert "| Findings | none |" in text


@pytest.mark.parametrize(
    ("text", "escaped"),
    [
        ("[click](https://example.invalid)", "\\[click\\]\\(https\\://example.invalid\\)"),
        ("<img src=x onerror=y>", "\\<img src=x onerror=y\\>"),
        ("ping @someone about #12", "ping \\@someone about \\#12"),
        ("**bold** _it_ `code`", "\\*\\*bold\\*\\* \\_it\\_ \\`code\\`"),
        ("| ~x~ &amp;", "\\| \\~x\\~ \\&amp;"),
        ("a\\b", "a\\\\b"),
        ("zero\U0000200bwidth", "zero\\\\u200bwidth"),
        ("plain words, 1.5", "plain words, 1.5"),
    ],
)
def test_md_text(text: str, escaped: str) -> None:
    assert md_text(text) == escaped


@pytest.mark.parametrize(
    ("text", "span"),
    [
        ("abc", "`abc`"),
        ("a`b", "``a`b``"),
        ("`start", "`` `start ``"),
        ("a``b`", "``` a``b` ```"),
        (" ", "` `"),
        ("x\U0000200by", "`x\\u200by`"),
    ],
)
def test_md_code(text: str, span: str) -> None:
    assert md_code(text) == span


def test_md_code_in_table_escapes_pipes() -> None:
    assert md_code("/tools/0/a|b", in_table=True) == "`/tools/0/a\\|b`"


def test_manifest_text_cannot_inject_markdown(tmp_path: Path) -> None:
    path = tmp_path / "m.json"
    path.write_text(
        json.dumps(
            {
                "serverInfo": {"name": "[x](https://example.invalid) @org"},
                "tools": [{"name": "t`x", "description": "<IMPORTANT>``` <img src=x>"}],
            }
        ),
        encoding="utf-8",
    )
    loaded = load_static(path)
    text = markdown.render(scan_loaded(loaded, clock=lambda: START))
    assert "| Server | \\[x\\]\\(https\\://example.invalid\\) \\@org |" in text
    assert '#### tool "t\\`x" › description' in text
    assert "Evidence: ````<IMPORTANT>``` <img src=x>````" in text


class Crashing(Analyzer):
    name = "test-md-crashing"
    module = Module.D2
    engine = Engine.STATIC

    def analyze(self, manifest: Manifest, ctx: ScanContext) -> Sequence[Finding]:
        raise RuntimeError("boom")


def test_failed_analyzer_warning() -> None:
    text = markdown.render(fixture_scan("d1/hidden_instructions", [Crashing, ToolPoisoning]))
    assert (
        "> **Warning:** analyzer `test-md-crashing` failed (RuntimeError\\: boom); "
        "the scan is incomplete." in text
    )


def test_cli_markdown_format() -> None:
    target = str(FIXTURES / "d1" / "hidden_instructions.json")
    result = CliRunner().invoke(app, ["scan", target, "--format", "markdown"])
    assert result.exit_code == 1
    assert result.stdout.startswith("## Zirah scan: grade F, trust score 13/100")


def test_score_cap_is_explained() -> None:
    manifest = Manifest(tools=(Tool(name="deploy", description="Uses AKIAZIRAHFAKE7Q2M4X9."),))
    loaded = Loaded(target=Target(kind=TargetKind.STATIC, location="m.json"), manifest=manifest)
    text = markdown.render(scan_loaded(loaded, clock=lambda: START))
    cap = "Capped at 39 (from 60): 1 critical finding with high confidence."
    assert f"> **Score cap:** {cap}" in text
    assert "rounded up = 60, capped at 39 by `" in text
