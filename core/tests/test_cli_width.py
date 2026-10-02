"""The CLI reports say the same things at any console width.

``conftest.py`` pins ``COLUMNS`` so the other CLI tests wrap the same everywhere. These tests
override the pin with narrow, default and wide widths, so a check that only holds at one
width (a phrase split by a line break, a secret folded across lines) fails here first.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from conftest import flat, squashed
from typer.testing import CliRunner

from zirah.cli import EXIT_CLEAN, EXIT_FINDINGS, app

FIXTURES = Path(__file__).parent / "fixtures" / "analyzers"
BENIGN = str(FIXTURES / "benign" / "everyday_tools.json")
D1 = str(FIXTURES / "d1" / "hidden_instructions.json")
D4 = str(FIXTURES / "d4" / "leaked_keys.json")
D4_SECRETS = [
    "AKIAZIRAHFAKE7Q2M4X9",
    "ghp_ZirahFakeTokenNotReal7f3a9c1e2b4d608",
    "sk-proj-zirah_fake_openai_4c8e1a93d07b52f6",
    "sk-ant-api03-zirah_fake_anthropic_9b2f7c41e06d3a58",
    "zirah_fake_4f9c2e71b8d3a605",
    "zirah_fake_bearer_5e8a1c7d2f9b0346",
    "zirah_fake_pw_71c3",
]

WIDTHS = [40, 80, 200]


@pytest.fixture(params=WIDTHS, ids=[f"columns-{w}" for w in WIDTHS])
def width(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> int:
    columns: int = request.param
    monkeypatch.setenv("COLUMNS", str(columns))
    return columns


def run(*args: str) -> tuple[int, str]:
    result = CliRunner().invoke(app, list(args))
    return result.exit_code, result.stdout


def assert_fits(out: str, width: int) -> None:
    widest = max(len(line) for line in out.splitlines())
    assert widest <= width, f"a line is {widest} characters wide at COLUMNS={width}"


def test_benign_scan(width: int) -> None:
    code, out = run("scan", BENIGN)
    assert code == EXIT_CLEAN
    assert_fits(out, width)
    text = flat(out)
    assert "Grade A" in text
    assert "Trust score 100/100" in text
    assert "No findings." in text


def test_malicious_scan(width: int) -> None:
    code, out = run("scan", D1)
    assert code == EXIT_FINDINGS
    assert_fits(out, width)
    text = flat(out)
    assert "Grade F" in text
    assert text.index("Grade F") < text.index("CRITICAL")
    assert 'tool "add" › description' in text
    assert "Fix: Remove the request." in text


def test_secrets_stay_redacted(width: int) -> None:
    fixture = Path(D4).read_text(encoding="utf-8")
    assert all(secret in fixture for secret in D4_SECRETS)  # each check below is meaningful
    code, out = run("scan", D4)
    assert code == EXIT_FINDINGS
    assert_fits(out, width)
    for secret in D4_SECRETS:
        assert squashed(secret) not in squashed(out)
    assert "****" in out


def test_discover_with_nothing_configured(
    width: int, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    monkeypatch.setenv("APPDATA", str(tmp_path / "roaming"))
    monkeypatch.delenv("ZIRAH_APPROVED", raising=False)
    monkeypatch.chdir(tmp_path)
    code, out = run("discover")
    assert code == EXIT_CLEAN
    assert_fits(out, width)
    assert "0 MCP servers in 0 config files" in flat(out)
