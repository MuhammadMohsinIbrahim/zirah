from __future__ import annotations

import json
from pathlib import Path

from zirah.report import terminal
from zirah.scan import Scan, scan

FIXTURES = Path(__file__).parent / "fixtures" / "analyzers"


def scan_manifest(tmp_path: Path, manifest: dict[str, object]) -> Scan:
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    return scan(str(path))


def test_header_comes_first_with_grade_score_and_meaning(tmp_path: Path) -> None:
    outcome = scan_manifest(
        tmp_path,
        {
            "serverInfo": {"name": "ops", "version": "1.0"},
            "tools": [{"name": "deploy", "description": "Uses AKIAZIRAHFAKE7Q2M4X9 for uploads."}],
        },
    )
    text = terminal.plain_text(outcome)
    lines = text.splitlines()
    assert lines[0] == "Zirah scan report"
    start = lines.index("Server  ops 1.0")
    assert lines[start + 1 : start + 6] == [
        "",
        " Grade F   Trust score 39/100",
        "Severe findings. Do not use this server until they are fixed.",
        "Capped at 39 (from 60): 1 critical finding with high confidence.",
        "1 finding at 1 location: 1 critical",
    ]
    assert "AKIA****" in text
    assert "AKIAZIRAHFAKE7Q2M4X9" not in text
    assert "Score: 100 - 40 points (deductions rounded up) = 60, capped at 39." in text


def test_sections_follow_severity_order() -> None:
    text = terminal.plain_text(scan(str(FIXTURES / "d1" / "hidden_instructions.json")))
    critical = text.index("CRITICAL ─")
    assert "HIGH ─" not in text  # every location's worst finding is critical
    assert text.index("Grade F") < critical
    assert text.count('tool "get_weather" › description') == 1


def test_a_snippet_shared_by_two_findings_is_shown_once() -> None:
    text = terminal.plain_text(scan(str(FIXTURES / "d1" / "hidden_instructions.json")))
    flat = " ".join(text.split())
    assert flat.count("~/.ssh/id_rsa and put it in the city field") == 1
    assert "D1-HIDDEN-COMMENT · -0.38 pts (same text as above) Fix:" in flat


def test_no_findings() -> None:
    text = terminal.plain_text(scan(str(FIXTURES / "benign" / "everyday_tools.json")))
    assert " Grade A   Trust score 100/100" in text
    assert text.count("No findings.") == 1
    assert "No significant findings." not in text
    assert "Score:" not in text
    assert text.rstrip().endswith("zirah 0.1.0.dev0")


def test_score_below_zero_says_it_is_floored() -> None:
    text = terminal.plain_text(scan(str(FIXTURES / "d4" / "leaked_keys.json")))
    flat = " ".join(text.split())
    assert "Score: 100 - 150 points (deductions rounded up) = 0 (floored at 0)." in flat
