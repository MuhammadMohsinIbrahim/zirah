from __future__ import annotations

import json
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import jsonschema  # type: ignore[import-untyped]
import pytest
from typer.testing import CliRunner

from zirah.analyzers.base import Analyzer, ScanContext
from zirah.analyzers.d1_tool_poisoning import ToolPoisoning
from zirah.cli import app
from zirah.loaders import Loaded
from zirah.models import (
    Engine,
    Finding,
    Manifest,
    Module,
    Severity,
    Target,
    TargetKind,
    Tool,
)
from zirah.report import sarif
from zirah.scan import Scan, scan, scan_loaded
from zirah.scoring import SECURITY_SEVERITY

FIXTURES = Path(__file__).parent / "fixtures"
SCHEMA = json.loads((FIXTURES / "sarif" / "sarif-schema-2.1.0.json").read_text(encoding="utf-8"))
VALIDATOR = jsonschema.Draft4Validator(SCHEMA)
MALICIOUS = FIXTURES / "analyzers" / "d1" / "hidden_instructions.json"
SECRETS = FIXTURES / "analyzers" / "d4" / "leaked_keys.json"
BENIGN = FIXTURES / "analyzers" / "benign" / "everyday_tools.json"
START = datetime(2026, 9, 28, 12, 0, tzinfo=UTC)


def fixed_scan(path: Path) -> Scan:
    return scan(str(path), clock=lambda: START)


def validate(document: dict[str, Any]) -> None:
    errors = sorted(VALIDATOR.iter_errors(document), key=lambda e: list(e.path))
    assert [f"{list(e.path)}: {e.message}" for e in errors] == []


@pytest.mark.parametrize("path", [MALICIOUS, SECRETS, BENIGN], ids=lambda p: p.stem)
def test_output_validates_against_the_official_schema(path: Path) -> None:
    validate(json.loads(sarif.render(fixed_scan(path))))


def test_the_vendored_schema_rejects_invalid_sarif() -> None:
    document = sarif.to_sarif(fixed_scan(MALICIOUS))
    document["runs"][0]["results"][0]["level"] = "fatal"
    del document["version"]
    assert len(list(VALIDATOR.iter_errors(document))) == 2


def test_one_result_per_finding_with_the_finding_id_as_fingerprint() -> None:
    outcome = fixed_scan(MALICIOUS)
    run = sarif.to_sarif(outcome)["runs"][0]
    results = run["results"]
    assert len(results) == len(outcome.result.findings)
    for result, finding in zip(results, outcome.result.findings, strict=True):
        assert result["fingerprints"] == {sarif.FINGERPRINT: finding.id}
        assert result["partialFingerprints"] == {sarif.FINGERPRINT: finding.id}
        assert result["ruleId"] == finding.rule_id
        assert run["tool"]["driver"]["rules"][result["ruleIndex"]]["id"] == finding.rule_id
        location = result["locations"][0]
        assert location["logicalLocations"][0]["fullyQualifiedName"] == finding.evidence.location
        assert location["physicalLocation"]["artifactLocation"]["uri"] == MALICIOUS.as_uri()
        assert result["properties"]["points"] == outcome.score.points_for(finding.id)


def test_rules_carry_owasp_tags_severity_and_precision() -> None:
    outcome = fixed_scan(MALICIOUS)
    rules = sarif.to_sarif(outcome)["runs"][0]["tool"]["driver"]["rules"]
    assert [r["id"] for r in rules] == sorted({f.rule_id for f in outcome.result.findings})
    by_id = {f.rule_id: f for f in outcome.result.findings}
    for rule in rules:
        finding = by_id[rule["id"]]
        props = rule["properties"]
        assert props["tags"] == ["security", "D1", "MCP03"]
        assert props["security-severity"] == SECURITY_SEVERITY[finding.severity]
        assert props["precision"] == finding.confidence.value
        assert rule["defaultConfiguration"]["level"] == sarif.LEVEL[finding.severity]
        assert rule["help"]["text"] == finding.remediation


@pytest.mark.parametrize(
    ("severity", "level"),
    [
        (Severity.CRITICAL, "error"),
        (Severity.HIGH, "error"),
        (Severity.MEDIUM, "warning"),
        (Severity.LOW, "note"),
        (Severity.INFO, "note"),
    ],
)
def test_severity_mapping(severity: Severity, level: str) -> None:
    assert sarif.LEVEL[severity] == level
    assert 0.0 <= float(SECURITY_SEVERITY[severity]) <= 10.0


def test_security_severity_sits_in_github_bands() -> None:
    bands = {
        Severity.CRITICAL: (9.0, 10.0),
        Severity.HIGH: (7.0, 8.9),
        Severity.MEDIUM: (4.0, 6.9),
        Severity.LOW: (0.1, 3.9),
    }
    for severity, (low, high) in bands.items():
        assert low <= float(SECURITY_SEVERITY[severity]) <= high


def test_run_properties_hold_score_grade_and_versions() -> None:
    outcome = fixed_scan(MALICIOUS)
    run = sarif.to_sarif(outcome)["runs"][0]
    assert run["properties"]["trustScore"] == outcome.result.trust_score
    assert run["properties"]["grade"] == "F"
    assert run["properties"]["manifestSha256"] == outcome.result.manifest_sha256
    assert run["tool"]["driver"]["properties"]["rulepackVersion"] == outcome.result.rulepack_version
    invocation = run["invocations"][0]
    assert invocation["executionSuccessful"] is True
    assert invocation["startTimeUtc"] == "2026-09-28T12:00:00Z"
    assert "toolExecutionNotifications" not in invocation


def test_output_is_ascii_and_escapes_invisible_characters(tmp_path: Path) -> None:
    path = tmp_path / "m.json"
    path.write_text(
        json.dumps(
            {"tools": [{"name": "t", "description": "Adds.\U0000200b\U0000200b\U0000200b"}]}
        ),
        encoding="utf-8",
    )
    text = sarif.render(scan(str(path)))
    assert text.isascii()
    assert "\\u200b" in text
    validate(json.loads(text))


def test_secrets_stay_redacted() -> None:
    text = sarif.render(fixed_scan(SECRETS))
    assert "ghp_ZirahFakeTokenNotReal7f3a9c1e2b4d608" not in text
    assert "zirah_fake_4f9c2e71b8d3a605" not in text


def test_benign_scan_has_no_results_or_rules() -> None:
    run = sarif.to_sarif(fixed_scan(BENIGN))["runs"][0]
    assert run["results"] == []
    assert run["tool"]["driver"]["rules"] == []


def test_same_input_gives_identical_sarif() -> None:
    assert sarif.render(fixed_scan(MALICIOUS)) == sarif.render(fixed_scan(MALICIOUS))


class Crashing(Analyzer):
    name = "test-sarif-crashing"
    module = Module.D2
    engine = Engine.STATIC

    def analyze(self, manifest: Manifest, ctx: ScanContext) -> Sequence[Finding]:
        raise RuntimeError("boom")


def test_failed_analyzers_become_notifications() -> None:
    outcome = scan(str(MALICIOUS), analyzers=[Crashing, ToolPoisoning], clock=lambda: START)
    document = sarif.to_sarif(outcome)
    validate(document)
    invocation = document["runs"][0]["invocations"][0]
    assert invocation["executionSuccessful"] is False
    (notification,) = invocation["toolExecutionNotifications"]
    assert notification["descriptor"]["id"] == "test-sarif-crashing"
    assert (
        notification["message"]["text"] == "Analyzer test-sarif-crashing failed: RuntimeError: boom"
    )


@pytest.mark.parametrize(
    ("location", "uri"),
    [
        ("server.json", "server.json"),
        ("dir\\server.json", "dir/server.json"),
        ("C:\\scans\\server.json", "file:///C:/scans/server.json"),
        ("/srv/scans/server.json", "file:///srv/scans/server.json"),
    ],
)
def test_artifact_uri(location: str, uri: str) -> None:
    assert sarif._artifact_uri(Target(kind=TargetKind.STATIC, location=location)) == uri


def test_non_file_targets_and_target_locations_are_logical_only() -> None:
    manifest = Manifest(tools=(Tool(name="t", description="<IMPORTANT>obey</IMPORTANT>"),))
    remote = Loaded(
        target=Target(kind=TargetKind.HTTP, location="https://example.invalid/mcp"),
        manifest=manifest,
    )
    document = sarif.to_sarif(scan_loaded(remote, clock=lambda: START))
    validate(document)
    run = document["runs"][0]
    assert "artifacts" not in run
    assert all("physicalLocation" not in r["locations"][0] for r in run["results"])

    args = Loaded(
        target=Target(
            kind=TargetKind.STATIC, location="m.json", args=("--token", "ghp_" + "Zf7a9" * 8)
        ),
        manifest=Manifest(),
    )
    (result,) = sarif.to_sarif(scan_loaded(args, clock=lambda: START))["runs"][0]["results"]
    assert "physicalLocation" not in result["locations"][0]
    assert result["locations"][0]["logicalLocations"][0]["fullyQualifiedName"] == "target:/args"


def test_cli_sarif_format(tmp_path: Path) -> None:
    out = tmp_path / "zirah.sarif"
    result = CliRunner().invoke(app, ["scan", str(MALICIOUS), "--format", "sarif", "-o", str(out)])
    assert result.exit_code == 1
    document = json.loads(out.read_text(encoding="utf-8"))
    validate(document)
    assert document["version"] == "2.1.0"
