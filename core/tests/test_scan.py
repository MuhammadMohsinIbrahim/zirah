from __future__ import annotations

import itertools
from collections.abc import Iterator, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from zirah.analyzers.base import Analyzer, ScanContext, discover_analyzers
from zirah.analyzers.d1_tool_poisoning import ToolPoisoning
from zirah.loaders import LoaderError, load_static
from zirah.models import (
    Confidence,
    Engine,
    Evidence,
    Finding,
    Grade,
    Manifest,
    Module,
    Owasp,
    Severity,
)
from zirah.rulepack import RulePack, load_rulepack
from zirah.scan import Scan, ScanError, load_target, scan, scan_loaded
from zirah.scoring import score

FIXTURES = Path(__file__).parent / "fixtures"
MALICIOUS = FIXTURES / "analyzers" / "d1" / "hidden_instructions.json"
BENIGN = FIXTURES / "analyzers" / "benign" / "everyday_tools.json"
START = datetime(2026, 9, 28, 12, 0, tzinfo=UTC)


def fixed_clock() -> Iterator[datetime]:
    return (START + timedelta(seconds=i) for i in itertools.count())


def clock_fn() -> datetime:
    return START


def run(
    path: Path,
    rules: RulePack | None = None,
    analyzers: Sequence[type[Analyzer]] | None = None,
) -> Scan:
    ticks = fixed_clock()
    return scan(str(path), rules=rules, analyzers=analyzers, clock=lambda: next(ticks))


def test_end_to_end_from_fixture_file_to_scan_result() -> None:
    result = run(MALICIOUS).result
    loaded = load_static(MALICIOUS)
    assert result.target == loaded.target
    assert result.manifest_sha256 == loaded.manifest.sha256()
    assert result.rulepack_version == load_rulepack().version
    assert result.engines_used == (Engine.STATIC,)
    assert result.started_at == START
    assert result.finished_at == START + timedelta(seconds=1)
    rules = {f.rule_id for f in result.findings}
    assert {"D1-INSTRUCTION-TAG", "D1-SENSITIVE-FILE-ACCESS", "D1-HIDDEN-COMMENT"} <= rules
    expected = score(result.findings)
    assert (result.trust_score, result.grade) == (expected.trust_score, expected.grade)
    assert result.grade is Grade.F


def test_same_input_gives_the_same_json_apart_from_timestamps() -> None:
    first = scan(str(MALICIOUS)).result.model_dump(mode="json")
    second = scan(str(MALICIOUS)).result.model_dump(mode="json")
    for data in (first, second):
        del data["started_at"], data["finished_at"]
    assert first == second


def test_same_input_and_clock_gives_identical_json() -> None:
    assert run(MALICIOUS).result.model_dump_json() == run(MALICIOUS).result.model_dump_json()


def test_benign_fixture_scores_100_a() -> None:
    outcome = run(BENIGN)
    assert outcome.result.findings == ()
    assert (outcome.result.trust_score, outcome.result.grade) == (100, Grade.A)
    assert outcome.complete


def test_scan_keeps_manifest_and_score_breakdown() -> None:
    outcome = run(MALICIOUS)
    assert outcome.manifest == load_static(MALICIOUS).manifest
    assert {d.finding_id for d in outcome.score.deductions} == {
        f.id for f in outcome.result.findings
    }


def test_rulepack_version_comes_from_the_loaded_pack() -> None:
    pack = load_rulepack().model_copy(update={"version": "custom-1"})
    assert run(BENIGN, rules=pack).result.rulepack_version == "custom-1"


# --- Failures --------------------------------------------------------------------------------


class Crashing(Analyzer):
    name = "test-crashing"
    module = Module.D2
    engine = Engine.STATIC

    def analyze(self, manifest: Manifest, ctx: ScanContext) -> Sequence[Finding]:
        raise RuntimeError("boom")


class WrongModule(Analyzer):
    name = "test-wrong-module"
    module = Module.D3
    engine = Engine.STATIC

    def analyze(self, manifest: Manifest, ctx: ScanContext) -> Sequence[Finding]:
        return [_finding(Module.D1)]


class Duplicating(Analyzer):
    name = "test-duplicating"
    module = Module.D1
    engine = Engine.STATIC

    def analyze(self, manifest: Manifest, ctx: ScanContext) -> Sequence[Finding]:
        return [_finding(Module.D1), _finding(Module.D1)]


def _finding(module: Module) -> Finding:
    return Finding(
        module=module,
        rule_id=f"{module}-TEST",
        severity=Severity.LOW,
        confidence=Confidence.LOW,
        owasp=(Owasp.MCP03,),
        title="Test",
        evidence=Evidence(location="/tools/0/description", snippet="x"),
        remediation="Fix it.",
        engine=Engine.STATIC,
    )


def test_a_crashing_analyzer_is_reported_and_the_scan_goes_on() -> None:
    outcome = run(MALICIOUS, analyzers=[Crashing, ToolPoisoning, WrongModule])
    assert not outcome.complete
    assert [(f.analyzer, f.error.split(":")[0]) for f in outcome.failures] == [
        ("test-crashing", "RuntimeError"),
        ("test-wrong-module", "AnalyzerError"),
    ]
    assert outcome.failures[0].error == "RuntimeError: boom"
    assert outcome.result.findings
    assert {f.module for f in outcome.result.findings} == {Module.D1}


def test_findings_are_deduplicated_by_id() -> None:
    outcome = run(BENIGN, analyzers=[Duplicating])
    assert len(outcome.result.findings) == 1


def test_no_analyzers_is_an_error() -> None:
    with pytest.raises(ScanError, match="no analyzers"):
        run(BENIGN, analyzers=[])


def test_default_runs_every_discovered_analyzer() -> None:
    outcome = scan_loaded(load_static(MALICIOUS), clock=clock_fn)
    assert outcome.result.started_at == outcome.result.finished_at == START
    assert outcome.complete
    assert len(discover_analyzers()) >= 4


# --- Targets ---------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("target", "message"),
    [
        ("npm://pkg", "expected an http"),
        ("http://127.0.0.1:9/mcp", "cannot connect"),  # discard port: nothing listens
    ],
)
def test_bad_or_unreachable_urls_give_a_readable_error(target: str, message: str) -> None:
    with pytest.raises(LoaderError, match=message):
        load_target(target)


def test_missing_file_is_a_loader_error(tmp_path: Path) -> None:
    with pytest.raises(LoaderError, match="file not found"):
        scan(str(tmp_path / "missing.json"))
