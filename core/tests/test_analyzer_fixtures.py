"""Run every static analyzer over the fixture corpus.

``fixtures/analyzers/d<N>/*.json`` are malicious manifests for module D<N>. Each lists what
it must produce under ``_zirah_expect`` as ``"RULE-ID /json/pointer"`` strings, and the
module's findings must match that list exactly: no misses and no extras.

``fixtures/analyzers/benign/*.json`` and the loader fixtures in ``fixtures/manifests`` are
ordinary servers (multilingual text, emoji, markdown, tools that mention each other). No
analyzer may report anything on them.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from zirah.analyzers.base import ScanContext, discover_analyzers
from zirah.loaders import load_static
from zirah.models import Engine, Finding, Module
from zirah.rulepack import load_rulepack

FIXTURES = Path(__file__).parent / "fixtures"
ANALYZER_FIXTURES = FIXTURES / "analyzers"
MALICIOUS = sorted(ANALYZER_FIXTURES.glob("d*/*.json"))
BENIGN = sorted(ANALYZER_FIXTURES.glob("benign/*.json")) + sorted(
    (FIXTURES / "manifests").glob("*.json")
)
STATIC_ANALYZERS = [cls for cls in discover_analyzers() if cls.engine is Engine.STATIC]
PACK = load_rulepack()

RUNTIME_ONLY = {"D4-AWS-SECRET-KEY", "D4-PRIVATE-KEY", "D4-JWT"}
"""Rules exercised in test_d4_secrets.py with values built at test time, so no key block,
token or credential pair that scanners recognise is ever committed."""


def fixture_id(path: Path) -> str:
    return f"{path.parent.name}/{path.stem}"


def run(path: Path, module: Module | None = None) -> list[Finding]:
    loaded = load_static(path)
    ctx = ScanContext(target=loaded.target, rules=PACK)
    return [
        finding
        for cls in STATIC_ANALYZERS
        if module is None or cls.module is module
        for finding in cls().run(loaded.manifest, ctx)
    ]


def expected(path: Path) -> list[str]:
    data = json.loads(path.read_text(encoding="utf-8"))
    entries: list[str] = data["_zirah_expect"]
    return entries


@pytest.mark.parametrize("path", MALICIOUS, ids=fixture_id)
def test_malicious_fixture_gives_exactly_the_expected_findings(path: Path) -> None:
    module = Module(path.parent.name.upper())
    found = sorted(f"{f.rule_id} {f.evidence.location}" for f in run(path, module))
    assert found == sorted(expected(path))


@pytest.mark.parametrize("path", BENIGN, ids=fixture_id)
def test_benign_fixture_is_clean(path: Path) -> None:
    findings = run(path)
    assert [f"{f.rule_id} {f.evidence.location}" for f in findings] == []


def test_every_rule_is_exercised_by_a_malicious_fixture() -> None:
    covered = {entry.split(" ", 1)[0] for path in MALICIOUS for entry in expected(path)}
    covered |= RUNTIME_ONLY
    modules = {cls.module for cls in STATIC_ANALYZERS}
    rules = {rule.id for rule in PACK.rules if rule.module in modules}
    assert sorted(rules - covered) == []


def test_every_static_module_has_fixtures() -> None:
    fixture_modules = {path.parent.name.upper() for path in MALICIOUS}
    assert {cls.module.value for cls in STATIC_ANALYZERS} <= fixture_modules
    assert BENIGN
