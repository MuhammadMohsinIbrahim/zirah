from __future__ import annotations

import itertools
import textwrap
from collections.abc import Callable, Sequence
from pathlib import Path

import pytest

from zirah.analyzers.base import Analyzer, AnalyzerError, ScanContext, discover_analyzers
from zirah.models import (
    Confidence,
    Engine,
    Evidence,
    Finding,
    Manifest,
    Module,
    Owasp,
    Severity,
    Target,
    TargetKind,
    Tool,
)

CTX = ScanContext(target=Target(kind=TargetKind.STATIC, location="manifest.json"))
MANIFEST = Manifest(tools=(Tool(name="echo", description="Echo the input. <IMPORTANT>"),))

_counter = itertools.count()

# A dummy analyzer as it would appear in a real module file under zirah/analyzers/.
DUMMY_ANALYZER = """
from zirah.analyzers.base import Analyzer
from zirah.models import (
    Confidence, Engine, Evidence, Finding, Module, Owasp, Severity,
)


class Dummy{suffix}(Analyzer):
    name = "{name}"
    module = Module.{module}
    engine = Engine.STATIC

    def analyze(self, manifest, ctx):
        return [
            Finding(
                module=self.module,
                rule_id="DUMMY-IMPORTANT",
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                owasp=(Owasp.MCP03,),
                title="Tag found",
                evidence=Evidence(location=f"/tools/{{i}}/description", snippet="<IMPORTANT>"),
                remediation="Remove it.",
                engine=self.engine,
            )
            for i, tool in enumerate(manifest.tools)
            if "<IMPORTANT>" in tool.description
        ]
"""


MakePackage = Callable[[dict[str, str]], str]


@pytest.fixture
def make_package(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> MakePackage:
    """Write a throwaway analyzers package and return its import name."""

    def make(files: dict[str, str]) -> str:
        name = f"fake_analyzers_{next(_counter)}"
        pkg = tmp_path / name
        pkg.mkdir()
        (pkg / "__init__.py").write_text("", encoding="utf-8")
        for filename, source in files.items():
            (pkg / filename).write_text(textwrap.dedent(source), encoding="utf-8")
        monkeypatch.syspath_prepend(str(tmp_path))
        return name

    return make


def make_finding(module: Module = Module.D1, engine: Engine = Engine.STATIC) -> Finding:
    return Finding(
        module=module,
        rule_id="X",
        severity=Severity.LOW,
        confidence=Confidence.LOW,
        owasp=(Owasp.MCP03,),
        title="t",
        evidence=Evidence(location="/tools/0", snippet="s"),
        remediation="r",
        engine=engine,
    )


class ReturnsGiven(Analyzer):
    """Test double that returns whatever findings it is constructed with."""

    name = "test-returns-given"
    module = Module.D1
    engine = Engine.STATIC

    def __init__(self, findings: Sequence[Finding]) -> None:
        self.findings = findings

    def analyze(self, manifest: Manifest, ctx: ScanContext) -> Sequence[Finding]:
        return self.findings


# --- Discovery ---------------------------------------------------------------------------


def test_dummy_analyzer_is_discovered_and_runs(make_package: MakePackage) -> None:
    package = make_package(
        {"d1_dummy.py": DUMMY_ANALYZER.format(suffix="", name="d1-dummy", module="D1")}
    )
    [analyzer_cls] = discover_analyzers(package)
    assert analyzer_cls.name == "d1-dummy"

    findings = analyzer_cls().run(MANIFEST, CTX)
    assert [f.evidence.location for f in findings] == ["/tools/0/description"]
    assert analyzer_cls().run(Manifest(), CTX) == []


def test_discovery_sorts_by_module_then_name(make_package: MakePackage) -> None:
    package = make_package(
        {
            "d10.py": DUMMY_ANALYZER.format(suffix="A", name="a-d10", module="D10"),
            "d2.py": DUMMY_ANALYZER.format(suffix="B", name="z-d2", module="D2"),
            "d2_more.py": DUMMY_ANALYZER.format(suffix="C", name="a-d2", module="D2"),
        }
    )
    # D2 sorts before D10 by module order, not by string.
    assert [cls.name for cls in discover_analyzers(package)] == ["a-d2", "z-d2", "a-d10"]


def test_discovery_skips_imported_and_abstract_classes(make_package: MakePackage) -> None:
    package = make_package(
        {
            "d1.py": DUMMY_ANALYZER.format(suffix="", name="d1-dummy", module="D1"),
            "reexport.py": "from .d1 import Dummy\n",
            "abstract.py": """
                from abc import abstractmethod
                from zirah.analyzers.base import Analyzer

                class Intermediate(Analyzer):
                    @abstractmethod
                    def helper(self): ...
            """,
            "_helpers.py": "VALUE = 1\n",
        }
    )
    assert [cls.name for cls in discover_analyzers(package)] == ["d1-dummy"]


def test_discovery_rejects_duplicate_names(make_package: MakePackage) -> None:
    package = make_package(
        {
            "one.py": DUMMY_ANALYZER.format(suffix="1", name="same", module="D1"),
            "two.py": DUMMY_ANALYZER.format(suffix="2", name="same", module="D2"),
        }
    )
    with pytest.raises(AnalyzerError, match="duplicate analyzer name 'same'"):
        discover_analyzers(package)


def test_builtin_package_discovers_only_analyzers() -> None:
    # Holds before and after real analyzers land: base.py itself contributes nothing.
    analyzers = discover_analyzers()
    assert all(issubclass(cls, Analyzer) for cls in analyzers)
    assert len({cls.name for cls in analyzers}) == len(analyzers)


def test_discovery_accepts_module_object(make_package: MakePackage) -> None:
    import importlib

    package = make_package(
        {"d1.py": DUMMY_ANALYZER.format(suffix="", name="d1-dummy", module="D1")}
    )
    assert discover_analyzers(importlib.import_module(package))[0].name == "d1-dummy"


# --- Declaration checks ------------------------------------------------------------------


def test_subclass_missing_declarations_is_rejected() -> None:
    with pytest.raises(AnalyzerError, match="must define module, engine"):

        class NoModule(Analyzer):
            name = "x"

            def analyze(self, manifest: Manifest, ctx: ScanContext) -> Sequence[Finding]:
                return []


def test_subclass_with_plain_string_module_is_rejected() -> None:
    with pytest.raises(AnalyzerError, match="must be Module/Engine members"):

        class StringModule(Analyzer):
            name = "x"
            module = "D1"  # type: ignore[assignment]
            engine = Engine.STATIC

            def analyze(self, manifest: Manifest, ctx: ScanContext) -> Sequence[Finding]:
                return []


def test_subclass_with_empty_name_is_rejected() -> None:
    with pytest.raises(AnalyzerError, match="name must not be empty"):

        class EmptyName(Analyzer):
            name = ""
            module = Module.D1
            engine = Engine.STATIC

            def analyze(self, manifest: Manifest, ctx: ScanContext) -> Sequence[Finding]:
                return []


# --- run() contract ----------------------------------------------------------------------


def test_run_returns_findings_as_list() -> None:
    findings = (make_finding(),)
    assert ReturnsGiven(findings).run(MANIFEST, CTX) == list(findings)


@pytest.mark.parametrize(
    "finding",
    [make_finding(module=Module.D2), make_finding(engine=Engine.LLM)],
)
def test_run_rejects_findings_outside_declared_module_or_engine(finding: Finding) -> None:
    with pytest.raises(AnalyzerError, match="test-returns-given"):
        ReturnsGiven([finding]).run(MANIFEST, CTX)


def test_scan_context_is_immutable() -> None:
    with pytest.raises(AttributeError):
        CTX.target = Target(kind=TargetKind.HTTP, location="x")  # type: ignore[misc]
