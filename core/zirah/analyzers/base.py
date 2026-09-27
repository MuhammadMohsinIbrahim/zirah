"""The common interface every analyzer implements, and discovery of analyzers."""

from __future__ import annotations

import importlib
import inspect
import pkgutil
from abc import ABC, abstractmethod
from collections.abc import Sequence
from dataclasses import dataclass
from types import ModuleType
from typing import ClassVar

from zirah.models import Engine, Finding, Manifest, Module, Target


@dataclass(frozen=True, slots=True)
class ScanContext:
    """Everything an analyzer may need besides the manifest.

    Grows as releases add inputs (rule packs, the LLM provider, downloaded source), so
    analyzers take it as one argument instead of a changing parameter list.
    """

    target: Target


class AnalyzerError(Exception):
    """An analyzer is misdeclared or returned findings that break its contract."""


class Analyzer(ABC):
    """Base class for analyzers.

    Subclasses declare which detection module and engine they implement and return findings
    for exactly that module and engine. A module with both static and LLM checks (e.g. D1)
    ships two analyzers.
    """

    name: ClassVar[str]
    """Unique, stable identifier, e.g. ``"d1-unicode"``. Used in logs and error reports."""
    module: ClassVar[Module]
    engine: ClassVar[Engine]

    def __init_subclass__(cls, **kwargs: object) -> None:
        super().__init_subclass__(**kwargs)
        if inspect.isabstract(cls):
            return
        missing = [attr for attr in ("name", "module", "engine") if not hasattr(cls, attr)]
        if missing:
            raise AnalyzerError(f"{cls.__qualname__} must define {', '.join(missing)}")
        if not isinstance(cls.module, Module) or not isinstance(cls.engine, Engine):
            raise AnalyzerError(f"{cls.__qualname__}: module/engine must be Module/Engine members")
        if not cls.name:
            raise AnalyzerError(f"{cls.__qualname__}: name must not be empty")

    @abstractmethod
    def analyze(self, manifest: Manifest, ctx: ScanContext) -> Sequence[Finding]:
        """Return the findings for ``manifest``. Must not mutate shared state."""

    def run(self, manifest: Manifest, ctx: ScanContext) -> list[Finding]:
        """Call :meth:`analyze` and check the findings match this analyzer's declaration."""
        findings = list(self.analyze(manifest, ctx))
        for finding in findings:
            if finding.module is not self.module or finding.engine is not self.engine:
                raise AnalyzerError(
                    f"analyzer {self.name!r} ({self.module}/{self.engine}) returned finding "
                    f"{finding.id} for {finding.module}/{finding.engine}"
                )
        return findings


def discover_analyzers(package: ModuleType | str = "zirah.analyzers") -> list[type[Analyzer]]:
    """Import every submodule of ``package`` and return the concrete analyzers defined there.

    Only classes defined in the package's own modules count (an imported analyzer is not
    discovered twice). The result is sorted by module (D1..D14), then name, so scans run
    analyzers in a stable order.
    """
    pkg = importlib.import_module(package) if isinstance(package, str) else package
    found: dict[str, type[Analyzer]] = {}
    for info in pkgutil.iter_modules(pkg.__path__, prefix=f"{pkg.__name__}."):
        submodule = importlib.import_module(info.name)
        for _, cls in inspect.getmembers(submodule, inspect.isclass):
            if (
                issubclass(cls, Analyzer)
                and not inspect.isabstract(cls)
                and cls.__module__ == submodule.__name__
            ):
                if cls.name in found and found[cls.name] is not cls:
                    raise AnalyzerError(
                        f"duplicate analyzer name {cls.name!r}: "
                        f"{found[cls.name].__module__} and {cls.__module__}"
                    )
                found[cls.name] = cls
    order = list(Module)
    return sorted(found.values(), key=lambda cls: (order.index(cls.module), cls.name))
