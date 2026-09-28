"""The scan pipeline for one target.

``load target -> hash manifest -> run analyzers concurrently -> dedupe -> score -> ScanResult``

An analyzer that crashes (or breaks its contract) is recorded in :attr:`Scan.failures` and the
scan goes on with the others; callers decide how to report an incomplete scan.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from zirah.analyzers.base import Analyzer, ScanContext, discover_analyzers
from zirah.judge import Judge
from zirah.llm.base import LlmClient
from zirah.loaders import Loaded, LoaderError, load_static
from zirah.models import Engine, Finding, Manifest, ScanResult
from zirah.rulepack import RulePack, load_rulepack
from zirah.scoring import Score, score

MAX_WORKERS = 8
"""Upper bound on analyzers running at the same time."""

_URL = re.compile(r"^[a-z][a-z0-9+.-]*://", re.IGNORECASE)

Clock = Callable[[], datetime]


def utc_now() -> datetime:
    return datetime.now(UTC)


class ScanError(Exception):
    """The scan could not run at all (as opposed to one analyzer failing)."""


@dataclass(frozen=True, slots=True)
class AnalyzerFailure:
    analyzer: str
    error: str
    """Exception type and message, e.g. ``"ValueError: bad input"``."""


@dataclass(frozen=True, slots=True)
class Scan:
    """A finished scan: the contract result plus what reports need to explain it."""

    result: ScanResult
    manifest: Manifest
    score: Score
    failures: tuple[AnalyzerFailure, ...] = ()

    @property
    def complete(self) -> bool:
        """Whether every analyzer ran. An incomplete scan may miss findings."""
        return not self.failures


def load_target(target: str) -> Loaded:
    """Load ``target``. For now only static manifest files are supported."""
    if _URL.match(target):
        raise LoaderError(
            f"{target}: remote targets are not supported yet; pass a manifest JSON file"
        )
    return load_static(Path(target))


def scan(
    target: str,
    *,
    rules: RulePack | None = None,
    analyzers: Sequence[type[Analyzer]] | None = None,
    clock: Clock = utc_now,
    llm: LlmClient | None = None,
) -> Scan:
    """Load and scan ``target``. Raises :class:`LoaderError` when it cannot be loaded."""
    started_at = clock()
    loaded = load_target(target)
    return scan_loaded(
        loaded, rules=rules, analyzers=analyzers, clock=clock, started_at=started_at, llm=llm
    )


def scan_loaded(
    loaded: Loaded,
    *,
    rules: RulePack | None = None,
    analyzers: Sequence[type[Analyzer]] | None = None,
    clock: Clock = utc_now,
    started_at: datetime | None = None,
    llm: LlmClient | None = None,
) -> Scan:
    """Scan an already loaded target with ``analyzers`` (default: every discovered one)."""
    started_at = started_at or clock()
    pack = rules if rules is not None else load_rulepack()
    classes = discover_analyzers() if analyzers is None else list(analyzers)
    if llm is None:  # LLM analyzers only run when an LLM is configured
        classes = [cls for cls in classes if cls.engine is not Engine.LLM]
    if not classes:
        raise ScanError("no analyzers to run")

    judge = Judge(llm, pack) if llm is not None else None
    ctx = ScanContext(target=loaded.target, rules=pack, llm=llm, judge=judge)
    manifest_sha256 = loaded.manifest.sha256()
    with ThreadPoolExecutor(max_workers=min(len(classes), MAX_WORKERS)) as pool:
        futures = [pool.submit(_run, cls, loaded.manifest, ctx) for cls in classes]
        # Collected in submission order, so the result does not depend on thread timing.
        outcomes = [future.result() for future in futures]

    findings: dict[str, Finding] = {}
    failures: list[AnalyzerFailure] = []
    for outcome in outcomes:
        if isinstance(outcome, AnalyzerFailure):
            failures.append(outcome)
            continue
        for finding in outcome:
            findings.setdefault(finding.id, finding)

    deduped = tuple(findings.values())
    scored = score(deduped)
    result = ScanResult(
        target=loaded.target,
        manifest_sha256=manifest_sha256,
        rulepack_version=pack.version,
        findings=deduped,
        trust_score=scored.trust_score,
        grade=scored.grade,
        started_at=started_at,
        finished_at=clock(),
        engines_used=_engines(classes),
        llm=judge.info if judge and Engine.LLM in _engines(classes) else None,
        score_breakdown=scored.breakdown,
    )
    return Scan(result=result, manifest=loaded.manifest, score=scored, failures=tuple(failures))


def _run(
    cls: type[Analyzer], manifest: Manifest, ctx: ScanContext
) -> list[Finding] | AnalyzerFailure:
    try:
        return cls().run(manifest, ctx)
    except Exception as exc:  # one analyzer must never take the scan down
        return AnalyzerFailure(analyzer=cls.name, error=f"{type(exc).__name__}: {exc}")


def _engines(classes: Sequence[type[Analyzer]]) -> tuple[Engine, ...]:
    return tuple({cls.engine: None for cls in classes})
