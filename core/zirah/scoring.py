"""Trust score and grade, and the breakdown that explains them.

This module alone holds the scoring numbers. How a score is built:

1. Each finding has a **weight**: its severity weight times its confidence multiplier.
2. Findings are **grouped by evidence location**. At one location the heaviest finding counts
   in full and each other one adds only ``SAME_LOCATION_SHARE`` of its weight, so one poisoned
   description matched by three rules is not counted three times.
3. Locations are ranked by weight, heaviest first, and the ``k``-th one (from 0) is multiplied
   by ``LOCATION_DECAY ** k``. These **diminishing returns** keep many low findings from
   outweighing one critical one.
4. The deductions are summed, rounded up to whole points and taken from 100.
5. **Hard caps** then limit the score, so no amount of arithmetic hides a real attack: any
   critical or high finding with high confidence caps the score (``CAPS``).

Every point is listed against a finding id in :attr:`Score.deductions`, and a cap names the
findings that triggered it.
"""

from __future__ import annotations

import math
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Final

from zirah.models import Confidence, Finding, Grade, Severity

MAX_SCORE: Final = 100
"""The score of a target with no findings."""

SEVERITY_WEIGHT: Final[dict[Severity, float]] = {
    Severity.CRITICAL: 40.0,
    Severity.HIGH: 20.0,
    Severity.MEDIUM: 8.0,
    Severity.LOW: 3.0,
    Severity.INFO: 1.0,
}
"""Points a finding at full confidence deducts on its own. INFO still costs a point, so that
100 always means "no findings"."""

CONFIDENCE_MULTIPLIER: Final[dict[Confidence, float]] = {
    Confidence.HIGH: 1.0,
    Confidence.MEDIUM: 0.75,
    Confidence.LOW: 0.5,
}

SAME_LOCATION_SHARE: Final = 0.1
"""Share of its weight that each finding after the heaviest one at a location adds."""

LOCATION_DECAY: Final = 0.8
"""Factor applied per rank to each further location: 1, 0.8, 0.64, ... Whatever the number of
locations, their total stays below ``1 / (1 - LOCATION_DECAY)`` = 5 times the heaviest."""

GRADE_THRESHOLDS: Final[tuple[tuple[int, Grade], ...]] = (
    (90, Grade.A),
    (75, Grade.B),
    (60, Grade.C),
    (40, Grade.D),
)
"""Lowest score for each grade, best first. Anything below the last one is an F."""


@dataclass(frozen=True, slots=True)
class CapRule:
    """The score can be at most ``limit`` when a finding with this severity and confidence
    exists."""

    severity: Severity
    confidence: Confidence
    limit: int


CAPS: Final[tuple[CapRule, ...]] = (
    CapRule(Severity.CRITICAL, Confidence.HIGH, 39),  # F
    CapRule(Severity.HIGH, Confidence.HIGH, 74),  # C at best
)

SECURITY_SEVERITY: Final[dict[Severity, str]] = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0",
    Severity.INFO: "0.0",
}
"""SARIF ``security-severity`` per severity. Each sits inside the band GitHub code scanning
uses for that severity (critical 9.0+, high 7.0-8.9, medium 4.0-6.9, low 0.1-3.9)."""

POINTS_DECIMALS: Final = 2
"""Decimal places kept for each finding's points."""


@dataclass(frozen=True, slots=True)
class Deduction:
    """What one finding cost: ``points = weight * share * decay``."""

    finding_id: str
    rule_id: str
    location: str
    weight: float
    """Severity weight times confidence multiplier."""
    share: float
    """1 for the heaviest finding at its location, ``SAME_LOCATION_SHARE`` for the others."""
    decay: float
    """``LOCATION_DECAY ** rank`` of the finding's location."""
    points: float


@dataclass(frozen=True, slots=True)
class AppliedCap:
    """A cap that lowered the score, and the findings that triggered it."""

    limit: int
    severity: Severity
    confidence: Confidence
    finding_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class Score:
    trust_score: int
    grade: Grade
    deductions: tuple[Deduction, ...]
    """One entry per finding, ordered by location rank, then by weight within a location."""
    uncapped_score: int
    """``MAX_SCORE`` minus the rounded-up deductions, before any cap."""
    cap: AppliedCap | None = None

    @property
    def total_points(self) -> float:
        return round(sum(d.points for d in self.deductions), POINTS_DECIMALS)

    @property
    def deducted_points(self) -> int:
        """``total_points`` rounded up: what is actually taken from ``MAX_SCORE``."""
        return math.ceil(self.total_points)

    def points_for(self, finding_id: str) -> float:
        """Points deducted for one finding (0 when it is not in this score)."""
        return next((d.points for d in self.deductions if d.finding_id == finding_id), 0.0)


def finding_weight(finding: Finding) -> float:
    return SEVERITY_WEIGHT[finding.severity] * CONFIDENCE_MULTIPLIER[finding.confidence]


def grade_for(trust_score: int) -> Grade:
    for threshold, grade in GRADE_THRESHOLDS:
        if trust_score >= threshold:
            return grade
    return Grade.F


def score(findings: Sequence[Finding]) -> Score:
    """Score ``findings`` (already deduplicated) and explain every deducted point."""
    by_location: dict[str, list[Finding]] = {}
    for finding in findings:
        by_location.setdefault(finding.evidence.location, []).append(finding)
    for group in by_location.values():
        group.sort(key=lambda f: (-finding_weight(f), f.id))

    def location_weight(group: list[Finding]) -> float:
        head, *rest = group
        return finding_weight(head) + SAME_LOCATION_SHARE * sum(map(finding_weight, rest))

    ranked = sorted(by_location.items(), key=lambda item: (-location_weight(item[1]), item[0]))

    deductions: list[Deduction] = []
    for rank, (location, group) in enumerate(ranked):
        decay = LOCATION_DECAY**rank
        for index, finding in enumerate(group):
            weight = finding_weight(finding)
            share = 1.0 if index == 0 else SAME_LOCATION_SHARE
            deductions.append(
                Deduction(
                    finding_id=finding.id,
                    rule_id=finding.rule_id,
                    location=location,
                    weight=weight,
                    share=share,
                    decay=decay,
                    points=round(weight * share * decay, POINTS_DECIMALS),
                )
            )

    total = round(sum(d.points for d in deductions), POINTS_DECIMALS)
    uncapped = max(0, MAX_SCORE - math.ceil(total))

    cap: AppliedCap | None = None
    for rule in CAPS:
        triggers = tuple(
            f.id
            for f in findings
            if f.severity is rule.severity and f.confidence is rule.confidence
        )
        if triggers and uncapped > rule.limit and (cap is None or rule.limit < cap.limit):
            cap = AppliedCap(rule.limit, rule.severity, rule.confidence, triggers)

    trust_score = min(uncapped, cap.limit) if cap else uncapped
    return Score(
        trust_score=trust_score,
        grade=grade_for(trust_score),
        deductions=tuple(deductions),
        uncapped_score=uncapped,
        cap=cap,
    )
