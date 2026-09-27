from __future__ import annotations

import math

import pytest

from zirah.models import Confidence, Engine, Evidence, Finding, Grade, Module, Owasp, Severity
from zirah.scoring import (
    CONFIDENCE_MULTIPLIER,
    GRADE_THRESHOLDS,
    LOCATION_DECAY,
    MAX_SCORE,
    SAME_LOCATION_SHARE,
    SEVERITY_WEIGHT,
    finding_weight,
    grade_for,
    score,
)

C, H, M, L, INF = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
)
HI, MED, LO = Confidence.HIGH, Confidence.MEDIUM, Confidence.LOW


def finding(
    severity: Severity, confidence: Confidence, location: str, rule: str = "D1-TEST"
) -> Finding:
    return Finding(
        module=Module.D1,
        rule_id=rule,
        severity=severity,
        confidence=confidence,
        owasp=(Owasp.MCP03,),
        title="Test finding",
        evidence=Evidence(location=location, snippet=f"{severity} {confidence}"),
        remediation="Fix it.",
        engine=Engine.STATIC,
    )


def spread(*specs: tuple[Severity, Confidence]) -> list[Finding]:
    """One finding per spec, each at its own location."""
    return [finding(sev, conf, f"/tools/{i}/description") for i, (sev, conf) in enumerate(specs)]


def same_place(*specs: tuple[Severity, Confidence]) -> list[Finding]:
    """One finding per spec, all at one location (different rules)."""
    return [
        finding(sev, conf, "/tools/0/description", rule=f"D1-RULE-{i}")
        for i, (sev, conf) in enumerate(specs)
    ]


def test_no_findings_is_100_and_grade_a() -> None:
    result = score([])
    assert (result.trust_score, result.grade) == (MAX_SCORE, Grade.A)
    assert result.deductions == ()
    assert result.cap is None
    assert result.total_points == 0


def test_every_severity_and_confidence_has_a_positive_weight() -> None:
    assert set(SEVERITY_WEIGHT) == set(Severity)
    assert set(CONFIDENCE_MULTIPLIER) == set(Confidence)
    assert all(weight > 0 for weight in SEVERITY_WEIGHT.values())
    assert all(multiplier > 0 for multiplier in CONFIDENCE_MULTIPLIER.values())


def test_any_finding_costs_at_least_one_point() -> None:
    assert score(spread((INF, LO))).trust_score == MAX_SCORE - 1


def test_weight_is_severity_times_confidence() -> None:
    (f,) = spread((C, MED))
    assert finding_weight(f) == SEVERITY_WEIGHT[C] * CONFIDENCE_MULTIPLIER[MED]


# --- Grades ----------------------------------------------------------------------------------


def test_grade_thresholds_match_the_spec() -> None:
    assert GRADE_THRESHOLDS == ((90, Grade.A), (75, Grade.B), (60, Grade.C), (40, Grade.D))


@pytest.mark.parametrize(
    ("trust_score", "grade"),
    [
        (100, Grade.A),
        (90, Grade.A),
        (89, Grade.B),
        (75, Grade.B),
        (74, Grade.C),
        (60, Grade.C),
        (59, Grade.D),
        (40, Grade.D),
        (39, Grade.F),
        (0, Grade.F),
    ],
)
def test_grade_boundaries(trust_score: int, grade: Grade) -> None:
    assert grade_for(trust_score) is grade


@pytest.mark.parametrize(
    ("findings", "trust_score", "grade"),
    [
        # 10 points
        (spread((H, LO)), 90, Grade.A),
        # 10 + 0.5*0.8 = 10.4, rounded up to 11
        (spread((H, LO), (INF, LO)), 89, Grade.B),
        # 20 + 6*0.8 = 24.8 -> 25
        (spread((C, LO), (M, MED)), 75, Grade.B),
        # 24.8 + 1*0.64 = 25.44 -> 26
        (spread((C, LO), (M, MED), (INF, HI)), 74, Grade.C),
        # 20 + 20*0.8 + 6*0.64 = 39.84 -> 40
        (spread((C, LO), (C, LO), (M, MED)), 60, Grade.C),
        # 39.84 + 0.5*0.512 (0.26) = 40.1 -> 41
        (spread((C, LO), (C, LO), (M, MED), (INF, LO)), 59, Grade.D),
        # 30 + 30*0.8 + 6*0.64 + 3*0.512 (1.54) = 59.38 -> 60
        (spread((C, MED), (C, MED), (M, MED), (L, HI)), 40, Grade.D),
        # 59.38 + 3*0.4096 (1.23) = 60.61 -> 61
        (spread((C, MED), (C, MED), (M, MED), (L, HI), (L, HI)), 39, Grade.F),
    ],
    ids=["90", "89", "75", "74", "60", "59", "40", "39"],
)
def test_boundary_scores_from_findings(
    findings: list[Finding], trust_score: int, grade: Grade
) -> None:
    result = score(findings)
    assert result.cap is None
    assert (result.trust_score, result.grade) == (trust_score, grade)


# --- Caps ------------------------------------------------------------------------------------


def test_critical_high_confidence_caps_at_39() -> None:
    findings = spread((C, HI))
    result = score(findings)
    assert result.uncapped_score == 60
    assert (result.trust_score, result.grade) == (39, Grade.F)
    assert result.cap is not None
    assert (result.cap.limit, result.cap.severity, result.cap.confidence) == (39, C, HI)
    assert result.cap.finding_ids == (findings[0].id,)


def test_high_high_confidence_caps_at_74() -> None:
    findings = spread((H, HI))
    result = score(findings)
    assert result.uncapped_score == 80
    assert (result.trust_score, result.grade) == (74, Grade.C)
    assert result.cap is not None
    assert result.cap.finding_ids == (findings[0].id,)


def test_lowest_cap_wins_and_names_its_findings() -> None:
    high, critical = same_place((H, HI), (C, HI))
    result = score([high, critical])
    assert result.uncapped_score == 58  # 40 + 0.1 * 20
    assert result.cap is not None
    assert (result.cap.limit, result.cap.finding_ids) == (39, (critical.id,))
    assert (result.trust_score, result.grade) == (39, Grade.F)


def test_cap_lists_every_triggering_finding() -> None:
    findings = same_place((C, HI), (L, LO), (C, HI))
    result = score(findings)
    assert result.cap is not None
    assert set(result.cap.finding_ids) == {findings[0].id, findings[2].id}


def test_cap_is_not_reported_when_the_score_is_already_lower() -> None:
    result = score(spread((C, HI), (C, HI), (C, HI)))
    assert result.uncapped_score < 39
    assert result.cap is None
    assert result.trust_score == result.uncapped_score


@pytest.mark.parametrize(
    "spec", [(C, MED), (C, LO), (H, MED), (H, LO), (M, HI)], ids=lambda s: f"{s[0]}-{s[1]}"
)
def test_lower_confidence_or_severity_is_not_capped(spec: tuple[Severity, Confidence]) -> None:
    result = score(spread(spec))
    assert result.cap is None


# --- Grouping and diminishing returns ---------------------------------------------------------


def test_same_location_counts_the_heaviest_in_full_and_the_rest_as_a_bonus() -> None:
    findings = same_place((H, MED), (C, MED), (M, HI))
    result = score(findings)
    by_rule = {d.rule_id: d for d in result.deductions}
    assert by_rule["D1-RULE-1"].share == 1.0
    assert by_rule["D1-RULE-0"].share == SAME_LOCATION_SHARE
    assert by_rule["D1-RULE-2"].share == SAME_LOCATION_SHARE
    assert result.total_points == pytest.approx(30 + SAME_LOCATION_SHARE * (15 + 8))


def test_three_findings_on_one_location_deduct_far_less_than_on_three() -> None:
    specs = [(H, MED), (H, MED), (H, MED)]
    grouped = score(same_place(*specs))
    separate = score(spread(*specs))
    # 15 + 1.5 + 1.5 = 18 against 15 + 12 + 9.6 = 36.6
    assert grouped.total_points == pytest.approx(18)
    assert separate.total_points == pytest.approx(36.6)
    assert grouped.total_points < separate.total_points / 2
    assert grouped.trust_score > separate.trust_score


def test_twenty_low_findings_do_not_outweigh_one_critical() -> None:
    lows = score(spread(*[(L, HI)] * 20))
    critical = score(spread((C, LO)))  # the weakest critical, and uncapped
    assert lows.total_points < critical.total_points
    assert lows.trust_score > critical.trust_score


def test_locations_decay_heaviest_first() -> None:
    findings = spread((L, HI), (C, MED), (M, HI))
    result = score(findings)
    assert [d.decay for d in result.deductions] == [1.0, LOCATION_DECAY, LOCATION_DECAY**2]
    assert [d.weight for d in result.deductions] == [30.0, 8.0, 3.0]


def test_ties_are_ordered_by_location_so_scores_are_deterministic() -> None:
    findings = spread((H, MED), (H, MED))
    assert score(findings) == score(list(reversed(findings)))
    assert [d.location for d in score(findings).deductions] == [
        "/tools/0/description",
        "/tools/1/description",
    ]


# --- Explainability -------------------------------------------------------------------------


@pytest.mark.parametrize(
    "findings",
    [
        spread((C, MED), (H, LO), (M, MED), (L, HI), (INF, LO)),
        same_place((C, MED), (H, LO)) + spread((M, MED), (L, HI)),
        spread(*[(L, MED)] * 12),
    ],
    ids=["mixed", "grouped", "many-lows"],
)
def test_every_deducted_point_traces_to_a_finding(findings: list[Finding]) -> None:
    result = score(findings)
    assert sorted(d.finding_id for d in result.deductions) == sorted(f.id for f in findings)
    for d in result.deductions:
        assert d.points == pytest.approx(d.weight * d.share * d.decay, abs=0.005)
        assert result.points_for(d.finding_id) == d.points
    assert result.total_points == pytest.approx(sum(d.points for d in result.deductions))
    assert result.uncapped_score == MAX_SCORE - math.ceil(result.total_points)
    assert result.trust_score == result.uncapped_score


def test_points_for_unknown_finding_is_zero() -> None:
    assert score([]).points_for("0" * 16) == 0.0


def test_score_never_goes_below_zero() -> None:
    result = score(spread(*[(C, MED)] * 30))
    assert result.uncapped_score == 0
    assert result.trust_score == 0
