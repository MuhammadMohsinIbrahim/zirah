"""Markdown report, for pull request comments and READMEs.

Layout: grade and trust score, a summary table, then findings grouped by severity and by
location, and a collapsed table explaining every deducted point.

Everything from the manifest is untrusted. Snippets go in code spans after
:func:`escape_text`, so invisible characters show as ``\\u200b``-style escapes; other text is
backslash-escaped so it cannot add links, HTML, mentions or formatting.
"""

from __future__ import annotations

import re

from zirah.models import ScoreDeduction, Severity
from zirah.report.common import (
    GRADE_MEANING,
    SAME_TEXT,
    LocationGroup,
    cap_explanation,
    describe_location,
    display_snippet,
    escape_text,
    group_by_location,
    one_line,
    score_formula,
    severity_counts,
    target_label,
)
from zirah.scan import Scan
from zirah.scoring import LOCATION_DECAY, SAME_LOCATION_SHARE

_SPECIAL = re.compile(r"([\\`*_{}\[\]()<>#+!|~&@:])")
_BACKTICKS = re.compile(r"`+")


def md_text(text: str) -> str:
    """``text`` escaped for markdown: visible escapes for invisible characters, and a
    backslash before every character markdown or GitHub could act on."""
    return _SPECIAL.sub(r"\\\1", escape_text(text))


def md_code(text: str, *, in_table: bool = False) -> str:
    """``text`` as an inline code span, whatever backticks it contains."""
    span = _span(escape_text(text))
    return span.replace("|", "\\|") if in_table else span


def _span(escaped: str) -> str:
    """A code span around already escaped text: the fence is longer than any run of
    backticks inside, and padded when the text starts or ends with one."""
    longest = max((len(run) for run in _BACKTICKS.findall(escaped)), default=0)
    fence = "`" * (longest + 1)
    pad = " " if escaped.startswith("`") or escaped.endswith("`") else ""
    return f"{fence}{pad}{escaped}{pad}{fence}"


def render(scan: Scan) -> str:
    lines: list[str] = []
    result = scan.result
    lines += [
        f"## Zirah scan: grade {result.grade}, trust score {result.trust_score}/100",
        "",
        GRADE_MEANING[result.grade] if result.findings else "No findings.",
        "",
    ]
    lines += _summary(scan)

    groups = group_by_location(result.findings, scan.score)
    for severity in reversed(Severity):
        section = [g for g in groups if g.severity is severity]
        if section:
            lines += [f"### {severity.capitalize()}", ""]
            for group in section:
                lines += _location(scan, group)

    if result.findings:
        lines += _breakdown(scan)
    return "\n".join(lines).rstrip("\n") + "\n"


def _summary(scan: Scan) -> list[str]:
    result = scan.result
    manifest = scan.manifest
    if result.findings:
        where = len(group_by_location(result.findings, scan.score))
        counts = ", ".join(f"{n} {sev}" for sev, n in severity_counts(result.findings))
        found = f"{len(result.findings)} at {where} location{'' if where == 1 else 's'}: {counts}"
    else:
        found = "none"
    rows = [("Target", md_code(target_label(result.target), in_table=True))]
    server = " ".join(p for p in (manifest.server_name, manifest.server_version) if p)
    if server:
        rows.append(("Server", md_text(server)))
    rows += [
        ("Findings", found),
        ("Rule pack", f"{md_text(result.rulepack_version)}"),
        ("Engines", ", ".join(result.engines_used)),
        ("Zirah", md_text(result.zirah_version)),
    ]
    lines = ["| | |", "|---|---|", *(f"| {k} | {v} |" for k, v in rows), ""]

    cap = cap_explanation(scan.score)
    if cap:
        lines += [f"> **Score cap:** {cap}", ""]
    for failure in scan.failures:
        lines += [
            f"> **Warning:** analyzer {md_code(failure.analyzer)} failed "
            f"({md_text(failure.error)}); the scan is incomplete.",
            "",
        ]
    return lines


def _location(scan: Scan, group: LocationGroup) -> list[str]:
    lines = [
        f"#### {md_text(describe_location(group.location, scan.manifest))}",
        "",
        md_code(group.location),
        "",
    ]
    previous: str | None = None
    for finding in group.findings:
        points = scan.score.points_for(finding.id)
        lines.append(
            f"- **{finding.severity.upper()}** {md_text(finding.title)} "
            f"({md_code(finding.rule_id)}, -{points:g} pts)"
        )
        snippet = display_snippet(finding)
        evidence = md_text(SAME_TEXT) if snippet == previous else _span(snippet)
        lines.append(f"  - Evidence: {evidence}")
        previous = snippet
        lines.append(f"  - Fix: {md_text(one_line(finding.remediation))}")
    lines.append("")
    return lines


def _breakdown(scan: Scan) -> list[str]:
    score = scan.score
    share = f"{SAME_LOCATION_SHARE:.0%}"
    lines = [
        "<details>",
        "<summary>How the trust score was computed</summary>",
        "",
        "Each finding's weight is its severity weight times its confidence multiplier. At one "
        f"location the heaviest finding counts in full and each other one adds {share} of its "
        f"weight (share). Locations are ranked heaviest first and each further one counts "
        f"{LOCATION_DECAY:g} times the one before (decay).",
        "",
        "| Finding | Rule | Location | Weight | Share | Decay | Points |",
        "|---|---|---|---:|---:|---:|---:|",
        *(_breakdown_row(d) for d in score.deductions),
        f"| | | | | | **Total** | **{score.total_points:g}** |",
        "",
        f"Trust score: {score_formula(score)}"
        + (" by " + ", ".join(md_code(i) for i in score.cap.finding_ids) if score.cap else "")
        + ".",
        "",
        "</details>",
    ]
    return lines


def _breakdown_row(d: ScoreDeduction) -> str:
    cells = [
        md_code(d.finding_id, in_table=True),
        md_code(d.rule_id, in_table=True),
        md_code(d.location, in_table=True),
        f"{d.weight:g}",
        f"{d.share:g}",
        f"{d.decay:.3g}",
        f"{d.points:g}",
    ]
    return "| " + " | ".join(cells) + " |"
