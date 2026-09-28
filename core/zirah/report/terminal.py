"""Terminal report: grade and trust score first, then findings grouped by severity.

Findings at the same location are shown together under one location heading. All text from
the manifest goes through :func:`escape_text` and is added as plain ``Text`` (never rich
markup), so a manifest cannot inject styles, links or terminal escapes.
"""

from __future__ import annotations

import io

from rich.console import Console, Group, RenderableType
from rich.padding import Padding
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

from zirah.models import Grade, Severity
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
)
from zirah.scan import Scan

REPORT_WIDTH = 100
"""Width used when the report is written to a file."""

SEVERITY_STYLE: dict[Severity, str] = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "bold yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}

GRADE_STYLE: dict[Grade, str] = {
    Grade.A: "bold white on green",
    Grade.B: "bold black on bright_green",
    Grade.C: "bold black on yellow",
    Grade.D: "bold white on dark_orange",
    Grade.F: "bold white on red",
}


def render(scan: Scan) -> RenderableType:
    """The whole report as one rich renderable."""
    parts: list[RenderableType] = [_header(scan)]
    groups = group_by_location(scan.result.findings, scan.score)
    for severity in reversed(Severity):
        section = [g for g in groups if g.severity is severity]
        if not section:
            continue
        parts.append(Rule(Text(severity.upper(), style=SEVERITY_STYLE[severity]), align="left"))
        parts.extend(_location(scan, group) for group in section)
    parts.append(_footer(scan))
    return Group(*parts)


def print_report(scan: Scan, console: Console) -> None:
    console.print(render(scan))


def plain_text(scan: Scan, width: int = REPORT_WIDTH) -> str:
    """The report without colors, e.g. for ``--output report.txt``."""
    buffer = io.StringIO()
    console = Console(file=buffer, width=width, color_system=None, highlight=False)
    print_report(scan, console)
    return "".join(line.rstrip() + "\n" for line in buffer.getvalue().splitlines())


def _header(scan: Scan) -> RenderableType:
    result = scan.result
    lines = Text()
    lines.append("Zirah scan report\n", style="bold")
    lines.append("Target  ", style="dim")
    lines.append(escape_text(result.target.location) + "\n")
    if scan.manifest.server_name or scan.manifest.server_version:
        server = " ".join(
            escape_text(part)
            for part in (scan.manifest.server_name, scan.manifest.server_version)
            if part
        )
        lines.append("Server  ", style="dim")
        lines.append(server + "\n")
    lines.append("\n")
    lines.append(f" Grade {result.grade} ", style=GRADE_STYLE[result.grade])
    lines.append("  Trust score ", style="bold")
    lines.append(f"{result.trust_score}/100\n", style="bold")
    if result.findings:
        lines.append(GRADE_MEANING[result.grade] + "\n")

    cap = cap_explanation(scan.score)
    if cap:
        lines.append(cap + "\n", style="bold")

    findings = result.findings
    if findings:
        groups = group_by_location(findings, scan.score)
        counts = ", ".join(f"{n} {sev}" for sev, n in severity_counts(findings))
        where = f"{len(groups)} location" + ("" if len(groups) == 1 else "s")
        noun = "finding" if len(findings) == 1 else "findings"
        lines.append(f"{len(findings)} {noun} at {where}: {counts}\n")
    else:
        lines.append("No findings.\n")

    for failure in scan.failures:
        lines.append(
            f"Warning: analyzer {failure.analyzer} failed ({escape_text(failure.error)}); "
            "the scan is incomplete.\n",
            style="bold yellow",
        )
    return lines


def _location(scan: Scan, group: LocationGroup) -> RenderableType:
    heading = Text()
    heading.append(describe_location(group.location, scan.manifest), style="bold")
    heading.append(f"  {escape_text(group.location)}", style="dim")

    rows = Table.grid(padding=(0, 2))
    rows.add_column(width=8, no_wrap=True)
    rows.add_column(ratio=1)
    previous: str | None = None
    for finding in group.findings:
        body = Text()
        body.append(escape_text(finding.title) + "\n", style="bold")
        points = scan.score.points_for(finding.id)
        body.append(f"{finding.rule_id} · -{points:g} pts\n", style="dim")
        snippet = display_snippet(finding)
        if snippet == previous:  # rules matching the same text show it once
            body.append(SAME_TEXT + "\n", style="dim")
        else:
            body.append(snippet + "\n", style="italic")
        previous = snippet
        body.append("Fix: ", style="green")
        body.append(one_line(escape_text(finding.remediation)))
        rows.add_row(Text(finding.severity.upper(), style=SEVERITY_STYLE[finding.severity]), body)
    return Group(heading, Padding(rows, (0, 0, 1, 2)))


def _footer(scan: Scan) -> RenderableType:
    result = scan.result
    engines = ", ".join(result.engines_used)
    text = Text(style="dim")
    if result.findings:
        text.append(
            f"Score: {score_formula(scan.score)}. Findings at one location count mostly once.\n"
        )
    text.append(
        f"Rule pack {result.rulepack_version} · engines: {engines} · zirah {result.zirah_version}"
    )
    return text
