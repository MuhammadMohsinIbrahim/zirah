"""Reports for ``zirah scan --all``: one summary table, or the ``ScanSession`` as JSON."""

from __future__ import annotations

import io

from rich.console import Console, Group, RenderableType
from rich.table import Table
from rich.text import Text

from zirah.report.common import escape_text, severity_counts, shorten
from zirah.report.discover import CLIENT_NAMES, COMMAND_CHARS
from zirah.report.terminal import GRADE_STYLE, REPORT_WIDTH, SEVERITY_STYLE
from zirah.scan import SessionEntry, SessionScan

STATUS_STYLE = {"scanned": "", "skipped": "yellow", "failed": "bold red", "duplicate": "dim"}


def render_json(run: SessionScan) -> str:
    return run.session.model_dump_json(indent=2) + "\n"


def render(run: SessionScan) -> RenderableType:
    counts = {status: 0 for status in STATUS_STYLE}
    for entry in run.entries:
        counts[entry.status] += 1
    header = Text()
    header.append("Zirah scan --all\n", style="bold")
    header.append(
        f"{len(run.entries)} configured servers: {counts['scanned']} scanned, "
        f"{counts['skipped']} skipped, {counts['failed']} failed, "
        f"{counts['duplicate']} duplicates.\n"
    )
    table = Table(expand=False)
    for column in ("Client", "Server", "Command or URL", "Result", "Findings"):
        table.add_column(column, overflow="fold")
    for entry in run.entries:
        table.add_row(*_row(entry))
    notes = [
        Text(
            f"{entry.server.client}/{escape_text(entry.server.name)}: {escape_text(entry.message)}",
            style=STATUS_STYLE[entry.status] or "dim",
        )
        for entry in run.entries
        if entry.status == "failed"
    ]
    return Group(header, table, *notes)


def print_report(run: SessionScan, console: Console) -> None:
    console.print(render(run))


def plain_text(run: SessionScan, width: int = REPORT_WIDTH) -> str:
    buffer = io.StringIO()
    print_report(run, Console(file=buffer, width=width, color_system=None, highlight=False))
    return "".join(line.rstrip() + "\n" for line in buffer.getvalue().splitlines())


def _row(entry: SessionEntry) -> list[Text]:
    server = entry.server
    cells = [
        Text(CLIENT_NAMES.get(server.client, server.client)),
        Text(escape_text(server.name)),
        Text(shorten(escape_text(server.command_line), COMMAND_CHARS)),
    ]
    if entry.scan is None:
        cells.append(Text(entry.status, style=STATUS_STYLE[entry.status]))
        cells.append(Text(shorten(escape_text(entry.message), COMMAND_CHARS), style="dim"))
        return cells
    result = entry.scan.result
    verdict = Text()
    verdict.append(f" {result.grade} ", style=GRADE_STYLE[result.grade])
    verdict.append(f" {result.trust_score}/100")
    if not entry.scan.complete:
        verdict.append(" (incomplete)", style="yellow")
    findings = Text()
    for i, (severity, count) in enumerate(severity_counts(result.findings)):
        findings.append(", " if i else "")
        findings.append(f"{count} {severity}", style=SEVERITY_STYLE[severity])
    cells += [verdict, findings if result.findings else Text("none", style="dim")]
    return cells
