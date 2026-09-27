"""The ``zirah`` command line.

Exit codes of ``zirah scan``:

- 0: no findings at or above ``--fail-on``
- 1: at least one finding at or above ``--fail-on``
- 2: usage error, the target could not be loaded, the report could not be written, or an
  analyzer failed (the scan is incomplete, so it cannot be called clean)
"""

from __future__ import annotations

import io
import sys
from collections.abc import Callable
from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from zirah import __version__
from zirah.loaders import LoaderError
from zirah.models import Severity
from zirah.report import json as json_report
from zirah.report import markdown, sarif, terminal
from zirah.scan import Scan, ScanError, scan

EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2

app = typer.Typer(
    name="zirah",
    help="Offline-first security scanner for MCP servers.",
    no_args_is_help=True,
    add_completion=False,
    # Tracebacks with local variables could print secrets from the scanned manifest.
    pretty_exceptions_enable=False,
)


class OutputFormat(StrEnum):
    TERMINAL = "terminal"
    JSON = "json"
    SARIF = "sarif"
    MARKDOWN = "markdown"


class FailOn(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    NONE = "none"


def _version(value: bool) -> None:
    if value:
        typer.echo(f"zirah {__version__}")
        raise typer.Exit(EXIT_CLEAN)


@app.callback()
def main(
    version: Annotated[
        bool,
        typer.Option("--version", callback=_version, is_eager=True, help="Show the version."),
    ] = False,
) -> None:
    """Zirah finds tool poisoning, prompt injection, tool shadowing and leaked secrets in MCP
    server manifests."""


@app.command("scan")
def scan_command(
    target: Annotated[str, typer.Argument(help="MCP manifest JSON file to scan.")],
    output_format: Annotated[
        OutputFormat, typer.Option("--format", "-f", help="Report format.")
    ] = OutputFormat.TERMINAL,
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Write the report to this file instead of stdout."),
    ] = None,
    fail_on: Annotated[
        FailOn,
        typer.Option(
            "--fail-on",
            help="Exit with 1 when a finding has this severity or higher ('none': never).",
        ),
    ] = FailOn.INFO,
) -> None:
    """Scan a target and print a report with its grade, trust score and findings.

    Exit codes: 0 no findings at or above --fail-on, 1 findings at or above --fail-on,
    2 usage, load or scan error.
    """
    _safe_stdout()
    stderr = Console(stderr=True, highlight=False, soft_wrap=True)
    try:
        outcome = scan(target)
    except (LoaderError, ScanError) as exc:
        stderr.print(f"error: {exc}", markup=False)
        raise typer.Exit(EXIT_ERROR) from None

    if output is None:
        _print(outcome, output_format)
    else:
        text = RENDERERS[output_format](outcome)
        try:
            output.write_text(text, encoding="utf-8", newline="\n")
        except OSError as exc:
            stderr.print(f"error: cannot write {output}: {exc.strerror}", markup=False)
            raise typer.Exit(EXIT_ERROR) from None
        result = outcome.result
        stderr.print(
            f"Grade {result.grade}, trust score {result.trust_score}/100, "
            f"{len(result.findings)} findings. {output_format} report written to {output}",
            markup=False,
        )

    for failure in outcome.failures:
        stderr.print(f"warning: analyzer {failure.analyzer} failed: {failure.error}", markup=False)
    raise typer.Exit(exit_code(outcome, fail_on))


def exit_code(outcome: Scan, fail_on: FailOn) -> int:
    if not outcome.complete:
        return EXIT_ERROR
    if fail_on is FailOn.NONE:
        return EXIT_CLEAN
    threshold = Severity(fail_on.value).rank
    failing = any(f.severity.rank >= threshold for f in outcome.result.findings)
    return EXIT_FINDINGS if failing else EXIT_CLEAN


RENDERERS: dict[OutputFormat, Callable[[Scan], str]] = {
    OutputFormat.TERMINAL: terminal.plain_text,
    OutputFormat.JSON: json_report.render,
    OutputFormat.SARIF: sarif.render,
    OutputFormat.MARKDOWN: markdown.render,
}
"""Each format as text; the terminal format is only used this way for ``--output``."""


def _print(outcome: Scan, output_format: OutputFormat) -> None:
    if output_format is OutputFormat.TERMINAL:
        terminal.print_report(outcome, Console(highlight=False))
    else:
        sys.stdout.write(RENDERERS[output_format](outcome))


def _safe_stdout() -> None:
    """Never crash on a character the console encoding lacks (e.g. CJK text in a cp1252
    console): write an escape for it instead."""
    for stream in (sys.stdout, sys.stderr):
        encoding = (getattr(stream, "encoding", None) or "").lower().replace("-", "")
        if encoding != "utf8" and isinstance(stream, io.TextIOWrapper):
            stream.reconfigure(errors="backslashreplace")
