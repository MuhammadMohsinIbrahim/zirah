"""The ``zirah`` command line.

Exit codes of ``zirah scan``:

- 0: no findings at or above ``--fail-on`` (default ``high``; ``none`` never fails)
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
from zirah.discover import discover
from zirah.llm import LlmError, resolve
from zirah.loaders import LoaderError
from zirah.loaders.stdio import EXEC_WARNING
from zirah.models import Severity, TargetKind
from zirah.report import discover as discover_report
from zirah.report import json as json_report
from zirah.report import markdown, sarif, terminal
from zirah.scan import Scan, ScanError, scan, target_kind

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


class HttpTransport(StrEnum):
    AUTO = "auto"
    STREAMABLE_HTTP = "streamable-http"
    SSE = "sse"


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
    target: Annotated[
        str,
        typer.Argument(
            help="Manifest JSON file, server URL, or stdio server command (needs --allow-exec).",
            show_default=False,
        ),
    ],
    args: Annotated[
        list[str] | None,
        typer.Argument(
            help="Arguments for a stdio server command. Put -- before ones that start with -.",
            show_default=False,
        ),
    ] = None,
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
    ] = FailOn.HIGH,
    llm: Annotated[
        str | None,
        typer.Option(
            "--llm",
            help=(
                "LLM judge: none (default, offline), ollama, openai or anthropic, each with an "
                "optional :model. Env: ZIRAH_LLM."
            ),
            show_default=False,
        ),
    ] = None,
    transport: Annotated[
        HttpTransport,
        typer.Option("--transport", help="HTTP transport for URL targets."),
    ] = HttpTransport.AUTO,
    allow_exec: Annotated[
        bool,
        typer.Option(
            "--allow-exec",
            help="Run a stdio server on this machine to read its manifest (no isolation).",
        ),
    ] = False,
) -> None:
    """Scan a target and print a report with its grade, trust score and findings.

    Exit codes: 0 no findings at or above --fail-on, 1 findings at or above --fail-on,
    2 usage, load or scan error.
    """
    _safe_stdout()
    stderr = Console(stderr=True, highlight=False, soft_wrap=True)
    try:
        client = resolve(llm)
        server_args = tuple(args or ())
        if allow_exec and target_kind(target, server_args) is TargetKind.STDIO:
            stderr.print(f"Warning: {EXEC_WARNING}", style="bold red", markup=False)
        outcome = scan(
            target, server_args, allow_exec=allow_exec, transport=transport.value, llm=client
        )
    except (LoaderError, ScanError, LlmError) as exc:
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


class DiscoverFormat(StrEnum):
    TERMINAL = "terminal"
    JSON = "json"


@app.command("discover")
def discover_command(
    output_format: Annotated[
        DiscoverFormat, typer.Option("--format", "-f", help="Report format.")
    ] = DiscoverFormat.TERMINAL,
    approved: Annotated[
        Path | None,
        typer.Option(
            "--approved",
            help="Approved servers (default ~/.config/zirah/approved.yaml, env ZIRAH_APPROVED).",
            show_default=False,
        ),
    ] = None,
) -> None:
    """List the MCP servers configured in Claude Desktop, Claude Code, Cursor, VS Code and
    Windsurf on this machine. Read-only and offline; nothing is run or uploaded.

    Exit codes: 0 done, 1 servers missing from the approved list (only when a list exists).
    """
    _safe_stdout()
    found = discover(cwd=Path.cwd(), approved_path=approved)
    if output_format is DiscoverFormat.JSON:
        sys.stdout.write(discover_report.render_json(found))
    else:
        discover_report.print_report(found, Console(highlight=False))
    raise typer.Exit(EXIT_FINDINGS if found.unapproved else EXIT_CLEAN)


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
