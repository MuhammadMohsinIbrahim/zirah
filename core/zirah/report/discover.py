"""Reports for ``zirah discover``: a table per client, or JSON.

Everything shown comes from local config files, which anyone on the machine (or a malicious
package) may have written, so it is escaped like manifest text. Environment and header values
never appear; only their names do.
"""

from __future__ import annotations

from rich.console import Console, Group, RenderableType
from rich.table import Table
from rich.text import Text

from zirah.discover import DiscoveredServer, Discovery
from zirah.report.common import escape_text, shorten

COMMAND_CHARS = 80
"""Longest command line or URL shown in the table."""

CLIENT_NAMES = {
    "claude-desktop": "Claude Desktop",
    "claude-code": "Claude Code",
    "cursor": "Cursor",
    "vscode": "VS Code",
    "windsurf": "Windsurf",
}


def render_json(discovery: Discovery) -> str:
    return discovery.model_dump_json(indent=2) + "\n"


def render(discovery: Discovery) -> RenderableType:
    parts: list[RenderableType] = []
    header = Text()
    header.append("Zirah discover\n", style="bold")
    count = len(discovery.servers)
    header.append(
        f"{count} MCP server{'' if count == 1 else 's'} in {len(discovery.configs_read)} "
        f"config file{'' if len(discovery.configs_read) == 1 else 's'}. Read-only: nothing was run "
        "or sent anywhere.\n"
    )
    if discovery.approved_list is None:
        header.append(
            "No approved list (~/.config/zirah/approved.yaml), so approval is not checked.\n",
            style="dim",
        )
    else:
        unapproved = len(discovery.unapproved)
        style = "bold red" if unapproved else "green"
        header.append(
            f"{unapproved} server{'' if unapproved == 1 else 's'} not on the approved list "
            f"({escape_text(discovery.approved_list)}).\n",
            style=style,
        )
    parts.append(header)

    for client, name in CLIENT_NAMES.items():
        servers = [s for s in discovery.servers if s.client == client]
        if servers:
            parts.append(_table(name, servers, discovery.approved_list is not None))

    for warning in discovery.warnings:
        parts.append(Text(f"Warning: {escape_text(warning)}", style="yellow"))
    return Group(*parts)


def print_report(discovery: Discovery, console: Console) -> None:
    console.print(render(discovery))


def _table(title: str, servers: list[DiscoveredServer], approval: bool) -> Table:
    table = Table(title=title, title_justify="left", title_style="bold", expand=False)
    table.add_column("Name")
    table.add_column("Scope")
    table.add_column("Type")
    table.add_column("Command or URL", overflow="fold")
    table.add_column("Env / headers")
    if approval:
        table.add_column("Approved")
    for server in servers:
        secrets = [*server.env_keys, *(f"{h} (header)" for h in server.header_keys)]
        row = [
            Text(escape_text(server.name)),
            Text(escape_text(server.scope)),
            Text(server.kind if server.transport == "auto" else server.transport),
            Text(shorten(escape_text(server.command_line), COMMAND_CHARS)),
            Text(escape_text(", ".join(secrets)) or "-", style="dim"),
        ]
        if approval:
            row.append(
                Text("yes", style="green") if server.approved else Text("NO", style="bold red")
            )
        table.add_row(*row)
    return table
