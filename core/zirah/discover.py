"""D14 shadow MCP discovery: find the MCP servers configured on this machine.

Reads the MCP configs of Claude Desktop, Claude Code, Cursor, VS Code and Windsurf (user and
project level, Windows, macOS and Linux paths), lists every server, and marks servers that are
not on the user's approved list (``~/.config/zirah/approved.yaml``).

Read-only and offline: nothing is executed, nothing is sent anywhere, and there is no upload
path. Secrets stay out of the output: environment and header *values* are never shown (only
their names), and arguments and URLs go through the D4 secret redaction.
"""

from __future__ import annotations

import json
import os
import re
import sys
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field

from zirah.analyzers.common import redact_target
from zirah.models import Module, Target, TargetKind
from zirah.rulepack import Rule, load_rulepack

Client = Literal["claude-desktop", "claude-code", "cursor", "vscode", "windsurf"]
Platform = Literal["windows", "macos", "linux"]
HttpTransport = Literal["auto", "streamable-http", "sse"]

MAX_CONFIG_BYTES: Final = 5 * 1024 * 1024
"""Larger config files are skipped with a warning."""
APPROVED_ENV: Final = "ZIRAH_APPROVED"
"""Overrides the approved-list path."""


def default_approved_path(home: Path) -> Path:
    return home / ".config" / "zirah" / "approved.yaml"


def current_platform() -> Platform:
    if sys.platform == "win32":
        return "windows"
    if sys.platform == "darwin":
        return "macos"
    return "linux"


# --- Model ---------------------------------------------------------------------------------------


class DiscoveredServer(BaseModel):
    """One configured MCP server. ``env`` holds the configured environment for running it and
    is never serialized or shown; ``env_keys`` lists the variable names."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    client: Client
    scope: str
    """``user``, or ``project:<path>`` for per-project configs."""
    config_path: str
    name: str
    kind: Literal["stdio", "http"]
    command: str | None = None
    args: tuple[str, ...] = ()
    url: str | None = None
    transport: HttpTransport = "auto"
    env_keys: tuple[str, ...] = ()
    header_keys: tuple[str, ...] = ()
    approved: bool | None = None
    """``None`` when there is no approved list."""
    env: dict[str, str] = Field(default_factory=dict, exclude=True, repr=False)
    raw_args: tuple[str, ...] = Field(default=(), exclude=True, repr=False)
    """The arguments as configured (``args`` is the redacted copy for display)."""
    raw_url: str | None = Field(default=None, exclude=True, repr=False)
    """The URL as configured (``url`` is the redacted copy for display)."""

    def target(self) -> Target:
        """The target to scan, with the configured (unredacted) URL or arguments. Scan
        results redact it again before anything is shown."""
        if self.kind == "http":
            return Target(
                kind=TargetKind.HTTP, location=self.raw_url or self.url or "?", name=self.name
            )
        return Target(
            kind=TargetKind.STDIO,
            location=self.command or "?",
            args=self.raw_args or self.args,
            name=self.name,
        )

    @property
    def command_line(self) -> str:
        if self.kind == "http":
            return self.url or ""
        parts = [self.command or "", *self.args]
        return " ".join(f'"{p}"' if not p or " " in p else p for p in parts)


class Discovery(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    servers: tuple[DiscoveredServer, ...] = ()
    configs_read: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()
    approved_list: str | None = None
    """Path of the approved list used, if one was found."""

    @property
    def unapproved(self) -> tuple[DiscoveredServer, ...]:
        return tuple(s for s in self.servers if s.approved is False)


# --- Where configs live ------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ConfigLocation:
    client: Client
    path: Path
    scope: str
    layout: Literal["mcpServers", "servers", "vscode-settings", "claude-code-user"]


def config_locations(
    home: Path, platform: Platform, cwd: Path | None = None, appdata: Path | None = None
) -> list[ConfigLocation]:
    """Every config file the five clients may use on ``platform``, user level first."""
    if platform == "windows":
        roaming = appdata or home / "AppData" / "Roaming"
        claude_desktop = roaming / "Claude" / "claude_desktop_config.json"
        vscode_user = roaming / "Code" / "User"
    elif platform == "macos":
        support = home / "Library" / "Application Support"
        claude_desktop = support / "Claude" / "claude_desktop_config.json"
        vscode_user = support / "Code" / "User"
    else:
        config = home / ".config"
        claude_desktop = config / "Claude" / "claude_desktop_config.json"
        vscode_user = config / "Code" / "User"

    locations = [
        ConfigLocation("claude-desktop", claude_desktop, "user", "mcpServers"),
        ConfigLocation("claude-code", home / ".claude.json", "user", "claude-code-user"),
        ConfigLocation("cursor", home / ".cursor" / "mcp.json", "user", "mcpServers"),
        ConfigLocation("vscode", vscode_user / "mcp.json", "user", "servers"),
        ConfigLocation("vscode", vscode_user / "settings.json", "user", "vscode-settings"),
        ConfigLocation(
            "windsurf", home / ".codeium" / "windsurf" / "mcp_config.json", "user", "mcpServers"
        ),
    ]
    if cwd is not None:
        project = f"project:{cwd}"
        locations += [
            ConfigLocation("claude-code", cwd / ".mcp.json", project, "mcpServers"),
            ConfigLocation("cursor", cwd / ".cursor" / "mcp.json", project, "mcpServers"),
            ConfigLocation("vscode", cwd / ".vscode" / "mcp.json", project, "servers"),
        ]
    return locations


# --- Discovery ---------------------------------------------------------------------------------


def discover(
    *,
    home: Path | None = None,
    cwd: Path | None = None,
    platform: Platform | None = None,
    appdata: Path | None = None,
    approved_path: Path | None = None,
    env: Mapping[str, str] | None = None,
) -> Discovery:
    """Find configured MCP servers. Every argument defaults to this machine; tests pass fakes."""
    env = os.environ if env is None else env
    home = home or Path.home()
    platform = platform or current_platform()
    if appdata is None and platform == "windows" and env.get("APPDATA"):
        appdata = Path(env["APPDATA"])
    secret_rules = load_rulepack().for_module(Module.D4)

    servers: list[DiscoveredServer] = []
    read: list[str] = []
    warnings: list[str] = []
    for location in config_locations(home, platform, cwd, appdata):
        data = _read_config(location.path, warnings)
        if data is None:
            continue
        read.append(str(location.path))
        for scope, name, raw in _entries(location, data):
            server = _server(location, scope, name, raw, secret_rules, warnings)
            if server is not None:
                servers.append(server)

    approved_file = approved_path or Path(env.get(APPROVED_ENV) or default_approved_path(home))
    approved = _read_approved(approved_file, warnings)
    if approved is not None:
        servers = [
            s.model_copy(update={"approved": any(_matches(s, entry) for entry in approved)})
            for s in servers
        ]
    return Discovery(
        servers=tuple(servers),
        configs_read=tuple(read),
        warnings=tuple(warnings),
        approved_list=str(approved_file) if approved is not None else None,
    )


def _read_config(path: Path, warnings: list[str]) -> Any:
    try:
        if not path.is_file():
            return None
        size = path.stat().st_size
        if size > MAX_CONFIG_BYTES:
            warnings.append(f"{path}: skipped, {size} bytes is over {MAX_CONFIG_BYTES}")
            return None
        text = path.read_bytes().decode("utf-8-sig")
    except (OSError, UnicodeDecodeError) as exc:
        warnings.append(f"{path}: cannot read ({type(exc).__name__})")
        return None
    try:
        return json.loads(strip_jsonc(text))
    except ValueError as exc:
        warnings.append(f"{path}: not valid JSON ({exc})")
        return None


def _entries(location: ConfigLocation, data: Any) -> Iterator[tuple[str, str, Any]]:
    """``(scope, name, raw entry)`` for every server in one config file."""
    if not isinstance(data, dict):
        return
    if location.layout == "claude-code-user":
        yield from _named(location.scope, data.get("mcpServers"))
        projects = data.get("projects")
        if isinstance(projects, dict):
            for project, settings in projects.items():
                if isinstance(settings, dict):
                    yield from _named(f"project:{project}", settings.get("mcpServers"))
    elif location.layout == "mcpServers":
        yield from _named(location.scope, data.get("mcpServers"))
    elif location.layout == "servers":
        yield from _named(location.scope, data.get("servers"))
    else:  # VS Code settings.json: "mcp": {"servers": {...}}
        mcp = data.get("mcp")
        if isinstance(mcp, dict):
            yield from _named(location.scope, mcp.get("servers"))


def _named(scope: str, servers: Any) -> Iterator[tuple[str, str, Any]]:
    if isinstance(servers, dict):
        for name, raw in servers.items():
            yield scope, str(name), raw


def _server(
    location: ConfigLocation,
    scope: str,
    name: str,
    raw: Any,
    secret_rules: Sequence[Rule],
    warnings: list[str],
) -> DiscoveredServer | None:
    where = f"{location.path}: server {name!r}"
    if not isinstance(raw, dict):
        warnings.append(f"{where}: not an object, skipped")
        return None
    declared = str(raw.get("type") or raw.get("transport") or "").lower()
    url = raw.get("url") or raw.get("serverUrl") or raw.get("httpUrl")
    command = raw.get("command")
    env = _mapping(raw.get("env"))
    headers = _mapping(raw.get("headers"))
    common: dict[str, Any] = {
        "client": location.client,
        "scope": scope,
        "config_path": str(location.path),
        "name": name,
        "env_keys": tuple(sorted(str(k) for k in env)),
        "header_keys": tuple(sorted(str(k) for k in headers)),
        "env": {str(k): str(v) for k, v in env.items() if isinstance(v, str | int | float)},
    }
    if isinstance(url, str) and url and not command:
        transport: HttpTransport = "auto"
        if declared == "sse":
            transport = "sse"
        elif declared in ("http", "streamable-http", "streamablehttp"):
            transport = "streamable-http"
        target = redact_target(Target(kind=TargetKind.HTTP, location=url), secret_rules)
        return DiscoveredServer(
            kind="http", url=target.location, raw_url=url, transport=transport, **common
        )
    if isinstance(command, str) and command:
        raw_args = raw.get("args")
        args: list[Any] = raw_args if isinstance(raw_args, list) else []
        configured = tuple(str(a) for a in args)
        target = redact_target(
            Target(kind=TargetKind.STDIO, location=command, args=configured), secret_rules
        )
        return DiscoveredServer(
            kind="stdio", command=target.location, args=target.args, raw_args=configured, **common
        )
    warnings.append(f"{where}: no command or url, skipped")
    return None


def _mapping(value: Any) -> dict[Any, Any]:
    return value if isinstance(value, dict) else {}


# --- Approved list -------------------------------------------------------------------------------


def _read_approved(path: Path, warnings: list[str]) -> list[dict[str, str]] | None:
    """Entries of the approved list, or ``None`` when there is no list.

    Format::

        servers:
          - name: github                                  # every given key must match
          - command: npx -y @modelcontextprotocol/server-filesystem
          - url: https://mcp.example.com/mcp
    """
    if not path.is_file():
        return None
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
        warnings.append(f"{path}: cannot read the approved list ({type(exc).__name__})")
        return None
    entries = data.get("servers") if isinstance(data, dict) else None
    if not isinstance(entries, list):
        warnings.append(f"{path}: expected a 'servers' list")
        return None
    approved = []
    for entry in entries:
        if (
            isinstance(entry, dict)
            and entry
            and all(k in ("name", "command", "url", "client") for k in entry)
        ):
            approved.append({str(k): str(v) for k, v in entry.items()})
        else:
            warnings.append(f"{path}: ignored entry {entry!r}; use name, command, url or client")
    return approved


def _matches(server: DiscoveredServer, entry: Mapping[str, str]) -> bool:
    actual = {
        "name": server.name,
        "client": server.client,
        "command": server.command_line if server.kind == "stdio" else None,
        "url": server.url,
    }
    return all(actual.get(key) == value for key, value in entry.items())


# --- JSONC -----------------------------------------------------------------------------------


_STRING: Final = r'"(?:\\.|[^"\\])*"'
_JSONC_COMMENT = re.compile(_STRING + r"|//[^\n]*|/\*.*?\*/", re.DOTALL)
_JSONC_COMMA = re.compile(_STRING + r"|,(?=\s*[}\]])")


def strip_jsonc(text: str) -> str:
    """``text`` without ``//`` and ``/* */`` comments and trailing commas (VS Code settings),
    leaving strings untouched."""
    return _JSONC_COMMA.sub(_keep_strings, _JSONC_COMMENT.sub(_keep_strings, text))


def _keep_strings(match: re.Match[str]) -> str:
    """Keep a matched JSON string; drop a matched comment or trailing comma."""
    return match.group(0) if match.group(0).startswith('"') else ""
