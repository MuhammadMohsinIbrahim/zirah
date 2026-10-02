"""D14 discover against fake homes built from fixture configs. Nothing real is read or run."""

from __future__ import annotations

import json
import shutil
import socket
import subprocess
import sys
from pathlib import Path
from typing import Any

import httpx
import pytest
from rich.console import Console
from typer.testing import CliRunner

from zirah import discover as discover_mod
from zirah.cli import EXIT_CLEAN, EXIT_FINDINGS, app
from zirah.discover import Discovery, Platform, config_locations, discover, strip_jsonc
from zirah.models import TargetKind
from zirah.report import discover as report

FIXTURES = Path(__file__).parent / "fixtures" / "discover"
SECRETS = [
    "ghp_ZirahFakeDesktopToken7f3a9c1e2b4d6",
    "zirah_fake_4f9c2e71b8d3a605",
    "zirah_fake_bearer_5e8a1c7d2f9b0346",
    "zirah_fake_weather_91c3",
]


def build_home(tmp_path: Path, platform: Platform) -> tuple[Path, Path, Path]:
    """A fake home and project with every fixture config where ``platform`` keeps it."""
    home, project, appdata = tmp_path / "home", tmp_path / "project", tmp_path / "roaming"
    by_client = {loc.path: loc for loc in config_locations(home, platform, project, appdata)}
    sources = {
        "claude-desktop": "claude_desktop_config.json",
        "claude-code-user": "claude.json",
        "cursor-user": "cursor_mcp.json",
        "vscode-mcp": "vscode_mcp.json",
        "vscode-settings": "vscode_settings.json",
        "windsurf": "windsurf_mcp_config.json",
        "claude-code-project": "project_mcp.json",
        "vscode-project": "workspace_vscode_mcp.json",
    }
    for path, loc in by_client.items():
        key = {
            ("claude-desktop", "user"): "claude-desktop",
            ("claude-code", "user"): "claude-code-user",
            ("cursor", "user"): "cursor-user",
            ("windsurf", "user"): "windsurf",
            ("claude-code", "project"): "claude-code-project",
            ("vscode", "project"): "vscode-project",
        }.get((loc.client, loc.scope.split(":")[0]))
        if loc.client == "vscode" and loc.scope == "user":
            key = "vscode-settings" if path.name == "settings.json" else "vscode-mcp"
        if key is None:
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(FIXTURES / sources[key], path)
    return home, project, appdata


def found(discovery: Discovery) -> list[tuple[str, str, str, str]]:
    return sorted((s.client, s.scope.split(":")[0], s.name, s.kind) for s in discovery.servers)


EXPECTED = [
    ("claude-code", "project", "db", "http"),
    ("claude-code", "project", "project-tools", "stdio"),
    ("claude-code", "user", "notes", "stdio"),
    ("claude-code", "user", "remote-docs", "http"),
    ("claude-desktop", "user", "filesystem", "stdio"),
    ("claude-desktop", "user", "github", "stdio"),
    ("cursor", "user", "linear", "http"),
    ("cursor", "user", "weather", "stdio"),
    ("vscode", "project", "ws-local", "stdio"),
    ("vscode", "user", "fetch", "stdio"),
    ("vscode", "user", "search", "http"),
    ("vscode", "user", "time", "stdio"),
    ("windsurf", "user", "remote", "http"),
    ("windsurf", "user", "sequential", "stdio"),
]


@pytest.mark.parametrize("platform", ["windows", "macos", "linux"])
def test_all_five_clients_parse_on_every_platform(tmp_path: Path, platform: Platform) -> None:
    home, project, appdata = build_home(tmp_path, platform)
    result = discover(home=home, cwd=project, platform=platform, appdata=appdata, env={})
    assert found(result) == EXPECTED
    assert len(result.configs_read) == 8
    assert result.warnings == (
        f"{home / '.cursor' / 'mcp.json'}: server 'broken': no command or url, skipped",
    )
    assert result.approved_list is None
    assert all(s.approved is None for s in result.servers)


def test_platform_paths() -> None:
    home, appdata = Path("/h"), Path("/r")
    paths = {
        str(loc.path).replace("\\", "/") for loc in config_locations(home, "windows", None, appdata)
    }
    assert "/r/Claude/claude_desktop_config.json" in paths
    assert "/r/Code/User/mcp.json" in paths
    mac = {str(loc.path).replace("\\", "/") for loc in config_locations(home, "macos")}
    assert "/h/Library/Application Support/Claude/claude_desktop_config.json" in mac
    linux = {str(loc.path).replace("\\", "/") for loc in config_locations(home, "linux")}
    assert "/h/.config/Code/User/settings.json" in linux
    assert "/h/.codeium/windsurf/mcp_config.json" in linux


def test_details_are_read(tmp_path: Path) -> None:
    home, project, _ = build_home(tmp_path, "linux")
    servers = {
        s.name: s for s in discover(home=home, cwd=project, platform="linux", env={}).servers
    }
    assert servers["time"].args == ("mcp-server-time", "--tz=UTC")  # from JSONC settings
    assert servers["db"].transport == "sse"
    assert servers["db"].scope == "project:/home/me/app"
    assert servers["remote-docs"].transport == "streamable-http"
    assert servers["remote-docs"].header_keys == ("Authorization",)
    assert servers["github"].env_keys == ("GITHUB_TOKEN",)
    assert servers["github"].env == {"GITHUB_TOKEN": SECRETS[0]}  # kept to run it, never shown
    assert servers["remote"].url == "https://windsurf.example.invalid/mcp"
    target = servers["notes"].target()
    assert (target.kind, target.location) == (TargetKind.STDIO, "python")
    assert servers["linear"].target().kind is TargetKind.HTTP


def test_secrets_never_reach_the_output(tmp_path: Path) -> None:
    home, project, _ = build_home(tmp_path, "linux")
    result = discover(home=home, cwd=project, platform="linux", env={})
    buffer = Console(record=True, width=200)
    report.print_report(result, buffer)
    outputs = [buffer.export_text(), report.render_json(result), repr(result)]
    for output in outputs:
        for secret in SECRETS:
            assert secret not in output
    data = json.loads(report.render_json(result))
    notes = next(s for s in data["servers"] if s["name"] == "notes")
    assert notes["args"][-1].endswith("****")
    assert "env" not in notes
    db = next(s for s in data["servers"] if s["name"] == "db")
    assert "api_key=zira****" in db["url"]


def test_approved_list(tmp_path: Path) -> None:
    home, project, _ = build_home(tmp_path, "linux")
    approved = tmp_path / "approved.yaml"
    approved.write_text(
        "servers:\n"
        "  - name: filesystem\n"
        "  - client: vscode\n"
        "  - url: https://windsurf.example.invalid/mcp\n"
        "  - command: npx -y @example/sequential-thinking\n"
        "  - bogus: 1\n",
        encoding="utf-8",
    )
    result = discover(home=home, cwd=project, platform="linux", approved_path=approved, env={})
    status = {s.name: s.approved for s in result.servers}
    assert status["filesystem"] is True
    assert status["fetch"] is True  # every vscode server
    assert status["time"] is True
    assert status["remote"] is True
    assert status["sequential"] is True
    assert status["github"] is False
    assert status["notes"] is False
    assert result.approved_list == str(approved)
    assert any("ignored entry" in w for w in result.warnings)
    buffer = Console(record=True, width=200)
    report.print_report(result, buffer)
    text = buffer.export_text()
    assert "not on the approved list" in text
    assert "NO" in text


def test_approved_list_from_env_and_bad_lists(tmp_path: Path) -> None:
    home, _, _ = build_home(tmp_path, "linux")
    bad = tmp_path / "bad.yaml"
    bad.write_text("servers: nope\n", encoding="utf-8")
    result = discover(home=home, platform="linux", env={"ZIRAH_APPROVED": str(bad)})
    assert result.approved_list is None
    assert any("expected a 'servers' list" in w for w in result.warnings)
    bad.write_text("servers: [\n", encoding="utf-8")
    result = discover(home=home, platform="linux", env={"ZIRAH_APPROVED": str(bad)})
    assert any("cannot read the approved list" in w for w in result.warnings)


def test_bad_configs_are_warnings_not_failures(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    (home / ".cursor").mkdir(parents=True)
    (home / ".cursor" / "mcp.json").write_text("{not json", encoding="utf-8")
    (home / ".codeium" / "windsurf").mkdir(parents=True)
    (home / ".codeium" / "windsurf" / "mcp_config.json").write_text(
        json.dumps({"mcpServers": {"x": "not an object", "y": {"command": "a"}}}), encoding="utf-8"
    )
    (home / ".claude.json").write_text("[1, 2]", encoding="utf-8")
    (home / ".config" / "Claude").mkdir(parents=True)
    (home / ".config" / "Claude" / "claude_desktop_config.json").write_text(
        " " * 150 + "{}", encoding="utf-8"
    )
    monkeypatch.setattr(discover_mod, "MAX_CONFIG_BYTES", 100)
    result = discover(home=home, platform="linux", env={})
    assert [s.name for s in result.servers] == ["y"]
    joined = "\n".join(result.warnings)
    assert "not valid JSON" in joined
    assert "over 100" in joined
    assert "not an object, skipped" in joined


def test_strip_jsonc_keeps_strings() -> None:
    text = '{"a": "http://x//y", "b": "/* no */", /* c */ "d": [1,], // e\n}'
    assert json.loads(strip_jsonc(text)) == {"a": "http://x//y", "b": "/* no */", "d": [1]}


def test_names_cannot_inject_markup(tmp_path: Path) -> None:
    home = tmp_path / "home"
    (home / ".cursor").mkdir(parents=True)
    (home / ".cursor" / "mcp.json").write_text(
        json.dumps({"mcpServers": {"[red]x[/]\u001b[2J": {"command": "a"}}}), encoding="utf-8"
    )
    buffer = Console(record=True, width=200)
    report.print_report(discover(home=home, platform="linux", env={}), buffer)
    text = buffer.export_text()
    assert "[red]x[/]\\u001b[2J" in text


# --- CLI: offline and read-only ------------------------------------------------------------------


def test_cli_discover_makes_no_network_calls_and_runs_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    platform = discover_mod.current_platform()
    home, project, appdata = build_home(tmp_path, platform)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    monkeypatch.setenv("APPDATA", str(appdata))
    monkeypatch.delenv("ZIRAH_APPROVED", raising=False)
    monkeypatch.chdir(project)

    def forbidden(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("discover must not touch the network or run anything")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(httpx.Client, "send", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)

    result = CliRunner().invoke(app, ["discover", "--format", "json"])
    assert result.exit_code == EXIT_CLEAN, result.output
    data = json.loads(result.stdout)
    assert len(data["servers"]) == len(EXPECTED)
    for secret in SECRETS:
        assert secret not in result.stdout

    approved = tmp_path / "approved.yaml"
    approved.write_text("servers:\n  - name: filesystem\n", encoding="utf-8")
    result = CliRunner().invoke(app, ["discover", "--approved", str(approved)])
    assert result.exit_code == EXIT_FINDINGS
    assert "13 servers not on the approved list" in " ".join(result.stdout.split())


def test_cli_discover_with_nothing_configured(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    monkeypatch.setenv("APPDATA", str(tmp_path / "roaming"))
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(app, ["discover"])
    assert result.exit_code == EXIT_CLEAN
    assert "0 MCP servers in 0 config files" in result.stdout


def test_current_platform() -> None:
    expected = {"win32": "windows", "darwin": "macos"}.get(sys.platform, "linux")
    assert discover_mod.current_platform() == expected


@pytest.mark.parametrize(
    ("value", "expected"), [("win32", "windows"), ("darwin", "macos"), ("linux", "linux")]
)
def test_current_platform_for_each_system(
    monkeypatch: pytest.MonkeyPatch, value: str, expected: Platform
) -> None:
    monkeypatch.setattr(sys, "platform", value)
    assert discover_mod.current_platform() == expected


def test_windows_reads_claude_desktop_from_appdata(tmp_path: Path) -> None:
    roaming = tmp_path / "roaming"
    (roaming / "Claude").mkdir(parents=True)
    config = {"mcpServers": {"notes": {"command": "notes-server"}}}
    (roaming / "Claude" / "claude_desktop_config.json").write_text(
        json.dumps(config), encoding="utf-8"
    )
    result = discover(home=tmp_path / "home", platform="windows", env={"APPDATA": str(roaming)})
    assert [(s.client, s.name) for s in result.servers] == [("claude-desktop", "notes")]


def test_unreadable_config_is_a_warning(tmp_path: Path) -> None:
    home = tmp_path / "home"
    (home / ".cursor").mkdir(parents=True)
    (home / ".cursor" / "mcp.json").write_bytes(b'{"mcpServers": {"\xff\xfe": {}}}')
    result = discover(home=home, platform="linux", env={})
    assert result.servers == ()
    assert any("cannot read (UnicodeDecodeError)" in w for w in result.warnings)
