"""``scan --all``: every discovered server into one ScanSession. Fake servers only."""

from __future__ import annotations

import json
import sys
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from zirah import scan as scan_mod
from zirah.analyzers.base import Analyzer, ScanContext
from zirah.analyzers.d1_tool_poisoning import ToolPoisoning
from zirah.cli import EXIT_CLEAN, EXIT_ERROR, EXIT_FINDINGS, app
from zirah.discover import DiscoveredServer
from zirah.loaders.stdio import EXEC_WARNING
from zirah.models import Engine, Finding, Manifest, Module, ScanSession
from zirah.scan import scan_all

SERVER = str(Path(__file__).parent / "fixtures" / "servers" / "fake_mcp_server.py")
TOKEN = "ghp_" + "Zf7a9c1e2b4d6" * 3


class JsonMcp(BaseHTTPRequestHandler):
    """A tiny Streamable HTTP MCP server (2025 era) with one clean tool."""

    def log_message(self, *args: Any) -> None:
        pass

    def do_POST(self) -> None:
        message = json.loads(self.rfile.read(int(self.headers["content-length"])))
        if "id" not in message:
            self.send_response(202)
            self.end_headers()
            return
        method = message["method"]
        if method == "initialize":
            result: dict[str, Any] = {
                "protocolVersion": "2025-11-25",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "remote-clean", "version": "1"},
            }
            body = {"jsonrpc": "2.0", "id": message["id"], "result": result}
        elif method == "tools/list":
            tools = [{"name": "time", "description": "Returns the time.", "inputSchema": {}}]
            body = {"jsonrpc": "2.0", "id": message["id"], "result": {"tools": tools}}
        else:
            body = {
                "jsonrpc": "2.0",
                "id": message["id"],
                "error": {"code": -32601, "message": "x"},
            }
        data = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


@pytest.fixture
def remote() -> Iterator[str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), JsonMcp)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_address[1]}/mcp"
    server.shutdown()
    server.server_close()


def stdio(name: str, client: str = "cursor", *extra: str, **env: str) -> DiscoveredServer:
    args = (SERVER, *extra)
    return DiscoveredServer(
        client=client,  # type: ignore[arg-type]
        scope="user",
        config_path="x",
        name=name,
        kind="stdio",
        command=sys.executable,
        args=args,
        raw_args=args,
        env=env,
    )


def http(name: str, url: str) -> DiscoveredServer:
    return DiscoveredServer(
        client="vscode", scope="user", config_path="x", name=name, kind="http", url=url, raw_url=url
    )


def test_stdio_is_skipped_without_allow_exec(remote: str) -> None:
    run = scan_all([stdio("local"), http("remote", remote)])
    assert [(e.server.name, e.status) for e in run.entries] == [
        ("local", "skipped"),
        ("remote", "scanned"),
    ]
    assert "--allow-exec" in run.entries[0].message
    assert [r.target.location for r in run.session.results] == [remote]


def test_everything_runs_with_allow_exec_and_duplicates_are_scanned_once(remote: str) -> None:
    servers = [
        stdio("local", "cursor", "--echo-env", "ZIRAH_TEST_KEY", ZIRAH_TEST_KEY="x"),
        stdio("same", "claude-desktop", "--echo-env", "ZIRAH_TEST_KEY"),
        http("remote", remote),
        http("down", "http://127.0.0.1:9/mcp"),
    ]
    servers[1] = servers[1].model_copy(
        update={"args": servers[0].args, "raw_args": servers[0].raw_args}
    )
    run = scan_all(servers, allow_exec=True)
    statuses = [(e.server.name, e.status) for e in run.entries]
    assert statuses == [
        ("local", "scanned"),
        ("same", "duplicate"),
        ("remote", "scanned"),
        ("down", "failed"),
    ]
    assert "same server as cursor/local" in run.entries[1].message
    assert "cannot connect" in run.entries[3].message
    local = run.entries[0].scan
    assert local is not None
    assert local.manifest.instructions == "Fake server for Zirah tests. ZIRAH_TEST_KEY is set."
    session = ScanSession.model_validate_json(run.session.model_dump_json())
    assert len(session.results) == 2


def test_configured_arguments_run_but_results_are_redacted() -> None:
    run = scan_all([stdio("tokened", "cursor", "--token", TOKEN)], allow_exec=True)
    (entry,) = run.entries
    assert entry.status == "scanned"
    assert TOKEN not in run.session.model_dump_json()


# --- CLI -----------------------------------------------------------------------------------------


@pytest.fixture
def fake_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, remote: str) -> Path:
    home = tmp_path / "home"
    (home / ".cursor").mkdir(parents=True)
    config = {
        "mcpServers": {
            "local": {"command": sys.executable, "args": [SERVER]},
            "remote": {"url": remote},
        }
    }
    (home / ".cursor" / "mcp.json").write_text(json.dumps(config), encoding="utf-8")
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    monkeypatch.setenv("APPDATA", str(tmp_path / "roaming"))
    monkeypatch.delenv("ZIRAH_APPROVED", raising=False)
    monkeypatch.chdir(tmp_path)
    return home


def test_cli_scan_all_json_is_one_session(fake_home: Path) -> None:
    result = CliRunner().invoke(app, ["scan", "--all", "--format", "json"])
    assert result.exit_code == EXIT_CLEAN, result.output  # only the clean remote ran
    session = ScanSession.model_validate_json(result.stdout)
    assert len(session.results) == 1
    assert "1 stdio server(s) skipped" in result.stderr


def test_cli_scan_all_with_allow_exec_shows_a_summary_table(fake_home: Path) -> None:
    result = CliRunner().invoke(app, ["scan", "--all", "--allow-exec", "--fail-on", "high"])
    assert result.exit_code == EXIT_FINDINGS
    assert result.stderr.startswith(f"Warning: {EXEC_WARNING}")
    out = " ".join(result.stdout.split())
    assert "2 configured servers: 2 scanned, 0 skipped, 0 failed, 0 duplicates." in out
    assert "critical" in out
    assert "none" in out  # the clean remote server


def test_cli_scan_all_output_file(fake_home: Path, tmp_path: Path) -> None:
    target = tmp_path / "session.txt"
    result = CliRunner().invoke(app, ["scan", "--all", "-o", str(target)])
    assert result.exit_code == EXIT_CLEAN
    assert "Zirah scan --all" in target.read_text(encoding="utf-8")


@pytest.mark.parametrize(
    ("args", "message"),
    [
        (["scan", "--all", "x.json"], "either a TARGET or --all"),
        (["scan"], "missing TARGET"),
        (["scan", "--all", "--format", "sarif"], "--all supports --format terminal or json"),
    ],
)
def test_cli_scan_all_usage(args: list[str], message: str, fake_home: Path) -> None:
    result = CliRunner().invoke(app, args)
    assert result.exit_code == EXIT_ERROR
    assert message in result.stderr


def test_cli_scan_all_output_file_not_writable(fake_home: Path, tmp_path: Path) -> None:
    result = CliRunner().invoke(app, ["scan", "--all", "-o", str(tmp_path)])  # a directory
    assert result.exit_code == EXIT_ERROR
    assert "error: cannot write" in result.stderr


class Crashing(Analyzer):
    name = "test-crashing"
    module = Module.D2
    engine = Engine.STATIC

    def analyze(self, manifest: Manifest, ctx: ScanContext) -> list[Finding]:
        raise RuntimeError("boom")


def test_cli_scan_all_with_an_incomplete_scan_exits_2(
    fake_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(scan_mod, "discover_analyzers", lambda: [Crashing, ToolPoisoning])
    result = CliRunner().invoke(app, ["scan", "--all", "--fail-on", "none"])
    assert result.exit_code == EXIT_ERROR
    assert "(incomplete)" in " ".join(result.stdout.split())
