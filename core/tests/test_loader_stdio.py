"""The stdio loader against an in-repo fake server (standard library only, harmless)."""

from __future__ import annotations

import ctypes
import os
import sys
import time
from pathlib import Path

import pytest
from conftest import flat, squashed
from typer.testing import CliRunner

from zirah.cli import EXIT_ERROR, EXIT_FINDINGS, app
from zirah.loaders import LoaderError, mcp_client
from zirah.loaders.stdio import EXEC_WARNING, load_stdio
from zirah.models import TargetKind
from zirah.scan import scan, target_kind

SERVER = str(Path(__file__).parent / "fixtures" / "servers" / "fake_mcp_server.py")
PYTHON = sys.executable


def load(
    *flags: str,
    request_timeout: float = mcp_client.REQUEST_TIMEOUT_S,
    total_timeout: float = mcp_client.TOTAL_TIMEOUT_S,
) -> tuple[str, ...]:
    loaded = load_stdio(
        PYTHON,
        [SERVER, *flags],
        allow_exec=True,
        request_timeout=request_timeout,
        total_timeout=total_timeout,
    )
    return tuple(tool.name for tool in loaded.manifest.tools)


@pytest.fixture
def fast_probe(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(mcp_client, "DISCOVER_TIMEOUT_S", 0.3)


def pid_alive(pid: int) -> bool:
    if sys.platform == "win32":
        handle = ctypes.windll.kernel32.OpenProcess(0x1000, False, pid)  # QUERY_LIMITED_INFO
        if not handle:
            return False
        code = ctypes.c_ulong()
        ctypes.windll.kernel32.GetExitCodeProcess(handle, ctypes.byref(code))
        ctypes.windll.kernel32.CloseHandle(handle)
        return code.value == 259  # STILL_ACTIVE
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    status = Path(f"/proc/{pid}/status")
    return not (status.exists() and "\nState:\tZ" in status.read_text(encoding="utf-8"))


def wait_dead(pid: int, seconds: float = 5.0) -> bool:
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if not pid_alive(pid):
            return True
        time.sleep(0.1)
    return False


# --- Safety ------------------------------------------------------------------------------------


def test_refuses_without_allow_exec_and_shows_the_warning() -> None:
    with pytest.raises(LoaderError) as info:
        load_stdio(PYTHON, [SERVER])
    assert EXEC_WARNING in str(info.value)
    assert "--allow-exec" in str(info.value)


def test_the_whole_process_tree_is_gone_afterwards(tmp_path: Path) -> None:
    pidfile = tmp_path / "pids"
    load("--child", str(pidfile))
    server_pid, child_pid = map(int, pidfile.read_text(encoding="utf-8").split())
    assert wait_dead(server_pid)
    assert wait_dead(child_pid)


def test_a_hanging_server_is_killed_after_the_timeout(tmp_path: Path, fast_probe: None) -> None:
    pidfile = tmp_path / "pids"
    start = time.monotonic()
    with pytest.raises(LoaderError, match=r"no response to initialize within 0\.5 s"):
        load("--hang", "--child", str(pidfile), request_timeout=0.5)
    assert time.monotonic() - start < 10
    server_pid, child_pid = map(int, pidfile.read_text(encoding="utf-8").split())
    assert wait_dead(server_pid)
    assert wait_dead(child_pid)


def test_total_timeout(fast_probe: None) -> None:
    with pytest.raises(LoaderError, match=r"gave up after 0\.6 s in total"):
        load("--hang", total_timeout=0.6)


# --- Protocol --------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "flags",
    [
        (),
        ("--version", "2024-11-05"),
        ("--version", "2025-03-26"),
        ("--version", "2025-11-25"),
        ("--era", "modern"),
    ],
)
def test_reads_the_manifest_in_every_supported_era(flags: tuple[str, ...]) -> None:
    loaded = load_stdio(PYTHON, [SERVER, *flags], allow_exec=True)
    manifest = loaded.manifest
    assert (manifest.server_name, manifest.server_version) == ("fake-server", "9.9.9")
    assert manifest.instructions == "Fake server for Zirah tests."
    assert [t.name for t in manifest.tools] == ["add", "tool_1", "tool_2"]
    assert [p.name for p in manifest.prompts] == ["greet"]
    assert [r.uri for r in manifest.resources] == ["file:///readme.md"]
    assert loaded.target.kind is TargetKind.STDIO
    assert (loaded.target.location, loaded.target.args) == (PYTHON, (SERVER, *flags))


@pytest.mark.parametrize("version", ["2024-10-07", "1999-01-01"])
def test_unsupported_protocol_versions_fail_clearly(version: str) -> None:
    with pytest.raises(LoaderError, match=f"unsupported MCP protocol version \\({version}\\)"):
        load("--version", version)


def test_pagination_is_followed() -> None:
    assert load("--tools", "5", "--page-size", "2") == (
        "add",
        "tool_1",
        "tool_2",
        "tool_3",
        "tool_4",
    )


def test_non_string_cursor_is_rejected() -> None:
    with pytest.raises(LoaderError, match="non-string nextCursor"):
        load("--tools", "5", "--page-size", "2", "--bad-cursor")


def test_item_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(mcp_client, "MAX_ITEMS", 3)
    with pytest.raises(LoaderError, match="more than 3 tools; refusing"):
        load("--tools", "5")


def test_page_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(mcp_client, "MAX_PAGES", 2)
    with pytest.raises(LoaderError, match="more than 2 pages"):
        load("--tools", "5", "--page-size", "1")


def test_message_size_limit() -> None:
    with pytest.raises(LoaderError, match="larger than"):
        load("--flood")


def test_server_exit_is_reported_with_its_stderr() -> None:
    with pytest.raises(LoaderError, match=r"exit code 3.*fatal: fake server gave up"):
        load("--exit")


def test_noise_and_server_requests_are_tolerated() -> None:
    assert load("--noisy") == ("add", "tool_1", "tool_2")


def test_a_result_that_is_not_an_object_is_rejected() -> None:
    with pytest.raises(LoaderError, match="returned no result object"):
        load("--no-result")


def test_unknown_command() -> None:
    with pytest.raises(LoaderError, match="command not found"):
        load_stdio("zirah-no-such-command-4c8e1a", allow_exec=True)


# --- Scan and CLI ------------------------------------------------------------------------------


def test_target_kind() -> None:
    assert target_kind(SERVER) is TargetKind.STATIC  # an existing file
    assert target_kind("missing.json") is TargetKind.STATIC
    assert target_kind(PYTHON, [SERVER]) is TargetKind.STDIO
    assert target_kind("npx") is TargetKind.STDIO
    assert target_kind("https://example.invalid/mcp") is TargetKind.HTTP


def test_secrets_in_arguments_are_redacted_in_the_result() -> None:
    token = "ghp_" + "Zf7a9c1e2b4d6" * 3
    result = scan(PYTHON, [SERVER, "--token", token], allow_exec=True).result
    assert token not in squashed(result.model_dump_json())
    assert result.target.args[-1].endswith("****")
    assert any(
        f.rule_id == "D4-GITHUB-TOKEN" and f.evidence.location == "target:/args"
        for f in result.findings
    )


def test_cli_refuses_without_the_flag() -> None:
    result = CliRunner().invoke(app, ["scan", PYTHON, SERVER])
    assert result.exit_code == EXIT_ERROR
    assert EXEC_WARNING in flat(result.stderr)


def test_cli_runs_with_the_flag_and_prints_the_warning() -> None:
    result = CliRunner().invoke(
        app, ["scan", "--allow-exec", PYTHON, SERVER, "--", "--era", "modern"]
    )
    assert result.exit_code == EXIT_FINDINGS
    assert result.stderr.startswith(f"Warning: {EXEC_WARNING}")
    assert "fake-server 9.9.9" in result.stdout
    assert "--era modern" in flat(result.stdout)  # the target line may wrap
