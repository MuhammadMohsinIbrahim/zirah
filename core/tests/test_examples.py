"""The demo servers in ``examples/`` give the results ``examples/README.md`` documents."""

from __future__ import annotations

import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from zirah.loaders import load_static
from zirah.loaders.stdio import load_stdio
from zirah.models import Module
from zirah.scan import scan

EXAMPLES = Path(__file__).resolve().parents[2] / "examples"
MALICIOUS = EXAMPLES / "malicious"
BENIGN = EXAMPLES / "benign"
pytestmark = pytest.mark.repo_checkout  # examples/ is not in the sdist
ROW = re.compile(r"^\| `(/[^`]*)` \| `(D\d+-[A-Z0-9-]+)` \|", re.MULTILINE)


def documented_findings() -> list[tuple[str, str]]:
    readme = (EXAMPLES / "README.md").read_text(encoding="utf-8")
    return sorted((rule, location) for location, rule in ROW.findall(readme))


def demo_server() -> ModuleType:
    spec = importlib.util.spec_from_file_location("demo_server", EXAMPLES / "demo_server.py")
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_malicious_demo_gives_exactly_the_documented_findings() -> None:
    result = scan(str(MALICIOUS / "manifest.json")).result
    found = sorted((f.rule_id, f.evidence.location) for f in result.findings)
    assert found == documented_findings()
    assert {f.module for f in result.findings} == {Module.D1, Module.D2, Module.D3, Module.D4}
    assert (result.grade, result.trust_score) == ("F", 0)


def test_benign_demo_is_clean() -> None:
    result = scan(str(BENIGN / "manifest.json")).result
    assert result.findings == ()
    assert (result.grade, result.trust_score) == ("A", 100)


@pytest.mark.parametrize("demo", [MALICIOUS, BENIGN], ids=["malicious", "benign"])
def test_stdio_server_serves_the_static_manifest(demo: Path) -> None:
    live = load_stdio(sys.executable, [str(demo / "server.py")], allow_exec=True).manifest
    assert live == load_static(demo / "manifest.json").manifest


def test_demo_tools_do_nothing() -> None:
    server = demo_server()
    manifest: dict[str, Any] = {"tools": []}
    called = server.handle(manifest, "tools/call", {"name": "send_email", "arguments": {}})
    assert called["result"]["isError"] is True
    assert server.handle(manifest, "prompts/get", {})["error"]["code"] == -32601
    assert server.handle(manifest, "ping", {}) == {"result": {}}
    init = server.handle(manifest, "initialize", {"protocolVersion": "2099-01-01"})
    assert init["result"]["protocolVersion"] == "2025-11-25"
    assert init["result"]["capabilities"] == {"tools": {}}


def test_demo_server_skips_noise_and_answers_requests() -> None:
    lines = [
        "not json",
        json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        json.dumps({"jsonrpc": "2.0", "id": 7, "method": "tools/list", "params": None}),
    ]
    done = subprocess.run(  # noqa: S603 - our own demo server
        [sys.executable, str(BENIGN / "server.py")],
        input="\n".join(lines) + "\n",
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=30,
        check=True,
    )
    (reply,) = [json.loads(line) for line in done.stdout.splitlines()]
    assert reply["id"] == 7
    assert [tool["name"] for tool in reply["result"]["tools"]] == [
        "add_note",
        "search_notes",
        "delete_note",
    ]


def test_demo_server_needs_a_manifest_argument() -> None:
    done = subprocess.run(  # noqa: S603 - our own demo server
        [sys.executable, str(EXAMPLES / "demo_server.py")],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=30,
        check=False,
    )
    assert done.returncode == 1
    assert "usage" in done.stderr


def test_demos_are_harmless() -> None:
    for path in EXAMPLES.rglob("*.json"):
        text = path.read_text(encoding="utf-8")
        hosts = re.findall(r"https?://(?:[^@/\s\"]*@)?([^/\s\":]+)", text)
        hosts += re.findall(r"[\w.+-]+@([\w-]+(?:\.[\w-]+)+)", text)
        assert all(host.endswith("example.invalid") for host in hosts), (path, hosts)
        secrets = re.findall(r"(?:pw|key|token|secret)\w*\s*[=:]\s*(\w+)", text, re.IGNORECASE)
        assert all(value.startswith("zirah_fake_") for value in secrets), (path, secrets)
