"""Conformance: our in-house MCP client must read exactly what the official SDK reads.

Each test starts a small real server built with the SDK (``fixtures/servers/sdk_server.py``),
lists it once with the SDK's own client and once with Zirah's loader, and compares the two
manifests. The SDK is a dev dependency only. Where it cannot be imported (for example when
Windows Application Control blocks one of its compiled dependencies) these tests are skipped
with that reason; on the Ubuntu CI runner they always run.
"""

from __future__ import annotations

import contextlib
import socket
import subprocess
import sys
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import pytest

from zirah.loaders import mcp_client, parse_manifest
from zirah.loaders.http import load_http
from zirah.loaders.stdio import kill_process_tree, load_stdio
from zirah.models import Manifest

try:
    import anyio
    from mcp import Client, StdioServerParameters
    from mcp.client.sse import sse_client
except Exception as exc:  # pragma: no cover - depends on the machine
    if sys.platform.startswith("linux"):
        raise  # never skip on the CI runner
    pytest.skip(f"official mcp SDK cannot be imported here: {exc}", allow_module_level=True)

SERVER = str(Path(__file__).parent / "fixtures" / "servers" / "sdk_server.py")


async def _all(method: Any, key: str) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    cursor: str | None = None
    while True:
        page = await method(cursor=cursor)
        data = page.model_dump(by_alias=True, mode="json", exclude_none=True)
        items += data[key]
        cursor = data.get("nextCursor")
        if not cursor:
            return items


async def sdk_manifest(server: Any) -> Manifest:
    """The manifest as the official SDK client sees it."""
    async with Client(server) as client:
        data: dict[str, Any] = {
            "tools": await _all(client.list_tools, "tools"),
            "prompts": await _all(client.list_prompts, "prompts"),
            "resources": await _all(client.list_resources, "resources"),
        }
        if client.instructions is not None:
            data["instructions"] = client.instructions
        if client.server_info is not None:
            data["serverInfo"] = {
                "name": client.server_info.name,
                "version": client.server_info.version,
            }
    return parse_manifest(data, "sdk")


def test_stdio_manifest_matches_the_sdk() -> None:
    ours = load_stdio(sys.executable, [SERVER], allow_exec=True).manifest
    theirs = anyio.run(sdk_manifest, StdioServerParameters(command=sys.executable, args=[SERVER]))
    assert ours == theirs
    assert ours.server_name == "sdk-conformance"
    assert [t.name for t in ours.tools] == ["add", "echo"]
    assert ours.tools[0].input_schema["properties"]["a"]["type"] == "integer"


def test_stdio_manifest_matches_the_sdk_on_the_initialize_handshake(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Skip the server/discover probe so our client takes the 2025-era initialize path.
    monkeypatch.setattr(mcp_client._Session, "negotiate", mcp_client._Session._initialize)
    ours = load_stdio(sys.executable, [SERVER], allow_exec=True).manifest
    params = StdioServerParameters(command=sys.executable, args=[SERVER])
    theirs = anyio.run(sdk_manifest, params)
    assert ours == theirs


def test_stdio_manifest_matches_the_sdk_on_protocol_2024_11_05(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Offer only 2024-11-05 in initialize; the SDK server must accept it and list as usual.
    monkeypatch.setattr(mcp_client._Session, "negotiate", mcp_client._Session._initialize)
    monkeypatch.setattr(mcp_client, "HANDSHAKE_VERSIONS", ("2024-11-05",))
    sent: list[str] = []
    original = mcp_client._Session._call

    def spy(self: Any, method: str, params: dict[str, Any], *args: Any) -> dict[str, Any]:
        result: dict[str, Any] = original(self, method, params, *args)
        if method == "initialize":
            sent.append(result["protocolVersion"])
        return result

    monkeypatch.setattr(mcp_client._Session, "_call", spy)
    ours = load_stdio(sys.executable, [SERVER], allow_exec=True).manifest
    params = StdioServerParameters(command=sys.executable, args=[SERVER])
    theirs = anyio.run(sdk_manifest, params)
    assert sent == ["2024-11-05"]
    assert ours == theirs


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port: int = sock.getsockname()[1]
        return port


@contextmanager
def sdk_http_server(transport: str) -> Iterator[int]:
    """Start the SDK server on a free local port and stop its process tree afterwards."""
    port = _free_port()
    process = subprocess.Popen(  # noqa: S603 - our own test server
        [sys.executable, SERVER, transport, str(port)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,  # POSIX: own group, killed as one; ignored on Windows
    )
    try:
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            with contextlib.suppress(OSError), socket.create_connection(("127.0.0.1", port), 0.5):
                break
            time.sleep(0.2)
        else:
            pytest.fail(f"SDK {transport} server did not start")
        yield port
    finally:
        kill_process_tree(process)


def test_streamable_http_manifest_matches_the_sdk() -> None:
    with sdk_http_server("streamable-http") as port:
        url = f"http://127.0.0.1:{port}/mcp"
        ours = load_http(url, transport="streamable-http").manifest
        theirs = anyio.run(sdk_manifest, url)
    assert ours == theirs
    assert ours.server_name == "sdk-conformance"


def test_sse_manifest_matches_the_sdk() -> None:
    with sdk_http_server("sse") as port:
        url = f"http://127.0.0.1:{port}/sse"
        ours = load_http(url, transport="sse").manifest
        theirs = anyio.run(sdk_manifest, sse_client(url))
    assert ours == theirs
    assert [t.name for t in ours.tools] == ["add", "echo"]
