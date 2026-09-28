"""Conformance: our in-house MCP client must read exactly what the official SDK reads.

Each test starts a small real server built with the SDK (``fixtures/servers/sdk_server.py``),
lists it once with the SDK's own client and once with Zirah's loader, and compares the two
manifests. The SDK is a dev dependency only. Where it cannot be imported (for example when
Windows Application Control blocks one of its compiled dependencies) these tests are skipped
with that reason; on the Ubuntu CI runner they always run.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest

from zirah.loaders import mcp_client, parse_manifest
from zirah.loaders.stdio import load_stdio
from zirah.models import Manifest

try:
    import anyio
    from mcp import Client, StdioServerParameters
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
