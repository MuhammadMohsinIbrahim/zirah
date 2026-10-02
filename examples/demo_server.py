"""A tiny MCP server over stdio that serves a manifest JSON file. Standard library only.

    python examples/demo_server.py examples/malicious/manifest.json

It answers ``initialize``, ``ping`` and the three ``*/list`` calls from the manifest, and
nothing else: every tool call, prompt fetch and resource read gets an error. That makes the
deliberately malicious demo harmless to run, because none of its tools do anything; the
"attack" is only text that a scanner should catch.

The demos in ``malicious/`` and ``benign/`` each have a ``server.py`` that runs this with
their own ``manifest.json``.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

PROTOCOL_VERSIONS = ("2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25")
METHOD_NOT_FOUND = -32601
LISTS = {"tools/list": "tools", "prompts/list": "prompts", "resources/list": "resources"}


def handle(manifest: dict[str, Any], method: str, params: dict[str, Any]) -> dict[str, Any]:
    """The JSON-RPC ``result`` (or ``error``) for one request."""
    if method == "initialize":
        requested = params.get("protocolVersion")
        version = requested if requested in PROTOCOL_VERSIONS else PROTOCOL_VERSIONS[-1]
        result: dict[str, Any] = {
            "protocolVersion": version,
            "capabilities": {key: {} for key in LISTS.values() if key in manifest},
            "serverInfo": manifest.get("serverInfo", {"name": "demo", "version": "0"}),
        }
        if "instructions" in manifest:
            result["instructions"] = manifest["instructions"]
        return {"result": result}
    if method == "ping":
        return {"result": {}}
    if method in LISTS:
        return {"result": {LISTS[method]: manifest.get(LISTS[method], [])}}
    if method == "tools/call":
        text = "This is a Zirah demo server: its tools do nothing."
        return {"result": {"content": [{"type": "text", "text": text}], "isError": True}}
    return {"error": {"code": METHOD_NOT_FOUND, "message": f"Method not found: {method}"}}


def serve(path: Path) -> None:
    """Answer requests on stdin until it closes."""
    manifest = json.loads(path.read_text(encoding="utf-8"))
    for line in sys.stdin:
        try:
            message = json.loads(line)
        except ValueError:
            continue
        if not isinstance(message, dict) or "id" not in message or "method" not in message:
            continue  # a notification or a response: nothing to answer
        params = message.get("params")
        reply = handle(manifest, message["method"], params if isinstance(params, dict) else {})
        sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": message["id"], **reply}) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: python demo_server.py MANIFEST.json")
    serve(Path(sys.argv[1]))
