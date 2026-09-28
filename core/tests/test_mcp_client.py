"""Protocol negotiation and limits of the in-house MCP client, over a scripted transport."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

import pytest

from zirah.loaders import LoaderError
from zirah.loaders.mcp_client import (
    CLIENT_INFO,
    METHOD_HEADER,
    PROTOCOL_VERSION_HEADER,
    PROTOCOL_VERSION_META,
    SERVER_INFO_META,
    Transport,
    fetch_manifest,
)

Handler = Callable[[str, dict[str, Any]], dict[str, Any]]
MODERN = "2026-07-28"


class Scripted(Transport):
    def __init__(self, handler: Handler) -> None:
        self.source = "scripted"
        self.handler = handler
        self.sent: list[tuple[str, dict[str, Any], dict[str, str]]] = []
        self.closed = False

    def request(
        self, message: dict[str, Any], *, timeout: float, headers: Mapping[str, str]
    ) -> dict[str, Any]:
        self.sent.append((message["method"], message.get("params", {}), dict(headers)))
        reply = self.handler(message["method"], message.get("params", {}))
        return {"jsonrpc": "2.0", "id": message["id"], **reply}

    def notify(self, message: dict[str, Any], *, headers: Mapping[str, str]) -> None:
        self.sent.append((message["method"], {}, dict(headers)))

    def close(self) -> None:
        self.closed = True


def ok(result: dict[str, Any]) -> dict[str, Any]:
    return {"result": result}


def error(code: int, data: Any = None) -> dict[str, Any]:
    return {"error": {"code": code, "message": "no", "data": data}}


def legacy(version: str = "2025-06-18") -> Handler:
    def handle(method: str, params: dict[str, Any]) -> dict[str, Any]:
        if method == "server/discover":
            return error(-32601)
        if method == "initialize":
            return ok(
                {
                    "protocolVersion": version,
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "legacy", "version": "1"},
                }
            )
        return ok({"tools": [{"name": "t", "inputSchema": {}}]})

    return handle


def modern(method: str, params: dict[str, Any]) -> dict[str, Any]:
    if method == "server/discover":
        return ok(
            {
                "supportedVersions": [MODERN],
                "capabilities": {"prompts": {}},
                "_meta": {SERVER_INFO_META: {"name": "modern", "version": "2"}},
            }
        )
    return ok({"prompts": [{"name": "p"}]})


def test_modern_server_gets_meta_and_method_headers() -> None:
    transport = Scripted(modern)
    data = fetch_manifest(transport)
    assert data == {"serverInfo": {"name": "modern", "version": "2"}, "prompts": [{"name": "p"}]}
    methods = [m for m, _, _ in transport.sent]
    assert methods == ["server/discover", "prompts/list"]
    _, params, headers = transport.sent[1]
    assert params["_meta"][PROTOCOL_VERSION_META] == MODERN
    assert headers == {PROTOCOL_VERSION_HEADER: MODERN, METHOD_HEADER: "prompts/list"}


def test_legacy_server_gets_initialize_then_initialized() -> None:
    transport = Scripted(legacy())
    data = fetch_manifest(transport)
    assert data["serverInfo"] == {"name": "legacy", "version": "1"}
    assert [m for m, _, _ in transport.sent] == [
        "server/discover",
        "initialize",
        "notifications/initialized",
        "tools/list",
    ]
    init_params = transport.sent[1][1]
    assert init_params["clientInfo"] == CLIENT_INFO
    assert transport.sent[3][2] == {PROTOCOL_VERSION_HEADER: "2025-06-18"}


def test_2025_03_26_sends_no_version_header() -> None:
    transport = Scripted(legacy("2025-03-26"))
    fetch_manifest(transport)
    assert transport.sent[3][2] == {}


def test_unsupported_version_error_naming_a_mutual_modern_version_is_retried() -> None:
    calls = []

    def handle(method: str, params: dict[str, Any]) -> dict[str, Any]:
        if method == "server/discover":
            calls.append(params["_meta"][PROTOCOL_VERSION_META])
            if len(calls) == 1:
                return error(-32022, {"supported": [MODERN, "2099-01-01"]})
        return modern(method, params)

    assert fetch_manifest(Scripted(handle))["serverInfo"]["name"] == "modern"
    assert calls == [MODERN, MODERN]


def test_modern_only_server_with_no_shared_version_fails_clearly() -> None:
    def handle(method: str, params: dict[str, Any]) -> dict[str, Any]:
        return error(-32022, {"supported": ["2099-01-01"]})

    with pytest.raises(LoaderError, match=r"unsupported MCP protocol version \(2099-01-01\)"):
        fetch_manifest(Scripted(handle))


def test_probe_timeout_falls_back_to_initialize() -> None:
    def handle(method: str, params: dict[str, Any]) -> dict[str, Any]:
        if method == "server/discover":
            raise TimeoutError
        return legacy()(method, params)

    assert fetch_manifest(Scripted(handle))["serverInfo"]["name"] == "legacy"


def test_discover_answer_without_a_modern_version_falls_back() -> None:
    def handle(method: str, params: dict[str, Any]) -> dict[str, Any]:
        if method == "server/discover":
            return ok({"supportedVersions": ["2025-11-25"], "capabilities": {}})
        return legacy()(method, params)

    assert fetch_manifest(Scripted(handle))["serverInfo"]["name"] == "legacy"


def test_initialize_rejected_as_unsupported_names_the_versions() -> None:
    def handle(method: str, params: dict[str, Any]) -> dict[str, Any]:
        if method == "server/discover":
            return error(-32601)
        return error(-32022, {"supported": ["2024-11-05"]})

    with pytest.raises(LoaderError, match=r"unsupported MCP protocol version \(2024-11-05\)"):
        fetch_manifest(Scripted(handle))


def test_other_initialize_errors_are_reported() -> None:
    def handle(method: str, params: dict[str, Any]) -> dict[str, Any]:
        return error(-32603)

    with pytest.raises(LoaderError, match="initialize failed with error -32603"):
        fetch_manifest(Scripted(handle))


def test_list_without_its_key_is_rejected() -> None:
    def handle(method: str, params: dict[str, Any]) -> dict[str, Any]:
        if method == "tools/list":
            return ok({"items": []})
        return legacy()(method, params)

    with pytest.raises(LoaderError, match="tools/list result has no tools list"):
        fetch_manifest(Scripted(handle))


def test_no_time_left_at_all() -> None:
    with pytest.raises(LoaderError, match="gave up after 0 s in total"):
        fetch_manifest(Scripted(modern), total_timeout=0)


def test_only_advertised_lists_are_requested_and_server_info_is_sanitized() -> None:
    def handle(method: str, params: dict[str, Any]) -> dict[str, Any]:
        if method == "server/discover":
            return error(-32601)
        return ok(
            {
                "protocolVersion": "2025-11-25",
                "capabilities": {"logging": {}},
                "serverInfo": {"name": "x", "version": 3, "extra": "y"},
                "instructions": 42,
            }
        )

    assert fetch_manifest(Scripted(handle)) == {"serverInfo": {"name": "x"}}
