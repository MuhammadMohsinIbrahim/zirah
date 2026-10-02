"""A minimal MCP client: just enough to read a server's manifest.

It negotiates the protocol, then lists tools, prompts and resources (following pagination) and
nothing else: no tool is ever called. The runtime uses this small in-house client instead of
the official SDK to keep the dependency footprint small and auditable; the SDK is used only in
conformance tests.

Protocol versions:

- ``2026-07-28`` (and later modern versions this client knows): no ``initialize``; the client
  probes ``server/discover`` and stamps every request with ``_meta`` (protocol version, client
  info and capabilities).
- ``2024-11-05``, ``2025-03-26``, ``2025-06-18`` and ``2025-11-25``: the ``initialize``
  handshake, used when the ``server/discover`` probe is not answered with a modern version.
  Listing works the same way in all of them; only ``2025-06-18`` and later send the
  ``MCP-Protocol-Version`` HTTP header.

Anything else fails with a clear error naming the versions on both sides.

The server is untrusted, so every limit is enforced here or in the transport: message size,
items per list, pages per list, time per request and total time.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from collections.abc import Mapping
from typing import Any, Final

from zirah import __version__
from zirah.loaders.base import LoaderError

MODERN_VERSIONS: Final = ("2026-07-28",)
"""Protocol versions with the stateless per-request ``_meta`` envelope."""
HANDSHAKE_VERSIONS: Final = ("2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25")
"""Protocol versions negotiated with ``initialize``."""
SUPPORTED_VERSIONS: Final = (*HANDSHAKE_VERSIONS, *MODERN_VERSIONS)
HEADER_VERSIONS: Final = ("2025-06-18", "2025-11-25", *MODERN_VERSIONS)
"""Versions whose HTTP requests carry the ``MCP-Protocol-Version`` header."""

CLIENT_INFO: Final = {"name": "zirah", "version": __version__}

PROTOCOL_VERSION_META: Final = "io.modelcontextprotocol/protocolVersion"
CLIENT_INFO_META: Final = "io.modelcontextprotocol/clientInfo"
CLIENT_CAPABILITIES_META: Final = "io.modelcontextprotocol/clientCapabilities"
SERVER_INFO_META: Final = "io.modelcontextprotocol/serverInfo"
PROTOCOL_VERSION_HEADER: Final = "mcp-protocol-version"
METHOD_HEADER: Final = "mcp-method"

UNSUPPORTED_PROTOCOL_VERSION: Final = -32022
METHOD_NOT_FOUND: Final = -32601

# --- Limits on untrusted servers ------------------------------------------------------------

REQUEST_TIMEOUT_S: Final = 30.0
"""Longest wait for one response."""
DISCOVER_TIMEOUT_S: Final = 10.0
"""Longest wait for the ``server/discover`` probe before falling back to ``initialize``."""
TOTAL_TIMEOUT_S: Final = 120.0
"""Longest time for the whole manifest extraction, server start-up included."""
MAX_MESSAGE_BYTES: Final = 8 * 1024 * 1024
"""Largest single JSON-RPC message accepted from a server."""
MAX_ITEMS: Final = 2000
"""Most tools, prompts or resources (each) accepted from one server."""
MAX_PAGES: Final = 100
"""Most pages followed for one list."""

LISTS: Final = (
    ("tools", "tools/list"),
    ("prompts", "prompts/list"),
    ("resources", "resources/list"),
)


class RpcError(LoaderError):
    """The server answered a request with a JSON-RPC error."""

    def __init__(self, source: str, method: str, code: Any, message: Any, data: Any) -> None:
        self.code = code
        self.data = data
        super().__init__(f"{source}: {method} failed with error {code}: {_short(message)}")


class Transport(ABC):
    """Moves JSON-RPC messages to and from one server."""

    source: str
    """How the server is named in error messages (command or URL)."""

    @abstractmethod
    def request(
        self, message: dict[str, Any], *, timeout: float, headers: Mapping[str, str]
    ) -> dict[str, Any]:
        """Send a request and return the JSON-RPC response with the same id."""

    @abstractmethod
    def notify(self, message: dict[str, Any], *, headers: Mapping[str, str]) -> None:
        """Send a notification."""

    @abstractmethod
    def close(self) -> None:
        """Release the connection (and, for stdio, stop the server)."""


class Deadline:
    def __init__(self, seconds: float, source: str) -> None:
        self.seconds = seconds
        self.source = source
        self._end = time.monotonic() + seconds

    def timeout(self, limit: float) -> float:
        """The time allowed for the next step: ``limit``, or less when the total runs out."""
        remaining = self._end - time.monotonic()
        if remaining <= 0:
            raise LoaderError(f"{self.source}: gave up after {self.seconds:g} s in total")
        return min(limit, remaining)


def fetch_manifest(
    transport: Transport,
    *,
    request_timeout: float = REQUEST_TIMEOUT_S,
    total_timeout: float = TOTAL_TIMEOUT_S,
) -> dict[str, Any]:
    """Negotiate, list everything and return the data in the static-manifest layout
    (``serverInfo``, ``instructions``, ``tools``, ``prompts``, ``resources``)."""
    session = _Session(transport, request_timeout, Deadline(total_timeout, transport.source))
    session.negotiate()
    return session.manifest_data()


class _Session:
    def __init__(self, transport: Transport, request_timeout: float, deadline: Deadline) -> None:
        self.transport = transport
        self.source = transport.source
        self.request_timeout = request_timeout
        self.deadline = deadline
        self.version: str | None = None
        self.modern = False
        self.capabilities: dict[str, Any] = {}
        self.server_info: Any = None
        self.instructions: Any = None
        self._next_id = 0

    # --- Negotiation -------------------------------------------------------------------------

    def negotiate(self) -> None:
        version = MODERN_VERSIONS[-1]
        for attempt in range(2):
            try:
                result = self._discover(version)
            except RpcError as exc:
                supported = _supported(exc.data)
                mutual = [v for v in MODERN_VERSIONS if v in supported]
                if exc.code == UNSUPPORTED_PROTOCOL_VERSION and mutual and attempt == 0:
                    version = mutual[-1]
                    continue
                if (
                    exc.code == UNSUPPORTED_PROTOCOL_VERSION
                    and supported
                    and not (set(supported) & set(SUPPORTED_VERSIONS))
                ):
                    raise self._unsupported(supported) from None
                self._initialize()
                return
            except _ProbeTimeoutError:
                self._initialize()
                return
            supported = _supported(result)
            mutual = [v for v in MODERN_VERSIONS if v in supported]
            if not mutual:
                self._initialize()  # a legacy server that happens to answer discover
                return
            self.version, self.modern = mutual[-1], True
            self.capabilities = _dict(result.get("capabilities"))
            self.server_info = _dict(result.get("_meta")).get(SERVER_INFO_META)
            self.instructions = result.get("instructions")
            return

    def _discover(self, version: str) -> dict[str, Any]:
        params = {"_meta": self._meta(version)}
        headers = {PROTOCOL_VERSION_HEADER: version, METHOD_HEADER: "server/discover"}
        try:
            return self._call("server/discover", params, headers, DISCOVER_TIMEOUT_S)
        except _RequestTimeoutError:
            raise _ProbeTimeoutError from None

    def _initialize(self) -> None:
        version = HANDSHAKE_VERSIONS[-1]
        for attempt in range(2):
            params = {"protocolVersion": version, "capabilities": {}, "clientInfo": CLIENT_INFO}
            try:
                result = self._call("initialize", params, {}, self.request_timeout)
                break
            except RpcError as exc:
                if exc.code != UNSUPPORTED_PROTOCOL_VERSION:
                    raise
                supported = _supported(exc.data)
                mutual = [v for v in HANDSHAKE_VERSIONS if v in supported]
                if not mutual or attempt == 1:
                    raise self._unsupported(supported) from None
                version = mutual[-1]  # a server that errors instead of offering its version
        agreed = result.get("protocolVersion")
        if agreed not in HANDSHAKE_VERSIONS:
            raise self._unsupported([agreed])
        self.version = agreed
        self.capabilities = _dict(result.get("capabilities"))
        self.server_info = result.get("serverInfo")
        self.instructions = result.get("instructions")
        self.transport.notify(
            {"jsonrpc": "2.0", "method": "notifications/initialized"}, headers=self._headers(None)
        )

    def _unsupported(self, versions: list[Any]) -> LoaderError:
        shown = ", ".join(_short(v) for v in versions) or "none"
        return LoaderError(
            f"{self.source}: unsupported MCP protocol version ({shown}); Zirah supports "
            f"{', '.join(SUPPORTED_VERSIONS)}"
        )

    def _meta(self, version: str) -> dict[str, Any]:
        return {
            PROTOCOL_VERSION_META: version,
            CLIENT_INFO_META: CLIENT_INFO,
            CLIENT_CAPABILITIES_META: {},
        }

    def _headers(self, method: str | None) -> dict[str, str]:
        headers: dict[str, str] = {}
        if self.version in HEADER_VERSIONS:
            headers[PROTOCOL_VERSION_HEADER] = self.version
        if self.modern and method:
            headers[METHOD_HEADER] = method
        return headers

    # --- Listing -----------------------------------------------------------------------------

    def manifest_data(self) -> dict[str, Any]:
        data: dict[str, Any] = {}
        if isinstance(self.server_info, dict):
            data["serverInfo"] = {
                key: self.server_info[key]
                for key in ("name", "version")
                if isinstance(self.server_info.get(key), str)
            }
        if isinstance(self.instructions, str):
            data["instructions"] = self.instructions
        for key, method in LISTS:
            if key in self.capabilities:
                data[key] = self._list(key, method)
        return data

    def _list(self, key: str, method: str) -> list[Any]:
        items: list[Any] = []
        cursor: Any = None
        for _ in range(MAX_PAGES):
            params: dict[str, Any] = {} if cursor is None else {"cursor": cursor}
            if self.modern and self.version is not None:
                params["_meta"] = self._meta(self.version)
            result = self._call(method, params, self._headers(method), self.request_timeout)
            page = result.get(key)
            if not isinstance(page, list):
                raise LoaderError(f"{self.source}: {method} result has no {key} list")
            items += page
            if len(items) > MAX_ITEMS:
                raise LoaderError(f"{self.source}: more than {MAX_ITEMS} {key}; refusing")
            cursor = result.get("nextCursor")
            if cursor is None or cursor == "":
                return items
            if not isinstance(cursor, str):
                raise LoaderError(f"{self.source}: {method} returned a non-string nextCursor")
        raise LoaderError(f"{self.source}: {method} returned more than {MAX_PAGES} pages")

    # --- Calls -------------------------------------------------------------------------------

    def _call(
        self, method: str, params: dict[str, Any], headers: Mapping[str, str], limit: float
    ) -> dict[str, Any]:
        self._next_id += 1
        message = {"jsonrpc": "2.0", "id": self._next_id, "method": method, "params": params}
        timeout = self.deadline.timeout(limit)
        try:
            response = self.transport.request(message, timeout=timeout, headers=headers)
        except TimeoutError:
            if timeout < limit:  # the total time ran out, not this request's
                raise LoaderError(
                    f"{self.source}: gave up after {self.deadline.seconds:g} s in total"
                ) from None
            raise _RequestTimeoutError(
                f"{self.source}: no response to {method} within {limit:g} s"
            ) from None
        if "error" in response:
            error = _dict(response.get("error"))
            raise RpcError(
                self.source, method, error.get("code"), error.get("message"), error.get("data")
            )
        result = response.get("result")
        if not isinstance(result, dict):
            raise LoaderError(f"{self.source}: {method} returned no result object")
        return result


class _RequestTimeoutError(LoaderError):
    """One request got no response in time (the total time had not run out)."""


class _ProbeTimeoutError(Exception):
    """The ``server/discover`` probe got no response: fall back to ``initialize``."""


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _supported(data: Any) -> list[str]:
    """``supported`` (from a -32022 error) or ``supportedVersions`` (from discover)."""
    data = _dict(data)
    value = data.get("supportedVersions", data.get("supported"))
    return [v for v in value if isinstance(v, str)] if isinstance(value, list) else []


def _short(value: Any, limit: int = 200) -> str:
    text = str(value)
    return text if len(text) <= limit else text[: limit - 1] + "…"
