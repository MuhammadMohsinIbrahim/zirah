"""Read the manifest of a remote MCP server over Streamable HTTP or the older HTTP+SSE transport.

Nothing runs locally. No credentials are sent (no auth by default), redirects are not followed
(the scanned URL is the one reported), and every response is bounded in size and time.

``transport="auto"`` uses Streamable HTTP, except for URLs ending in ``/sse``; when the first
POST is answered with 404 or 405 it falls back to HTTP+SSE, as the MCP spec suggests for
backwards compatibility.
"""

from __future__ import annotations

import contextlib
import json
import queue
import threading
import time
from collections.abc import Iterator, Mapping
from typing import Any, Final, Literal
from urllib.parse import urljoin, urlsplit

import httpx

from zirah import __version__
from zirah.loaders.base import Loaded, LoaderError
from zirah.loaders.mcp_client import (
    MAX_MESSAGE_BYTES,
    REQUEST_TIMEOUT_S,
    TOTAL_TIMEOUT_S,
    Transport,
    fetch_manifest,
)
from zirah.loaders.static import parse_manifest
from zirah.models import Target, TargetKind

HttpTransportName = Literal["auto", "streamable-http", "sse"]

CONNECT_TIMEOUT_S: Final = 10.0
"""Longest wait for a connection, and for an SSE server's ``endpoint`` event."""
SESSION_HEADER: Final = "mcp-session-id"
USER_AGENT: Final = f"zirah/{__version__}"
RPC_HTTP_ERROR: Final = -32001
"""JSON-RPC code used for an HTTP error that came without a JSON-RPC body."""


def load_http(
    url: str,
    *,
    transport: HttpTransportName = "auto",
    request_timeout: float = REQUEST_TIMEOUT_S,
    total_timeout: float = TOTAL_TIMEOUT_S,
    http_transport: httpx.BaseTransport | None = None,
) -> Loaded:
    """Read the manifest at ``url``. ``http_transport`` is for tests."""
    _check_url(url)
    use_sse = transport == "sse" or (transport == "auto" and _path(url).endswith("/sse"))
    if not use_sse:
        try:
            data = _fetch(
                StreamableHttpTransport(url, http_transport), request_timeout, total_timeout
            )
        except _NotStreamableError:
            if transport == "streamable-http":
                raise LoaderError(
                    f"{url}: not a Streamable HTTP MCP endpoint (HTTP 404/405)"
                ) from None
            use_sse = True
    if use_sse:
        data = _fetch(SseTransport(url, http_transport), request_timeout, total_timeout)
    manifest = parse_manifest(data, url)
    return Loaded(
        target=Target(kind=TargetKind.HTTP, location=url, name=manifest.server_name),
        manifest=manifest,
    )


def _fetch(transport: Transport, request_timeout: float, total_timeout: float) -> dict[str, Any]:
    try:
        return fetch_manifest(
            transport, request_timeout=request_timeout, total_timeout=total_timeout
        )
    finally:
        transport.close()


class _NotStreamableError(LoaderError):
    """The first POST got 404 or 405: probably an HTTP+SSE server."""


# --- Streamable HTTP -------------------------------------------------------------------------


class StreamableHttpTransport(Transport):
    def __init__(self, url: str, http_transport: httpx.BaseTransport | None = None) -> None:
        self.source = url
        self._client = _client(http_transport)
        self._session: str | None = None
        self._first = True

    def request(
        self, message: dict[str, Any], *, timeout: float, headers: Mapping[str, str]
    ) -> dict[str, Any]:
        deadline = time.monotonic() + timeout
        first, self._first = self._first, False
        try:
            with self._client.stream(
                "POST", self.source, json=message, headers=self._headers(headers), timeout=timeout
            ) as response:
                if first and response.status_code in (404, 405):
                    raise _NotStreamableError(self.source)
                if session := response.headers.get(SESSION_HEADER):
                    self._session = session
                if response.status_code >= 400:
                    return _http_error(response, message["id"], deadline)
                return self._response(response, message["id"], deadline)
        except httpx.TimeoutException:
            raise TimeoutError from None
        except httpx.HTTPError as exc:
            raise _connection_error(self.source, exc) from None

    def notify(self, message: dict[str, Any], *, headers: Mapping[str, str]) -> None:
        try:
            self._client.post(
                self.source, json=message, headers=self._headers(headers), timeout=CONNECT_TIMEOUT_S
            )
        except httpx.HTTPError as exc:
            raise _connection_error(self.source, exc) from None

    def close(self) -> None:
        if self._session:
            with contextlib.suppress(httpx.HTTPError):
                self._client.delete(self.source, headers=self._headers({}), timeout=2.0)
        self._client.close()

    def _headers(self, extra: Mapping[str, str]) -> dict[str, str]:
        headers = {"Accept": "application/json, text/event-stream", **extra}
        if self._session:
            headers[SESSION_HEADER] = self._session
        return headers

    def _response(self, response: httpx.Response, msg_id: Any, deadline: float) -> dict[str, Any]:
        if response.status_code in (301, 302, 303, 307, 308):
            location = response.headers.get("location", "?")
            raise LoaderError(
                f"{self.source}: redirected to {location}; scan the final URL instead"
            )
        kind = response.headers.get("content-type", "").split(";")[0].strip().lower()
        if kind == "text/event-stream":
            for event, data in _sse_events(response, deadline, self.source):
                if event not in ("", "message"):
                    continue
                try:
                    found = _match(json.loads(data), msg_id)
                except ValueError:
                    continue
                if found is not None:
                    return found
            raise LoaderError(f"{self.source}: the event stream ended without a response")
        if kind == "application/json":
            found = _match(_read_json(response, deadline, self.source), msg_id)
            if found is not None:
                return found
            raise LoaderError(f"{self.source}: the response does not answer the request")
        shown = kind or "none"
        raise LoaderError(
            f"{self.source}: unexpected content type {shown!r} (HTTP {response.status_code})"
        )


# --- HTTP+SSE ------------------------------------------------------------------------------------


class SseTransport(Transport):
    """The HTTP+SSE transport: one GET event stream for responses, POSTs to its endpoint."""

    def __init__(self, url: str, http_transport: httpx.BaseTransport | None = None) -> None:
        self.source = url
        self._client = _client(http_transport)
        self._messages: queue.Queue[Any] = queue.Queue()
        self._endpoint: str | None = None
        self._ready = threading.Event()
        self._stop = threading.Event()
        self._error: LoaderError | None = None
        self._thread = threading.Thread(target=self._listen, daemon=True)
        self._thread.start()
        if not self._ready.wait(CONNECT_TIMEOUT_S):
            self.close()
            raise LoaderError(f"{url}: no SSE endpoint event within {CONNECT_TIMEOUT_S:g} s")
        if self._error is not None:
            self.close()
            raise self._error

    def request(
        self, message: dict[str, Any], *, timeout: float, headers: Mapping[str, str]
    ) -> dict[str, Any]:
        deadline = time.monotonic() + timeout
        self._post(message, headers, timeout)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError
            try:
                incoming = self._messages.get(timeout=remaining)
            except queue.Empty:
                raise TimeoutError from None
            if isinstance(incoming, LoaderError):
                raise incoming
            found = _match(incoming, message["id"])
            if found is not None:
                return found

    def notify(self, message: dict[str, Any], *, headers: Mapping[str, str]) -> None:
        self._post(message, headers, CONNECT_TIMEOUT_S)

    def close(self) -> None:
        self._stop.set()
        self._client.close()

    def _post(self, message: dict[str, Any], headers: Mapping[str, str], timeout: float) -> None:
        if self._endpoint is None:  # pragma: no cover - __init__ guarantees it
            raise LoaderError(f"{self.source}: no SSE endpoint")
        try:
            response = self._client.post(
                self._endpoint, json=message, headers=dict(headers), timeout=timeout
            )
        except httpx.TimeoutException:
            raise TimeoutError from None
        except httpx.HTTPError as exc:
            raise _connection_error(self.source, exc) from None
        if response.status_code >= 400:
            raise LoaderError(
                f"{self.source}: POST to the SSE endpoint failed with HTTP {response.status_code}"
            )

    def _listen(self) -> None:
        try:
            with self._client.stream(
                "GET",
                self.source,
                headers={"Accept": "text/event-stream"},
                timeout=CONNECT_TIMEOUT_S,
            ) as response:
                if response.status_code != 200:
                    raise LoaderError(
                        f"{self.source}: SSE stream failed with HTTP {response.status_code}"
                    )
                for event, data in _sse_events(response, None, self.source, self._stop):
                    if event == "endpoint":
                        self._endpoint = self._resolve_endpoint(data)
                        self._ready.set()
                    elif event in ("", "message"):
                        with contextlib.suppress(ValueError):
                            self._messages.put(json.loads(data))
        except LoaderError as exc:
            self._fail(exc)
        except httpx.TimeoutException:
            self._fail(LoaderError(f"{self.source}: the SSE stream timed out"))
        except httpx.HTTPError as exc:
            if not self._stop.is_set():
                self._fail(_connection_error(self.source, exc))
        else:
            self._fail(LoaderError(f"{self.source}: the SSE stream ended"))

    def _resolve_endpoint(self, data: str) -> str:
        endpoint = urljoin(self.source, data.strip())
        if _origin(endpoint) != _origin(self.source):
            raise LoaderError(
                f"{self.source}: the SSE endpoint points to another origin: {endpoint}"
            )
        return endpoint

    def _fail(self, error: LoaderError) -> None:
        if self._error is None:
            self._error = error
        self._messages.put(error)
        self._ready.set()


# --- Helpers -------------------------------------------------------------------------------------


def _client(http_transport: httpx.BaseTransport | None) -> httpx.Client:
    return httpx.Client(
        transport=http_transport,
        follow_redirects=False,
        headers={"User-Agent": USER_AGENT},
        timeout=httpx.Timeout(REQUEST_TIMEOUT_S, connect=CONNECT_TIMEOUT_S),
    )


def _sse_events(
    response: httpx.Response,
    deadline: float | None,
    source: str,
    stop: threading.Event | None = None,
) -> Iterator[tuple[str, str]]:
    """``(event, data)`` pairs from a text/event-stream body, within size and time limits."""
    event, size = "", 0
    data: list[str] = []
    for line in response.iter_lines():
        if stop is not None and stop.is_set():
            return
        if deadline is not None and time.monotonic() > deadline:
            raise TimeoutError
        size += len(line) + 1
        if size > MAX_MESSAGE_BYTES:
            raise LoaderError(f"{source}: a message is larger than {MAX_MESSAGE_BYTES} bytes")
        if line == "":
            if data:
                yield event, "\n".join(data)
            event, data, size = "", [], 0
        elif line.startswith(":"):
            continue
        else:
            name, _, value = line.partition(":")
            value = value.removeprefix(" ")
            if name == "event":
                event = value
            elif name == "data":
                data.append(value)
    if data:
        yield event, "\n".join(data)


def _read_json(response: httpx.Response, deadline: float, source: str) -> Any:
    body = bytearray()
    for chunk in response.iter_bytes():
        body += chunk
        if len(body) > MAX_MESSAGE_BYTES:
            raise LoaderError(f"{source}: a message is larger than {MAX_MESSAGE_BYTES} bytes")
        if time.monotonic() > deadline:
            raise TimeoutError
    try:
        return json.loads(body)
    except ValueError:
        raise LoaderError(f"{source}: the response is not valid JSON") from None


def _http_error(response: httpx.Response, msg_id: Any, deadline: float) -> dict[str, Any]:
    """A JSON-RPC error for an HTTP error: the server's own JSON-RPC error when it sent one."""
    with contextlib.suppress(LoaderError, TimeoutError):
        found = _match(_read_json(response, deadline, ""), msg_id)
        if found is not None and "error" in found:
            return found
    return {
        "jsonrpc": "2.0",
        "id": msg_id,
        "error": {"code": RPC_HTTP_ERROR, "message": f"HTTP {response.status_code}"},
    }


def _match(data: Any, msg_id: Any) -> dict[str, Any] | None:
    """The response for ``msg_id`` in a message or a batch, if there is one."""
    for item in data if isinstance(data, list) else [data]:
        if (
            isinstance(item, dict)
            and item.get("id") == msg_id
            and ("result" in item or "error" in item)
        ):
            return item
    return None


def _check_url(url: str) -> None:
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise LoaderError(f"{url}: expected an http(s) URL")


def _path(url: str) -> str:
    return urlsplit(url).path.rstrip("/")


def _origin(url: str) -> tuple[str, str, int | None]:
    parts = urlsplit(url)
    return parts.scheme, (parts.hostname or "").lower(), parts.port


def _connection_error(source: str, exc: httpx.HTTPError) -> LoaderError:
    return LoaderError(f"{source}: cannot connect ({type(exc).__name__})")
