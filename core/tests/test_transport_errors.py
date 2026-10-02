"""Transport error paths: servers that fail, stall, lie or crash part-way through.

HTTP servers are simulated in-process with ``httpx.MockTransport``; stdio servers are small
Python scripts that misbehave on purpose. Nothing here touches a real network.
"""

from __future__ import annotations

import json
import os
import queue
import signal
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Iterator
from types import SimpleNamespace
from typing import Any, cast

import httpx
import pytest

from zirah.loaders import LoaderError, http, mcp_client, stdio
from zirah.loaders.http import SseTransport, load_http
from zirah.loaders.stdio import StdioTransport, kill_process_tree, load_stdio

URL = "http://mcp.example.invalid/mcp"
SSE_URL = "http://mcp.example.invalid/sse"
TOOLS = [{"name": "add", "description": "Adds two numbers.", "inputSchema": {"type": "object"}}]

Answer = Callable[[dict[str, Any]], httpx.Response]


@pytest.fixture(autouse=True)
def fast_probe(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(mcp_client, "DISCOVER_TIMEOUT_S", 0.5)


def rpc(message: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": message["id"], "result": result}


def legacy_result(message: dict[str, Any]) -> dict[str, Any]:
    """What a well-behaved 2025-era server answers, as a JSON-RPC response."""
    method = message["method"]
    if method == "initialize":
        return rpc(
            message,
            {
                "protocolVersion": "2025-06-18",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "mock", "version": "1"},
            },
        )
    if method == "tools/list":
        return rpc(message, {"tools": TOOLS})
    return {"jsonrpc": "2.0", "id": message["id"], "error": {"code": -32601, "message": "nf"}}


def as_json(body: Any, status: int = 200) -> httpx.Response:
    return httpx.Response(status, json=body)


def as_events(*chunks: str | bytes) -> httpx.Response:
    data = [c.encode() if isinstance(c, str) else c for c in chunks]
    return httpx.Response(200, headers={"content-type": "text/event-stream"}, content=iter(data))


def streamable(
    tools_list: Answer | None = None, notify: Answer | None = None
) -> httpx.MockTransport:
    """A Streamable HTTP server that is well-behaved except where overridden."""

    def handle(request: httpx.Request) -> httpx.Response:
        message = json.loads(request.content)
        if "id" not in message:
            return notify(message) if notify else httpx.Response(202)
        if message["method"] == "tools/list" and tools_list is not None:
            return tools_list(message)
        return as_json(legacy_result(message))

    return httpx.MockTransport(handle)


def load(transport: httpx.MockTransport, **kwargs: Any) -> list[str]:
    loaded = load_http(URL, transport="streamable-http", http_transport=transport, **kwargs)
    return [tool.name for tool in loaded.manifest.tools]


# --- Streamable HTTP -----------------------------------------------------------------------------


def test_connection_lost_while_sending_a_notification() -> None:
    def refuse(message: dict[str, Any]) -> httpx.Response:
        raise httpx.ConnectError("connection reset")

    with pytest.raises(LoaderError, match=r"cannot connect \(ConnectError\)"):
        load(streamable(notify=refuse))


def test_event_stream_skips_other_events_and_malformed_data() -> None:
    def events(message: dict[str, Any]) -> httpx.Response:
        return as_events(
            ": keep-alive\n\n",
            "event: ping\ndata: {}\n\n",
            "data: {not json\n\n",
            f"data: {json.dumps(legacy_result(message))}",  # no closing blank line
        )

    assert load(streamable(events)) == ["add"]


def test_event_stream_that_ends_without_the_answer() -> None:
    def events(message: dict[str, Any]) -> httpx.Response:
        note = {"jsonrpc": "2.0", "method": "notifications/message", "params": {}}
        return as_events(f"data: {json.dumps(note)}\n\n")

    with pytest.raises(LoaderError, match="event stream ended without a response"):
        load(streamable(events))


def test_json_answer_to_another_request() -> None:
    def wrong_id(message: dict[str, Any]) -> httpx.Response:
        return as_json({"jsonrpc": "2.0", "id": 999, "result": {"tools": TOOLS}})

    with pytest.raises(LoaderError, match="does not answer the request"):
        load(streamable(wrong_id))


def test_http_error_with_a_json_rpc_error_body() -> None:
    def bad_request(message: dict[str, Any]) -> httpx.Response:
        error = {"code": -32602, "message": "bad cursor"}
        return as_json({"jsonrpc": "2.0", "id": message["id"], "error": error}, status=400)

    with pytest.raises(LoaderError, match="tools/list failed with error -32602: bad cursor"):
        load(streamable(bad_request))


def test_malformed_json_body() -> None:
    def garbage(message: dict[str, Any]) -> httpx.Response:
        return httpx.Response(200, headers={"content-type": "application/json"}, content=b"{")

    with pytest.raises(LoaderError, match="not valid JSON"):
        load(streamable(garbage))


def test_oversized_event(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(http, "MAX_MESSAGE_BYTES", 200)

    def huge(message: dict[str, Any]) -> httpx.Response:
        return as_events("data: " + "x" * 500 + "\n\n")

    with pytest.raises(LoaderError, match="larger than 200 bytes"):
        load(streamable(huge))


def trickle(chunk: bytes, every: float, count: int) -> Iterator[bytes]:
    for _ in range(count):
        time.sleep(every)
        yield chunk


def test_event_stream_that_never_answers_times_out() -> None:
    def stalling(message: dict[str, Any]) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "text/event-stream"},
            content=trickle(b": still working\n\n", 0.05, 100),
        )

    with pytest.raises(LoaderError, match=r"no response to tools/list within 0\.4 s"):
        load(streamable(stalling), request_timeout=0.4)


def test_json_body_that_trickles_in_times_out() -> None:
    def slow(message: dict[str, Any]) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            content=trickle(b" ", 0.05, 100),
        )

    with pytest.raises(LoaderError, match=r"no response to tools/list within 0\.4 s"):
        load(streamable(slow), request_timeout=0.4)


def test_server_crash_mid_stream() -> None:
    def crash(message: dict[str, Any]) -> httpx.Response:
        def body() -> Iterator[bytes]:
            yield b": starting\n\n"
            raise httpx.ReadError("connection closed by peer")

        return httpx.Response(200, headers={"content-type": "text/event-stream"}, content=body())

    with pytest.raises(LoaderError, match=r"cannot connect \(ReadError\)"):
        load(streamable(crash))


# --- HTTP+SSE ------------------------------------------------------------------------------------


class FakeSse:
    """An HTTP+SSE server: a GET event stream, and POSTs answered by ``post``."""

    def __init__(
        self,
        endpoint: str | None = "/messages",
        post: Answer | None = None,
        get: Callable[[], None] | None = None,
    ) -> None:
        self.endpoint = endpoint
        self.post = post or self._answer
        self.get = get
        self.events: queue.Queue[dict[str, Any] | None] = queue.Queue()
        self.done = threading.Event()
        self.transport = httpx.MockTransport(self._handle)

    def _handle(self, request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            if self.get is not None:
                self.get()
            return httpx.Response(
                200, headers={"content-type": "text/event-stream"}, content=self._stream()
            )
        return self.post(json.loads(request.content))

    def _answer(self, message: dict[str, Any]) -> httpx.Response:
        if "id" in message:
            self.events.put(legacy_result(message))
        return httpx.Response(202)

    def _stream(self) -> Iterator[bytes]:
        if self.endpoint is not None:
            yield f"event: endpoint\ndata: {self.endpoint}\n\n".encode()
        while not self.done.is_set():
            try:
                event = self.events.get(timeout=0.05)
            except queue.Empty:
                yield b": keep-alive\n\n"
                continue
            if event is None:
                return  # the server hangs up
            yield f"event: message\ndata: {json.dumps(event)}\n\n".encode()


@pytest.fixture
def sse() -> Iterator[Callable[..., FakeSse]]:
    servers: list[FakeSse] = []

    def start(**kwargs: Any) -> FakeSse:
        server = FakeSse(**kwargs)
        servers.append(server)
        return server

    yield start
    for server in servers:
        server.done.set()


def ping(msg_id: int = 1) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": msg_id, "method": "ping"}


def test_sse_reads_a_manifest(sse: Callable[..., FakeSse]) -> None:
    server = sse()
    loaded = load_http(SSE_URL, http_transport=server.transport)
    assert [tool.name for tool in loaded.manifest.tools] == ["add"]


def test_sse_without_an_endpoint_event(
    sse: Callable[..., FakeSse], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(http, "CONNECT_TIMEOUT_S", 0.3)
    server = sse(endpoint=None)
    with pytest.raises(LoaderError, match=r"no SSE endpoint event within 0\.3 s"):
        load_http(SSE_URL, http_transport=server.transport)


@pytest.mark.parametrize(
    ("error", "message"),
    [
        (httpx.ReadTimeout("slow"), "the SSE stream timed out"),
        (httpx.ConnectError("refused"), r"cannot connect \(ConnectError\)"),
    ],
)
def test_sse_stream_that_cannot_be_opened(
    sse: Callable[..., FakeSse], error: Exception, message: str
) -> None:
    def fail() -> None:
        raise error

    server = sse(get=fail)
    with pytest.raises(LoaderError, match=message):
        load_http(SSE_URL, http_transport=server.transport)


def test_sse_request_with_no_time_left(sse: Callable[..., FakeSse]) -> None:
    transport = SseTransport(SSE_URL, sse().transport)
    try:
        with pytest.raises(TimeoutError):
            transport.request(ping(), timeout=0, headers={})
    finally:
        transport.close()


def test_sse_request_that_is_never_answered(sse: Callable[..., FakeSse]) -> None:
    server = sse(post=lambda message: httpx.Response(202))
    transport = SseTransport(SSE_URL, server.transport)
    try:
        with pytest.raises(TimeoutError):
            transport.request(ping(), timeout=0.3, headers={})
    finally:
        transport.close()


def test_sse_server_hangs_up_mid_session(sse: Callable[..., FakeSse]) -> None:
    server = sse()
    transport = SseTransport(SSE_URL, server.transport)
    try:
        assert transport.request(ping(1), timeout=5, headers={})["id"] == 1
        server.events.put(None)
        with pytest.raises(LoaderError, match="the SSE stream ended"):
            transport.request(ping(2), timeout=5, headers={})
    finally:
        transport.close()


@pytest.mark.parametrize(
    ("post", "error", "message"),
    [
        (httpx.ReadTimeout("slow"), TimeoutError, None),
        (httpx.ConnectError("refused"), LoaderError, r"cannot connect \(ConnectError\)"),
        (httpx.Response(500), LoaderError, "POST to the SSE endpoint failed with HTTP 500"),
    ],
)
def test_sse_post_failures(
    sse: Callable[..., FakeSse],
    post: httpx.Response | Exception,
    error: type[Exception],
    message: str | None,
) -> None:
    def answer(request: dict[str, Any]) -> httpx.Response:
        if isinstance(post, Exception):
            raise post
        return post

    transport = SseTransport(SSE_URL, sse(post=answer).transport)
    try:
        with pytest.raises(error, match=message):
            transport.request(ping(), timeout=5, headers={})
    finally:
        transport.close()


# --- stdio ---------------------------------------------------------------------------------------

PYTHON = sys.executable


def script(code: str) -> StdioTransport:
    return StdioTransport(PYTHON, ["-c", code])


def test_popen_failure_is_readable(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*args: Any, **kwargs: Any) -> Any:
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(subprocess, "Popen", refuse)
    with pytest.raises(LoaderError, match=r"cannot start \(Permission denied\)"):
        load_stdio("zirah-test-server", allow_exec=True)


@pytest.mark.parametrize(
    ("platform", "expected"), [("linux", "start_new_session"), ("win32", "creationflags")]
)
def test_server_gets_its_own_process_group(
    monkeypatch: pytest.MonkeyPatch, platform: str, expected: str
) -> None:
    seen: dict[str, Any] = {}

    def record(*args: Any, **kwargs: Any) -> Any:
        seen.update(kwargs)
        raise FileNotFoundError

    monkeypatch.setattr(sys, "platform", platform)
    monkeypatch.setattr(subprocess, "Popen", record)
    monkeypatch.setattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x200, raising=False)
    monkeypatch.setattr(subprocess, "CREATE_NO_WINDOW", 0x8000000, raising=False)
    with pytest.raises(LoaderError, match="command not found"):
        StdioTransport("zirah-test-server")
    assert expected in seen


def test_request_with_no_time_left() -> None:
    transport = script("import time; time.sleep(30)")
    try:
        with pytest.raises(TimeoutError):
            transport.request(ping(), timeout=0, headers={})
    finally:
        transport.close()
        transport.close()  # closing twice is harmless


def test_blank_lines_and_non_object_json_are_skipped() -> None:
    code = (
        "import sys, json\n"
        "message = json.loads(sys.stdin.readline())\n"
        "print()\n"
        "print('[1, 2]')\n"
        "print(json.dumps('just a string'))\n"
        "print(json.dumps({'jsonrpc': '2.0', 'id': message['id'], 'result': {}}), flush=True)\n"
        "sys.stdin.read()\n"
    )
    transport = script(code)
    try:
        assert transport.request(ping(7), timeout=30, headers={}) == {
            "jsonrpc": "2.0",
            "id": 7,
            "result": {},
        }
    finally:
        transport.close()


def keep_writing(transport: StdioTransport) -> None:
    for _ in range(50):  # the pipe may accept a write or two before it reports
        transport.notify(ping(), headers={})
        time.sleep(0.05)


def test_writing_to_a_server_that_already_exited() -> None:
    transport = script("pass")
    try:
        transport.process.wait(timeout=30)
        with pytest.raises(LoaderError, match=r"closed its output \(exit code 0\)"):
            keep_writing(transport)
    finally:
        transport.close()


def test_server_that_closed_stdout_but_keeps_running() -> None:
    # A real child cannot show this portably (on Windows a launcher process may hold the
    # pipe open), so the process is faked: its output ended, but it does not exit.
    def still_running(timeout: float | None = None) -> int:
        raise subprocess.TimeoutExpired("server", timeout or 0)

    transport = bare_transport()
    transport.process = cast(Any, SimpleNamespace(wait=still_running))
    transport._stderr = bytearray(b"starting\nfatal: lost the database\n")
    message = str(transport._exited())
    assert message == (
        "broken: the server closed its output; last stderr line: 'fatal: lost the database'"
    )


def test_server_crashes_after_initialize() -> None:
    code = (
        "import sys, json\n"
        "for line in sys.stdin:\n"
        "    message = json.loads(line)\n"
        "    if message.get('method') == 'initialize':\n"
        "        result = {'protocolVersion': '2025-06-18', 'capabilities': {'tools': {}}}\n"
        "        reply = {'jsonrpc': '2.0', 'id': message['id'], 'result': result}\n"
        "        print(json.dumps(reply), flush=True)\n"
        "    elif message.get('method') == 'tools/list':\n"
        "        sys.exit(3)\n"
        "    elif 'id' in message:\n"
        "        error = {'code': -32601, 'message': 'nf'}\n"
        "        print(json.dumps({'jsonrpc': '2.0', 'id': message['id'], 'error': error}),"
        " flush=True)\n"
    )
    with pytest.raises(LoaderError, match=r"closed its output \(exit code 3\)"):
        load_stdio(PYTHON, ["-c", code], allow_exec=True)


class Broken:
    """A pipe whose every read fails."""

    def readline(self, size: int = -1) -> bytes:
        raise OSError("pipe broke")

    def fileno(self) -> int:
        raise ValueError("I/O operation on closed file")


def bare_transport() -> StdioTransport:
    """A transport whose process has broken pipes and no reader threads."""
    transport = object.__new__(StdioTransport)
    transport.source = "broken"
    transport.process = cast(Any, SimpleNamespace(stdout=Broken(), stderr=Broken()))
    transport._messages = queue.Queue()
    transport._stderr = bytearray()
    return transport


def test_broken_stdout_reads_as_end_of_output() -> None:
    transport = bare_transport()
    transport._read_stdout()
    assert transport._messages.get_nowait() is stdio._EOF


def test_broken_stderr_is_ignored() -> None:
    transport = bare_transport()
    transport._read_stderr()
    assert transport._stderr == bytearray()


class FakeProcess:
    pid = 4242

    def __init__(self) -> None:
        self.calls: list[str] = []

    def wait(self, timeout: float | None = None) -> int:
        self.calls.append("wait")
        if len(self.calls) == 1:
            raise subprocess.TimeoutExpired("server", timeout or 0)
        return 0

    def kill(self) -> None:
        self.calls.append("kill")


def test_kill_process_tree_on_posix(monkeypatch: pytest.MonkeyPatch) -> None:
    sent: list[tuple[int, int]] = []

    def killpg(pid: int, sig: int) -> None:
        sent.append((pid, sig))
        if len(sent) == 2:
            raise ProcessLookupError  # the group is already gone

    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(signal, "SIGKILL", 9, raising=False)
    monkeypatch.setattr(os, "killpg", killpg, raising=False)
    process = FakeProcess()
    kill_process_tree(cast(Any, process))
    assert sent == [(4242, signal.SIGTERM), (4242, 9)]
    assert process.calls == ["wait", "kill", "wait"]


def test_kill_process_tree_on_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    ran: list[list[str]] = []

    def run(args: list[str], **kwargs: Any) -> Any:
        ran.append(args)
        raise subprocess.TimeoutExpired(args, kwargs["timeout"])

    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setenv("SYSTEMROOT", "C:\\Windows")
    monkeypatch.setattr(subprocess, "run", run)
    process = FakeProcess()
    kill_process_tree(cast(Any, process))
    ((command, *flags),) = ran
    assert command.lower().endswith("taskkill.exe")
    assert flags == ["/T", "/F", "/PID", "4242"]
    assert process.calls == ["kill", "wait"]
