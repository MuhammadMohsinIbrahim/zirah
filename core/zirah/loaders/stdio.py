"""Run a stdio MCP server and read its manifest.

This executes the server's code on the host with the user's permissions, so it only runs when
the caller passes ``allow_exec=True`` (``--allow-exec`` on the CLI), which also prints
``EXEC_WARNING``. The server gets a time limit, its messages a size limit, and afterwards its
whole process tree is killed: ``taskkill /T /F`` on Windows, the process group on POSIX.
"""

from __future__ import annotations

import contextlib
import json
import os
import queue
import shutil
import signal
import subprocess
import sys
import threading
import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import IO, Any, Final

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

EXEC_WARNING: Final = (
    "This runs the server's code on your machine with your user permissions. "
    "Prefer --docker or a static manifest."
)
"""The host-execution warning from SPEC section 4.3."""

KILL_TIMEOUT_S: Final = 5.0
"""Longest wait for the process tree to die after it was told to."""
STDERR_TAIL_BYTES: Final = 2000
"""Last bytes of the server's stderr kept for error messages."""

_EOF: Final = object()


def load_stdio(
    command: str,
    args: Sequence[str] = (),
    *,
    allow_exec: bool = False,
    env: Mapping[str, str] | None = None,
    request_timeout: float = REQUEST_TIMEOUT_S,
    total_timeout: float = TOTAL_TIMEOUT_S,
) -> Loaded:
    """Start ``command args``, read its manifest over stdio and stop it again.

    ``env`` adds to (and overrides) the inherited environment. It is never recorded in the
    target: environment variables often hold secrets.
    """
    if not allow_exec:
        raise LoaderError(
            f"refusing to run {command!r}: {EXEC_WARNING} Pass --allow-exec to run it anyway."
        )
    transport = StdioTransport(command, args, env=env)
    try:
        data = fetch_manifest(
            transport, request_timeout=request_timeout, total_timeout=total_timeout
        )
    finally:
        transport.close()
    manifest = parse_manifest(data, transport.source)
    target = Target(
        kind=TargetKind.STDIO, location=command, args=tuple(args), name=manifest.server_name
    )
    return Loaded(target=target, manifest=manifest)


class StdioTransport(Transport):
    """Newline-delimited JSON-RPC over a child process's stdin and stdout."""

    def __init__(
        self, command: str, args: Sequence[str] = (), *, env: Mapping[str, str] | None = None
    ) -> None:
        self.source = command
        executable = shutil.which(command) or command
        kwargs: dict[str, Any] = {}
        if sys.platform == "win32":
            kwargs["creationflags"] = (
                subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW
            )
        else:
            kwargs["start_new_session"] = True  # own process group, killed as one
        try:
            self.process = subprocess.Popen(  # noqa: S603 - running it is the point, behind --allow-exec
                [executable, *args],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env={**os.environ, **(env or {})},
                **kwargs,
            )
        except FileNotFoundError:
            raise LoaderError(f"{command}: command not found") from None
        except OSError as exc:
            raise LoaderError(f"{command}: cannot start ({exc.strerror})") from None

        self._messages: queue.Queue[Any] = queue.Queue()
        self._stderr = bytearray()
        self._closed = False
        threading.Thread(target=self._read_stdout, daemon=True).start()
        threading.Thread(target=self._read_stderr, daemon=True).start()

    # --- Transport ---------------------------------------------------------------------------

    def request(
        self, message: dict[str, Any], *, timeout: float, headers: Mapping[str, str]
    ) -> dict[str, Any]:
        self._send(message)
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError
            try:
                incoming = self._messages.get(timeout=remaining)
            except queue.Empty:
                raise TimeoutError from None
            if incoming is _EOF:
                raise self._exited()
            if isinstance(incoming, LoaderError):
                raise incoming
            if not isinstance(incoming, dict):
                continue
            if "method" in incoming:
                self._answer_server(incoming)
            elif incoming.get("id") == message["id"]:
                return incoming
            # Anything else (a late answer to an abandoned request) is ignored.

    def notify(self, message: dict[str, Any], *, headers: Mapping[str, str]) -> None:
        self._send(message)

    def close(self) -> None:
        """Kill the whole process tree first (so no child is orphaned), then the pipes."""
        if self._closed:
            return
        self._closed = True
        kill_process_tree(self.process)
        for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
            _close_quietly(stream)

    # --- Internals ---------------------------------------------------------------------------

    def _send(self, message: dict[str, Any]) -> None:
        line = json.dumps(message, separators=(",", ":")).encode("utf-8") + b"\n"
        stdin = self.process.stdin
        if stdin is None:  # pragma: no cover - Popen always gives a pipe here
            raise self._exited()
        try:
            stdin.write(line)
            stdin.flush()
        except (BrokenPipeError, OSError, ValueError):
            raise self._exited() from None

    def _answer_server(self, incoming: dict[str, Any]) -> None:
        """Answer server-to-client requests so the server does not wait; ignore notifications."""
        if "id" not in incoming:
            return
        if incoming.get("method") == "ping":
            reply: dict[str, Any] = {"jsonrpc": "2.0", "id": incoming["id"], "result": {}}
        else:
            reply = {
                "jsonrpc": "2.0",
                "id": incoming["id"],
                "error": {"code": -32601, "message": "not supported by zirah"},
            }
        with contextlib.suppress(LoaderError):
            self._send(reply)

    def _read_stdout(self) -> None:
        stdout = self.process.stdout
        if stdout is None:  # pragma: no cover
            return
        try:
            while True:
                line = stdout.readline(MAX_MESSAGE_BYTES + 1)
                if not line:
                    break
                if len(line) > MAX_MESSAGE_BYTES:
                    self._messages.put(
                        LoaderError(
                            f"{self.source}: a message is larger than {MAX_MESSAGE_BYTES} bytes"
                        )
                    )
                    return
                if not line.strip():
                    continue
                try:
                    self._messages.put(json.loads(line))
                except ValueError:
                    continue  # stray output (a log line) on stdout is skipped
        except (OSError, ValueError):
            pass
        self._messages.put(_EOF)

    def _read_stderr(self) -> None:
        stderr = self.process.stderr
        if stderr is None:  # pragma: no cover
            return
        try:
            while chunk := os.read(stderr.fileno(), 4096):
                self._stderr += chunk
                del self._stderr[:-STDERR_TAIL_BYTES]
        except (OSError, ValueError):
            pass

    def _exited(self) -> LoaderError:
        try:
            code = self.process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            code = None
        tail = bytes(self._stderr).decode("utf-8", "replace").strip()
        message = f"{self.source}: the server closed its output"
        if code is not None:
            message += f" (exit code {code})"
        if tail:
            last = tail.splitlines()[-1]
            message += f"; last stderr line: {last[:300]!a}"
        return LoaderError(message)


def kill_process_tree(process: subprocess.Popen[bytes]) -> None:
    """Kill ``process`` and everything it started, then reap it."""
    if sys.platform == "win32":
        system_root = os.environ.get("SYSTEMROOT", r"C:\Windows")
        taskkill = Path(system_root) / "System32" / "taskkill.exe"
        with contextlib.suppress(OSError, subprocess.TimeoutExpired):
            subprocess.run(  # noqa: S603 - fixed system binary, no shell
                [str(taskkill), "/T", "/F", "/PID", str(process.pid)],
                capture_output=True,
                timeout=KILL_TIMEOUT_S,
                check=False,
            )
    else:
        # The server leads its own process group (start_new_session), so the group holds
        # every descendant, even ones whose parent already exited.
        with contextlib.suppress(OSError):
            os.killpg(process.pid, signal.SIGTERM)
        with contextlib.suppress(subprocess.TimeoutExpired):
            process.wait(timeout=KILL_TIMEOUT_S / 2)
        with contextlib.suppress(OSError):
            os.killpg(process.pid, signal.SIGKILL)  # whatever ignored SIGTERM
    with contextlib.suppress(OSError, subprocess.TimeoutExpired):
        process.kill()
        process.wait(timeout=KILL_TIMEOUT_S)


def _close_quietly(stream: IO[bytes] | None) -> None:
    if stream is not None:
        with contextlib.suppress(OSError):
            stream.close()
