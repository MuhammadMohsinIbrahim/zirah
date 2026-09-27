"""Load a manifest from a JSON file, without contacting or running the server.

Accepted layouts (MCP field names, camelCase):

- A combined object with any of ``serverInfo``, ``instructions``, ``tools``, ``prompts``,
  ``resources``: what ``initialize`` plus the three ``*/list`` calls return.
- A JSON-RPC response (``{"jsonrpc": "2.0", "id": 1, "result": {...}}``); ``result`` is used.
- A list of the above, e.g. a recorded session; the parts are merged into one manifest.

Unknown keys (``nextCursor``, ``capabilities``, ``_meta``, ...) are ignored.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ValidationError

from zirah.loaders.base import Loaded, LoaderError
from zirah.models import Manifest, Prompt, PromptArgument, Resource, Target, TargetKind, Tool

MAX_MANIFEST_BYTES = 20 * 1024 * 1024
"""Refuse larger files: a manifest is kilobytes, and the input is untrusted."""


def load_static(path: Path) -> Loaded:
    """Read a manifest JSON file. Raises :class:`LoaderError` with a readable message."""
    data = _parse(path)
    parts = data if isinstance(data, list) else [data]

    tools: list[Tool] = []
    prompts: list[Prompt] = []
    resources: list[Resource] = []
    server_name: str | None = None
    server_version: str | None = None
    instructions: str | None = None
    found = False

    for index, raw_part in enumerate(parts):
        where = f"[{index}]" if isinstance(data, list) else ""
        part = _unwrap(_expect_dict(raw_part, where or "top level", path), where, path)

        if "serverInfo" in part:
            found = True
            info = _expect_dict(part["serverInfo"], f"{where}serverInfo", path)
            server_name = _optional_str(info.get("name"), f"{where}serverInfo.name", path)
            server_version = _optional_str(info.get("version"), f"{where}serverInfo.version", path)
        if "instructions" in part:
            found = True
            instructions = _optional_str(part["instructions"], f"{where}instructions", path)
        if "tools" in part:
            found = True
            tools += [_tool(t, w, path) for w, t in _items(part, "tools", where, path)]
        if "prompts" in part:
            found = True
            prompts += [_prompt(p, w, path) for w, p in _items(part, "prompts", where, path)]
        if "resources" in part:
            found = True
            resources += [_resource(r, w, path) for w, r in _items(part, "resources", where, path)]

    if not found:
        raise _error(
            path, None, "no MCP data found (expected tools, prompts, resources, serverInfo)"
        )

    manifest = Manifest(
        server_name=server_name,
        server_version=server_version,
        instructions=instructions,
        tools=tuple(tools),
        prompts=tuple(prompts),
        resources=tuple(resources),
    )
    # The path is kept as given: resolving it would put the user's directories into reports.
    target = Target(kind=TargetKind.STATIC, location=str(path), name=server_name)
    return Loaded(target=target, manifest=manifest)


# --- Reading -----------------------------------------------------------------------------


def _parse(path: Path) -> Any:
    try:
        size = path.stat().st_size
    except FileNotFoundError:
        raise _error(path, None, "file not found") from None
    except OSError as exc:
        raise _error(path, None, f"cannot read file: {exc.strerror}") from exc
    if not path.is_file():
        raise _error(path, None, "not a file")
    if size > MAX_MANIFEST_BYTES:
        raise _error(path, None, f"file is {size} bytes; the limit is {MAX_MANIFEST_BYTES}")

    try:
        text = path.read_bytes().decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise _error(path, None, f"not valid UTF-8 (byte {exc.start})") from exc
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise _error(
            path, None, f"invalid JSON at line {exc.lineno}, column {exc.colno}: {exc.msg}"
        ) from exc


def _items(part: dict[str, Any], key: str, where: str, path: Path) -> list[tuple[str, Any]]:
    """The list at ``part[key]``, each item paired with its location for error messages."""
    items = part[key]
    if not isinstance(items, list):
        raise _error(path, f"{where}{key}", "must be a list")
    return [(f"{where}{key}[{i}]", item) for i, item in enumerate(items)]


def _unwrap(part: dict[str, Any], where: str, path: Path) -> dict[str, Any]:
    if "error" in part and "jsonrpc" in part:
        raise _error(path, where or None, "is a JSON-RPC error response, not a result")
    if "result" in part and "jsonrpc" in part:
        return _expect_dict(part["result"], f"{where}result", path)
    return part


# --- Mapping MCP objects to the contract --------------------------------------------------


def _tool(raw: Any, where: str, path: Path) -> Tool:
    obj = _expect_dict(raw, where, path)
    return _build(
        Tool,
        where,
        path,
        name=obj.get("name"),
        title=obj.get("title"),
        description=_description(obj),
        input_schema=obj.get("inputSchema", {}),
        output_schema=obj.get("outputSchema"),
        annotations=obj.get("annotations"),
    )


def _prompt(raw: Any, where: str, path: Path) -> Prompt:
    obj = _expect_dict(raw, where, path)
    arguments = obj.get("arguments")
    if arguments is None:
        arguments = []
    if not isinstance(arguments, list):
        raise _error(path, f"{where}.arguments", "must be a list")
    return _build(
        Prompt,
        where,
        path,
        name=obj.get("name"),
        title=obj.get("title"),
        description=_description(obj),
        arguments=tuple(
            _argument(a, f"{where}.arguments[{i}]", path) for i, a in enumerate(arguments)
        ),
    )


def _argument(raw: Any, where: str, path: Path) -> PromptArgument:
    obj = _expect_dict(raw, where, path)
    return _build(
        PromptArgument,
        where,
        path,
        name=obj.get("name"),
        description=_description(obj),
        required=obj.get("required", False),
    )


def _resource(raw: Any, where: str, path: Path) -> Resource:
    obj = _expect_dict(raw, where, path)
    return _build(
        Resource,
        where,
        path,
        uri=obj.get("uri"),
        name=obj.get("name"),
        title=obj.get("title"),
        description=_description(obj),
        mime_type=obj.get("mimeType"),
    )


def _description(obj: dict[str, Any]) -> Any:
    # MCP makes description optional; a JSON null means the same as absent.
    value = obj.get("description")
    return "" if value is None else value


def _build[M: BaseModel](model: type[M], where: str, path: Path, **fields: Any) -> M:
    try:
        return model.model_validate(fields)
    except ValidationError as exc:
        error = exc.errors()[0]
        field = ".".join(str(part) for part in error["loc"])
        raise _error(path, f"{where}.{field}", error["msg"].lower()) from exc


# --- Helpers -----------------------------------------------------------------------------


def _expect_dict(value: Any, where: str, path: Path) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise _error(path, where, f"must be an object, not {_json_type(value)}")
    return value


def _optional_str(value: Any, where: str, path: Path) -> str | None:
    if value is None or isinstance(value, str):
        return value
    raise _error(path, where, f"must be a string, not {_json_type(value)}")


def _json_type(value: Any) -> str:
    kinds: dict[type, str] = {dict: "an object", list: "a list", str: "a string", bool: "a boolean"}
    if value is None:
        return "null"
    if isinstance(value, int | float) and not isinstance(value, bool):
        return "a number"
    return kinds.get(type(value), type(value).__name__)


def _error(path: Path, where: str | None, message: str) -> LoaderError:
    return LoaderError(f"{path}: {where}: {message}" if where else f"{path}: {message}")
