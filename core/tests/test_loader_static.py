from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from zirah.loaders import LoaderError, load_static
from zirah.loaders import static as static_module
from zirah.models import TargetKind

FIXTURES = Path(__file__).parent / "fixtures" / "manifests"


def write_json(tmp_path: Path, data: Any, name: str = "manifest.json") -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


# --- Fixtures shaped like real server responses ------------------------------------------


def test_loads_jsonrpc_tools_list_response() -> None:
    loaded = load_static(FIXTURES / "filesystem_tools_list.json")
    manifest = loaded.manifest
    assert [t.name for t in manifest.tools] == ["read_file", "write_file", "list_directory"]
    read_file = manifest.tools[0]
    assert read_file.title == "Read file"
    assert read_file.input_schema["required"] == ["path"]
    assert read_file.annotations == {"readOnlyHint": True}
    assert manifest.server_name is None
    assert loaded.target.kind is TargetKind.STATIC
    assert loaded.target.location == str(FIXTURES / "filesystem_tools_list.json")


def test_loads_combined_object_with_every_feature() -> None:
    manifest = load_static(FIXTURES / "everything_combined.json").manifest
    assert (manifest.server_name, manifest.server_version) == ("example-everything", "1.4.0")
    assert manifest.instructions == "Demo server that exposes one of each MCP feature."
    echo, ping = manifest.tools
    assert echo.output_schema == {"type": "object", "properties": {"echo": {"type": "string"}}}
    assert ping.description == ""  # JSON null description is treated as absent
    [prompt] = manifest.prompts
    assert prompt.title == "Summarize text"
    assert [(a.name, a.required) for a in prompt.arguments] == [("text", True), ("style", False)]
    [resource] = manifest.resources
    assert (resource.uri, resource.mime_type) == ("file:///docs/readme.md", "text/markdown")


def test_merges_recorded_session() -> None:
    loaded = load_static(FIXTURES / "recorded_session.json")
    manifest = loaded.manifest
    assert manifest.server_name == "example-notes"
    assert manifest.instructions == "Use these tools to manage the user's notes."
    assert [t.name for t in manifest.tools] == ["add_note"]
    assert [p.name for p in manifest.prompts] == ["daily_review"]
    assert manifest.resources == ()
    assert loaded.target.name == "example-notes"


def test_loading_is_deterministic() -> None:
    path = FIXTURES / "everything_combined.json"
    assert load_static(path).manifest.sha256() == load_static(path).manifest.sha256()


def test_invisible_characters_survive_loading(tmp_path: Path) -> None:
    hidden = "Adds numbers.​‮"
    path = write_json(tmp_path, {"tools": [{"name": "add", "description": hidden}]})
    assert load_static(path).manifest.tools[0].description == hidden


def test_utf8_bom_is_accepted(tmp_path: Path) -> None:
    path = tmp_path / "bom.json"
    path.write_bytes(b"\xef\xbb\xbf" + json.dumps({"tools": []}).encode("utf-8"))
    assert load_static(path).manifest.tools == ()


def test_unknown_keys_are_ignored(tmp_path: Path) -> None:
    path = write_json(
        tmp_path,
        {"tools": [{"name": "t", "icons": [], "_meta": {}}], "nextCursor": "abc", "extra": 1},
    )
    assert load_static(path).manifest.tools[0].name == "t"


def test_tool_without_input_schema_gets_empty_schema(tmp_path: Path) -> None:
    path = write_json(tmp_path, {"tools": [{"name": "t"}]})
    assert load_static(path).manifest.tools[0].input_schema == {}


# --- Readable errors ---------------------------------------------------------------------


def assert_error(path: Path, message: str) -> None:
    with pytest.raises(LoaderError, match=message) as info:
        load_static(path)
    assert str(info.value).startswith(str(path))


def test_missing_file(tmp_path: Path) -> None:
    assert_error(tmp_path / "missing.json", "file not found")


def test_directory_is_not_a_file(tmp_path: Path) -> None:
    assert_error(tmp_path, "not a file")


def test_unreadable_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = write_json(tmp_path, {"tools": []})

    def deny(self: Path, *args: Any, **kwargs: Any) -> Any:
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(Path, "stat", deny)
    assert_error(path, "cannot read file: Permission denied")


def test_oversized_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(static_module, "MAX_MANIFEST_BYTES", 10)
    assert_error(write_json(tmp_path, {"tools": []}), "the limit is 10")


def test_invalid_json_reports_position(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_text('{"tools": [\n  {"name": "a",}\n]}', encoding="utf-8")
    assert_error(path, "invalid JSON at line 2, column")


def test_invalid_utf8(tmp_path: Path) -> None:
    path = tmp_path / "latin1.json"
    path.write_bytes('{"tools": [{"name": "café"}]}'.encode("latin-1"))
    assert_error(path, "not valid UTF-8")


def test_jsonrpc_error_response(tmp_path: Path) -> None:
    path = write_json(
        tmp_path, {"jsonrpc": "2.0", "id": 1, "error": {"code": -32601, "message": "nope"}}
    )
    assert_error(path, "is a JSON-RPC error response")


def test_no_mcp_data(tmp_path: Path) -> None:
    assert_error(write_json(tmp_path, {"hello": "world"}), "no MCP data found")


@pytest.mark.parametrize(
    ("data", "message"),
    [
        ("just a string", r"top level: must be an object, not a string"),
        ([{"tools": []}, 5], r"\[1\]: must be an object, not a number"),
        ({"tools": {"name": "t"}}, r"tools: must be a list"),
        ({"tools": [None]}, r"tools\[0\]: must be an object, not null"),
        ({"tools": [{"name": ""}]}, r"tools\[0\]\.name: string should have at least 1"),
        ({"tools": [{"description": "no name"}]}, r"tools\[0\]\.name: input should be a valid"),
        ({"tools": [{"name": "t", "description": 5}]}, r"tools\[0\]\.description"),
        ({"tools": [{"name": "t", "inputSchema": []}]}, r"tools\[0\]\.input_schema"),
        ({"prompts": [{"name": "p", "arguments": {}}]}, r"prompts\[0\]\.arguments: must be a list"),
        ({"prompts": [{"name": "p", "arguments": [{}]}]}, r"prompts\[0\]\.arguments\[0\]\.name"),
        ({"resources": [{"name": "r"}]}, r"resources\[0\]\.uri"),
        ({"serverInfo": "demo"}, r"serverInfo: must be an object, not a string"),
        ({"serverInfo": {"name": 3}}, r"serverInfo\.name: must be a string, not a number"),
        ({"instructions": True}, r"instructions: must be a string, not a boolean"),
        ({"jsonrpc": "2.0", "result": []}, r"result: must be an object, not a list"),
    ],
)
def test_malformed_input_names_the_element(tmp_path: Path, data: Any, message: str) -> None:
    assert_error(write_json(tmp_path, data), message)


def test_error_in_list_part_is_prefixed_with_index(tmp_path: Path) -> None:
    path = write_json(tmp_path, [{"tools": []}, {"tools": [{"name": ""}]}])
    assert_error(path, r"\[1\]tools\[0\]\.name")
