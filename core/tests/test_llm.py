from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx
import pytest
from typer.testing import CliRunner

from zirah.cli import EXIT_CLEAN, EXIT_ERROR, app
from zirah.llm import LlmError, LlmRateLimitError, resolve
from zirah.llm.base import MAX_RESPONSE_BYTES, TEMPERATURE, dig
from zirah.llm.ollama import DEFAULT_HOST, DEFAULT_MODEL, OllamaClient, normalize_host
from zirah.models import LlmInfo, LlmProvider

SCHEMA: dict[str, Any] = {"type": "object", "properties": {"ok": {"type": "boolean"}}}
BENIGN = str(Path(__file__).parent / "fixtures" / "analyzers" / "benign" / "everyday_tools.json")

Handler = Callable[[httpx.Request], httpx.Response]


def ollama(handler: Handler, **kwargs: Any) -> OllamaClient:
    return OllamaClient(transport=httpx.MockTransport(handler), **kwargs)


# --- resolve ---------------------------------------------------------------------------------


def test_default_is_none() -> None:
    assert resolve(None, env={}) is None
    assert resolve("none", env={}) is None
    assert resolve("NONE", env={"ZIRAH_LLM": "ollama"}) is None


def test_env_var_is_used_when_no_flag() -> None:
    client = resolve(None, env={"ZIRAH_LLM": "ollama"})
    assert isinstance(client, OllamaClient)
    assert (client.model, client.host) == (DEFAULT_MODEL, DEFAULT_HOST)


def test_flag_overrides_env_and_model_may_contain_colons() -> None:
    client = resolve("ollama:qwen2.5:7b", env={"ZIRAH_LLM": "none", "OLLAMA_HOST": "gpu:11434"})
    assert isinstance(client, OllamaClient)
    assert (client.model, client.host) == ("qwen2.5:7b", "http://gpu:11434")
    assert client.info == LlmInfo(provider=LlmProvider.OLLAMA, model="qwen2.5:7b", temperature=0.0)


@pytest.mark.parametrize(
    ("spec", "message"),
    [
        ("none:model", "does not take a model"),
        ("gpt", "unknown LLM provider 'gpt'"),
    ],
)
def test_bad_specs(spec: str, message: str) -> None:
    with pytest.raises(LlmError, match=message):
        resolve(spec, env={})


@pytest.mark.parametrize(
    ("host", "url"),
    [
        ("localhost:11434", "http://localhost:11434"),
        ("http://127.0.0.1:11434/", "http://127.0.0.1:11434"),
        (" https://ollama.example.invalid ", "https://ollama.example.invalid"),
    ],
)
def test_normalize_host(host: str, url: str) -> None:
    assert normalize_host(host) == url


@pytest.mark.parametrize("host", ["ftp://example.invalid", "http://", "http://[bad"])
def test_invalid_host(host: str) -> None:
    with pytest.raises(LlmError, match="invalid host"):
        normalize_host(host)


def test_model_is_required() -> None:
    with pytest.raises(LlmError, match="model name is required"):
        OllamaClient("")


# --- Ollama over mocked HTTP -------------------------------------------------------------------


def test_ollama_success_sends_temperature_0_and_the_schema() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(
            200, json={"message": {"role": "assistant", "content": '{"ok":true}'}}
        )

    client = ollama(handler, model="llama3.1:8b", host="localhost:11434")
    assert client.complete_json("system text", "user text", SCHEMA) == '{"ok":true}'
    (request,) = seen
    assert str(request.url) == "http://localhost:11434/api/chat"
    body = json.loads(request.content)
    assert body["model"] == "llama3.1:8b"
    assert body["stream"] is False
    assert body["format"] == SCHEMA
    assert body["options"]["temperature"] == TEMPERATURE == 0.0
    assert body["messages"] == [
        {"role": "system", "content": "system text"},
        {"role": "user", "content": "user text"},
    ]
    assert "authorization" not in request.headers


@pytest.mark.parametrize(
    ("response", "error", "message"),
    [
        (httpx.Response(429), LlmRateLimitError, "rate limited"),
        (httpx.Response(500, text="boom"), LlmError, "HTTP 500"),
        (httpx.Response(404), LlmError, "HTTP 404"),
        (httpx.Response(200, text="not json"), LlmError, "not valid JSON"),
        (httpx.Response(200, json={"message": {}}), LlmError, "no message content"),
        (httpx.Response(200, json=["x"]), LlmError, "no message content"),
        (
            httpx.Response(200, content=b" " * (MAX_RESPONSE_BYTES + 1)),
            LlmError,
            "larger than",
        ),
    ],
    ids=["429", "500", "404", "not-json", "no-content", "wrong-shape", "too-large"],
)
def test_ollama_error_paths(response: httpx.Response, error: type[LlmError], message: str) -> None:
    client = ollama(lambda _: response)
    with pytest.raises(error, match=message):
        client.complete_json("s", "u", SCHEMA)


@pytest.mark.parametrize(
    ("exc", "message"),
    [
        (httpx.ReadTimeout("slow"), "no response within 5 s"),
        (httpx.ConnectError("refused"), "cannot reach http://localhost:11434 \\(ConnectError\\)"),
    ],
)
def test_ollama_network_errors(exc: Exception, message: str) -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        raise exc

    with pytest.raises(LlmError, match=message):
        ollama(handler, timeout=5).complete_json("s", "u", SCHEMA)


def test_dig() -> None:
    data = {"a": [{"b": 1}]}
    assert dig(data, "a", 0, "b") == 1
    assert dig(data, "a", -1, "b") == 1
    assert dig(data, "a", 1) is None
    assert dig(data, "x") is None
    assert dig(data, "a", "b") is None
    assert dig(data, "a", 0, "b", "c") is None


# --- CLI ---------------------------------------------------------------------------------------


def test_llm_none_needs_no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def no_network(*args: object, **kwargs: object) -> None:
        raise AssertionError("network used with --llm none")

    monkeypatch.setattr(httpx.Client, "send", no_network)
    monkeypatch.delenv("ZIRAH_LLM", raising=False)
    for args in (["scan", BENIGN], ["scan", BENIGN, "--llm", "none"]):
        assert CliRunner().invoke(app, args).exit_code == EXIT_CLEAN


def test_bad_llm_flag_is_a_usage_error() -> None:
    result = CliRunner().invoke(app, ["scan", BENIGN, "--llm", "gpt"])
    assert result.exit_code == EXIT_ERROR
    assert "unknown LLM provider 'gpt'" in result.stderr
