"""Ollama: a local model server. No API key; nothing leaves the machine."""

from __future__ import annotations

from typing import Any, Final
from urllib.parse import urlsplit

import httpx

from zirah.llm.base import (
    DEFAULT_TIMEOUT_S,
    MAX_OUTPUT_TOKENS,
    TEMPERATURE,
    LlmClient,
    LlmError,
    dig,
)
from zirah.models import LlmProvider

DEFAULT_HOST: Final = "http://localhost:11434"
DEFAULT_MODEL: Final = "llama3.1:8b"


class OllamaClient(LlmClient):
    provider = LlmProvider.OLLAMA

    def __init__(
        self,
        model: str = DEFAULT_MODEL,
        *,
        host: str = DEFAULT_HOST,
        timeout: float = DEFAULT_TIMEOUT_S,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        super().__init__(model, timeout=timeout, transport=transport)
        self.host = normalize_host(host)

    def complete_json(self, system: str, user: str, schema: dict[str, Any]) -> str:
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "stream": False,
            "format": schema,
            "options": {"temperature": TEMPERATURE, "seed": 0, "num_predict": MAX_OUTPUT_TOKENS},
        }
        data = self._post(f"{self.host}/api/chat", payload, headers={})
        content = dig(data, "message", "content")
        if not isinstance(content, str):
            raise LlmError("ollama: response has no message content")
        return content


def normalize_host(host: str) -> str:
    """``OLLAMA_HOST`` as a base URL: ``localhost:11434`` gets ``http://``, and only http(s)
    is accepted."""
    host = host.strip()
    if "://" not in host:
        host = "http://" + host
    try:
        url = urlsplit(host)
        valid = url.scheme in ("http", "https") and bool(url.hostname)
        url.port  # noqa: B018 - raises on a malformed port
    except ValueError:
        valid = False
    if not valid:
        raise LlmError(f"ollama: invalid host {host!r}; expected http(s)://host:port")
    return host.rstrip("/")
