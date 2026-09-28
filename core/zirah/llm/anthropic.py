"""Anthropic Messages API over plain HTTP (no SDK, to keep the runtime dependencies small).

The API key comes only from ``ANTHROPIC_API_KEY`` and is sent only in the ``x-api-key``
header. Replies are constrained with structured outputs (``output_config.format``).

Current models (Claude Opus 5, Sonnet 5, Opus 4.7/4.8, Fable, Mythos) reject sampling
parameters, so ``temperature`` is sent only to models that still accept it. On the models
that support it, ``fallbacks: "default"`` lets the API retry a safety refusal on another
model instead of returning it.
"""

from __future__ import annotations

from typing import Any, Final

import httpx

from zirah.llm.base import DEFAULT_TIMEOUT_S, TEMPERATURE, LlmClient, LlmError, dig
from zirah.models import LlmProvider

API_URL: Final = "https://api.anthropic.com/v1/messages"
API_VERSION: Final = "2023-06-01"
KEY_ENV: Final = "ANTHROPIC_API_KEY"
DEFAULT_MODEL: Final = "claude-opus-5"

MAX_TOKENS: Final = 16000
"""Output budget per request; thinking tokens count against it on current models."""

NO_SAMPLING_PARAMS: Final = (
    "claude-opus-5",
    "claude-sonnet-5",
    "claude-opus-4-7",
    "claude-opus-4-8",
    "claude-fable-",
    "claude-mythos-",
)
"""Model id prefixes that reject ``temperature`` (HTTP 400)."""

FALLBACK_MODELS: Final = ("claude-opus-5", "claude-fable-5-1")
"""Models that take ``fallbacks: "default"`` with the header below."""
FALLBACK_BETA: Final = "server-side-fallback-2026-07-01"


class AnthropicClient(LlmClient):
    provider = LlmProvider.ANTHROPIC

    def __init__(
        self,
        api_key: str,
        model: str = DEFAULT_MODEL,
        *,
        url: str = API_URL,
        timeout: float = DEFAULT_TIMEOUT_S,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        super().__init__(model, timeout=timeout, transport=transport)
        if not api_key:
            raise LlmError(f"anthropic: set {KEY_ENV} to use this provider")
        self._api_key = api_key
        self._url = url

    def __repr__(self) -> str:  # never show the key
        return f"AnthropicClient(model={self.model!r})"

    @property
    def temperature(self) -> float | None:
        return None if self.model.startswith(NO_SAMPLING_PARAMS) else TEMPERATURE

    def complete_json(self, system: str, user: str, schema: dict[str, Any]) -> str:
        payload: dict[str, Any] = {
            "model": self.model,
            "max_tokens": MAX_TOKENS,
            "system": system,
            "messages": [{"role": "user", "content": user}],
            "output_config": {"format": {"type": "json_schema", "schema": schema}},
        }
        headers = {"x-api-key": self._api_key, "anthropic-version": API_VERSION}
        if self.temperature is not None:
            payload["temperature"] = self.temperature
        if self.model in FALLBACK_MODELS:
            payload["fallbacks"] = "default"
            headers["anthropic-beta"] = FALLBACK_BETA

        data = self._post(self._url, payload, headers)
        stop_reason = dig(data, "stop_reason")
        if stop_reason == "refusal":
            raise LlmError("anthropic: the model declined to answer")
        if stop_reason == "max_tokens":
            raise LlmError("anthropic: the reply was cut off at the token limit")
        # Thinking and fallback blocks may come first; the JSON reply is in the text blocks.
        content = dig(data, "content")
        texts: list[str] = []
        for block in content if isinstance(content, list) else []:
            if isinstance(block, dict) and block.get("type") == "text":
                text = block.get("text")
                if isinstance(text, str):
                    texts.append(text)
        if not texts:
            raise LlmError("anthropic: response has no text content")
        return "".join(texts)
