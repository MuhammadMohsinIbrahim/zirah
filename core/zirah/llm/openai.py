"""OpenAI Chat Completions over plain HTTP (no SDK, to keep the runtime dependencies small).

The API key comes only from ``OPENAI_API_KEY`` and is sent only in the ``Authorization``
header. Replies are constrained with a strict ``json_schema`` response format.
"""

from __future__ import annotations

from typing import Any, Final

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

API_URL: Final = "https://api.openai.com/v1/chat/completions"
KEY_ENV: Final = "OPENAI_API_KEY"
DEFAULT_MODEL: Final = "gpt-4.1-mini"
SCHEMA_NAME: Final = "zirah_verdict"


class OpenAIClient(LlmClient):
    provider = LlmProvider.OPENAI

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
            raise LlmError(f"openai: set {KEY_ENV} to use this provider")
        self._api_key = api_key
        self._url = url

    def __repr__(self) -> str:  # never show the key
        return f"OpenAIClient(model={self.model!r})"

    def complete_json(self, system: str, user: str, schema: dict[str, Any]) -> str:
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": TEMPERATURE,
            "max_completion_tokens": MAX_OUTPUT_TOKENS,
            "response_format": {
                "type": "json_schema",
                "json_schema": {"name": SCHEMA_NAME, "schema": schema, "strict": True},
            },
        }
        headers = {"Authorization": f"Bearer {self._api_key}"}
        data = self._post(self._url, payload, headers)
        message = dig(data, "choices", 0, "message")
        if isinstance(dig(message, "refusal"), str):
            raise LlmError("openai: the model declined to answer")
        if dig(data, "choices", 0, "finish_reason") == "length":
            raise LlmError("openai: the reply was cut off at the token limit")
        content = dig(message, "content")
        if not isinstance(content, str):
            raise LlmError("openai: response has no message content")
        return content
