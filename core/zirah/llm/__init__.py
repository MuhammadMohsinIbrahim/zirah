"""LLM providers for the optional semantic judge.

Provider code lives only in this package. ``resolve`` turns ``--llm`` or ``ZIRAH_LLM`` into a
client: ``none`` (the default, fully offline) or ``ollama[:model]``.
"""

from __future__ import annotations

import os
from collections.abc import Mapping

from zirah.llm.base import LlmClient, LlmError, LlmRateLimitError
from zirah.llm.ollama import DEFAULT_HOST, OllamaClient

__all__ = ["LlmClient", "LlmError", "LlmRateLimitError", "resolve"]

ENV_VAR = "ZIRAH_LLM"
NONE = "none"


def resolve(spec: str | None = None, env: Mapping[str, str] | None = None) -> LlmClient | None:
    """The client for ``spec`` (e.g. ``ollama:llama3.1:8b``), falling back to ``ZIRAH_LLM``
    and then to ``none``. Returns ``None`` for ``none``; raises :class:`LlmError` on an
    unknown provider or bad settings."""
    env = os.environ if env is None else env
    spec = (spec or env.get(ENV_VAR) or NONE).strip()
    name, _, model = spec.partition(":")
    name = name.strip().lower()
    if name == NONE:
        if model:
            raise LlmError("--llm none does not take a model")
        return None
    if name == "ollama":
        host = env.get("OLLAMA_HOST") or DEFAULT_HOST
        return OllamaClient(model, host=host) if model else OllamaClient(host=host)
    raise LlmError(f"unknown LLM provider {name!r}; use one of: none, ollama")
