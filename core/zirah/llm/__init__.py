"""LLM providers for the optional semantic judge.

Provider code lives only in this package. ``resolve`` turns ``--llm`` or ``ZIRAH_LLM`` into a
client: ``none`` (the default, fully offline), ``ollama[:model]``, ``openai[:model]`` or
``anthropic[:model]``. API keys are read only from ``OPENAI_API_KEY`` and
``ANTHROPIC_API_KEY``.
"""

from __future__ import annotations

import os
from collections.abc import Mapping

from zirah.llm import anthropic, ollama, openai
from zirah.llm.base import LlmClient, LlmError, LlmRateLimitError

__all__ = ["LlmClient", "LlmError", "LlmRateLimitError", "resolve"]

ENV_VAR = "ZIRAH_LLM"
NONE = "none"
PROVIDERS = ("none", "ollama", "openai", "anthropic")


def resolve(spec: str | None = None, env: Mapping[str, str] | None = None) -> LlmClient | None:
    """The client for ``spec`` (e.g. ``ollama:llama3.1:8b``), falling back to ``ZIRAH_LLM``
    and then to ``none``. Returns ``None`` for ``none``; raises :class:`LlmError` on an
    unknown provider, a missing API key or bad settings."""
    env = os.environ if env is None else env
    spec = (spec or env.get(ENV_VAR) or NONE).strip()
    name, _, model = spec.partition(":")
    name = name.strip().lower()
    model = model.strip()
    if name == NONE:
        if model:
            raise LlmError("--llm none does not take a model")
        return None
    if name == "ollama":
        host = env.get("OLLAMA_HOST") or ollama.DEFAULT_HOST
        return ollama.OllamaClient(model or ollama.DEFAULT_MODEL, host=host)
    if name == "openai":
        key = env.get(openai.KEY_ENV, "")
        return openai.OpenAIClient(key, model or openai.DEFAULT_MODEL)
    if name == "anthropic":
        key = env.get(anthropic.KEY_ENV, "")
        return anthropic.AnthropicClient(key, model or anthropic.DEFAULT_MODEL)
    raise LlmError(f"unknown LLM provider {name!r}; use one of: {', '.join(PROVIDERS)}")
