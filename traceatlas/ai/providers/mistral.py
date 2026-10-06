"""Mistral adapter (OpenAI-compatible API)."""
from __future__ import annotations
from traceatlas.ai.providers.openai import OpenAICompatibleProvider


class MistralProvider(OpenAICompatibleProvider):
    def __init__(self, base_url: str | None = None, api_key: str | None = None, **kw):
        super().__init__(base_url=base_url or "https://api.mistral.ai/v1",
                         api_key=api_key, provider_name="mistral", **kw)
