"""Qwen adapter: DashScope's OpenAI-compatible endpoint or a local runtime."""
from __future__ import annotations
from traceatlas.ai.providers.openai import OpenAICompatibleProvider


class QwenProvider(OpenAICompatibleProvider):
    def __init__(self, base_url: str | None = None, api_key: str | None = None, **kw):
        super().__init__(base_url=base_url or "https://dashscope.aliyuncs.com/compatible-mode/v1",
                         api_key=api_key, provider_name="qwen", **kw)
