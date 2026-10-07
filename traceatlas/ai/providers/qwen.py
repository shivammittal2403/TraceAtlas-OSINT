"""Qwen via OpenAI-compatible endpoint (DashScope compat or local vLLM/Ollama-OpenAI shim)."""

from __future__ import annotations

import os

from traceatlas.ai.providers.openai import OpenAICompatibleProvider


class QwenProvider(OpenAICompatibleProvider):
    name = "qwen"

    def __init__(self, spec, api_key=None, base_url=None, timeout_s=90.0):
        super().__init__(spec,
                         api_key=api_key or os.environ.get("QWEN_API_KEY", ""),
                         base_url=base_url or os.environ.get(
                             "QWEN_BASE_URL", "https://dashscope.aliyuncs.com/compatible-mode/v1"),
                         timeout_s=timeout_s)
