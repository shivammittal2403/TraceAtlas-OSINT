"""DeepSeek via its OpenAI-compatible API."""

from __future__ import annotations

import os

from traceatlas.ai.providers.openai import OpenAICompatibleProvider


class DeepSeekProvider(OpenAICompatibleProvider):
    name = "deepseek"

    def __init__(self, spec, api_key=None, base_url=None, timeout_s=90.0):
        super().__init__(spec,
                         api_key=api_key or os.environ.get("DEEPSEEK_API_KEY", ""),
                         base_url=base_url or os.environ.get(
                             "DEEPSEEK_BASE_URL", "https://api.deepseek.com/v1"),
                         timeout_s=timeout_s)
