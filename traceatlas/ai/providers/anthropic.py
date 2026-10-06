"""Anthropic Messages-API adapter (cloud)."""
from __future__ import annotations
import os, time
import httpx
from traceatlas.ai.providers.base import (BaseAIProvider, GenerationResult,
                                          ModelCapabilities, ModelUnavailableError)


class AnthropicProvider(BaseAIProvider):
    provider_name = "anthropic"
    default_privacy_class = "cloud"

    def __init__(self, api_key: str | None = None, timeout: float = 90.0):
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        self.base_url = os.environ.get("ANTHROPIC_BASE_URL", "https://api.anthropic.com").rstrip("/")
        self.timeout = timeout

    def _client(self):
        return httpx.Client(base_url=self.base_url, timeout=self.timeout,
                            headers={"x-api-key": self.api_key,
                                     "anthropic-version": "2023-06-01",
                                     "content-type": "application/json"})

    def generate(self, prompt, *, system="", model, temperature=0.1,
                 max_tokens=2048, json_mode=False) -> GenerationResult:
        if not self.api_key:
            raise ModelUnavailableError("anthropic: no API key configured")
        if json_mode:
            prompt += "\nRespond with ONLY one valid JSON object."
        payload = {"model": model, "max_tokens": max_tokens,
                   "temperature": temperature,
                   "messages": [{"role": "user", "content": prompt}]}
        if system:
            payload["system"] = system
        t0 = time.perf_counter()
        try:
            with self._client() as c:
                r = c.post("/v1/messages", json=payload)
                r.raise_for_status()
                data = r.json()
        except httpx.HTTPError as exc:
            raise ModelUnavailableError(f"anthropic generate failed: {exc}") from exc
        text = "".join(b.get("text", "") for b in data.get("content", []) if b.get("type") == "text")
        usage = data.get("usage") or {}
        return GenerationResult(text=text, model=model, provider=self.provider_name,
                                latency_ms=(time.perf_counter() - t0) * 1000.0,
                                input_tokens=int(usage.get("input_tokens", 0) or 0),
                                output_tokens=int(usage.get("output_tokens", 0) or 0), raw=data)

    def health(self) -> bool:
        return bool(self.api_key)

    def models(self) -> list[str]:
        return []

    def capabilities(self, model: str) -> ModelCapabilities:
        return ModelCapabilities(structured_output=True, tool_calling=True,
                                 vision=("claude" in model), context_window=200000,
                                 privacy_class="cloud")
