"""OpenAI-compatible chat-completions adapter (openai.com, and any endpoint
speaking the same API — used by qwen/deepseek/mistral adapters below).

Cloud provider: privacy_class="cloud". Never selected when AI_MODE=local_only.
Model ids come from configuration only (no hardcoded model names).
"""

from __future__ import annotations

import os
import time

import httpx

from traceatlas.ai.providers.base import (
    BaseAIProvider, GenerationResult, ModelCapabilities, ModelUnavailableError,
)


class OpenAICompatibleProvider(BaseAIProvider):
    provider_name = "openai"
    default_privacy_class = "cloud"

    def __init__(self, base_url: str | None = None, api_key: str | None = None,
                 timeout: float = 90.0, provider_name: str | None = None):
        self.provider_name = provider_name or "openai"
        env_prefix = self.provider_name.upper()
        self.base_url = (base_url or os.environ.get(f"{env_prefix}_BASE_URL")
                         or "https://api.openai.com/v1").rstrip("/")
        self.api_key = api_key or os.environ.get(f"{env_prefix}_API_KEY", "")
        self.timeout = timeout

    def _client(self) -> httpx.Client:
        return httpx.Client(
            base_url=self.base_url, timeout=self.timeout,
            headers={"Authorization": f"Bearer {self.api_key}",
                     "Content-Type": "application/json"})

    def generate(self, prompt: str, *, system: str = "", model: str,
                 temperature: float = 0.1, max_tokens: int = 2048,
                 json_mode: bool = False) -> GenerationResult:
        if not self.api_key:
            raise ModelUnavailableError(f"{self.provider_name}: no API key configured")
        messages = ([{"role": "system", "content": system}] if system else []) + \
                   [{"role": "user", "content": prompt}]
        payload: dict = {"model": model, "messages": messages,
                         "temperature": temperature, "max_tokens": max_tokens}
        if json_mode:
            payload["response_format"] = {"type": "json_object"}
        t0 = time.perf_counter()
        try:
            with self._client() as c:
                r = c.post("/chat/completions", json=payload)
                r.raise_for_status()
                data = r.json()
        except httpx.HTTPError as exc:
            raise ModelUnavailableError(f"{self.provider_name} generate failed: {exc}") from exc
        latency = (time.perf_counter() - t0) * 1000.0
        usage = data.get("usage") or {}
        text = (data.get("choices") or [{}])[0].get("message", {}).get("content", "")
        return GenerationResult(text=text or "", model=model,
                                provider=self.provider_name, latency_ms=latency,
                                input_tokens=int(usage.get("prompt_tokens", 0) or 0),
                                output_tokens=int(usage.get("completion_tokens", 0) or 0),
                                raw=data)

    def embed(self, texts: list[str], *, model: str) -> list[list[float]]:
        if not self.api_key:
            raise ModelUnavailableError(f"{self.provider_name}: no API key configured")
        with self._client() as c:
            r = c.post("/embeddings", json={"model": model, "input": texts})
            r.raise_for_status()
            return [item["embedding"] for item in r.json().get("data", [])]

    def health(self) -> bool:
        if not self.api_key:
            return False
        try:
            with self._client() as c:
                return c.get("/models").status_code == 200
        except httpx.HTTPError:
            return False

    def models(self) -> list[str]:
        if not self.api_key:
            return []
        try:
            with self._client() as c:
                r = c.get("/models")
                r.raise_for_status()
                return [m["id"] for m in r.json().get("data", [])]
        except httpx.HTTPError as exc:
            raise ModelUnavailableError(str(exc)) from exc

    def capabilities(self, model: str) -> ModelCapabilities:
        vision_markers = ("gpt-4o", "gpt-4.1", "-vision", "qwen-vl", "llava")
        return ModelCapabilities(
            structured_output=True, tool_calling=True,
            vision=any(m in model for m in vision_markers),
            embeddings=("-embed" in model or "embedding" in model),
            context_window=(128000 if "gpt-4" in model else 32768),
            privacy_class="cloud")


class OpenAIProvider(OpenAICompatibleProvider):
    def __init__(self, **kw):
        kw.setdefault("provider_name", "openai")
        super().__init__(**kw)
