"""Ollama provider adapter — first-class LOCAL model support (§26, §28).

Talks to the Ollama HTTP API (default http://localhost:11434, override with
OLLAMA_BASE_URL). No model name is hardcoded: models come from configuration
(TRACEATLAS_PRIMARY_MODEL / TRACEATLAS_SECONDARY_MODEL / ... resolved by the
gateway into ids like "ollama/llama3.1").

Privacy class is always "local": data never leaves the configured host.
"""

from __future__ import annotations

import os
import time

import httpx

from traceatlas.ai.providers.base import (
    BaseAIProvider,
    GenerationResult,
    ModelCapabilities,
    ModelUnavailableError,
)

DEFAULT_OLLAMA_BASE_URL = "http://localhost:11434"


class OllamaProvider(BaseAIProvider):
    provider_name = "ollama"
    default_privacy_class = "local"

    def __init__(self, base_url: str | None = None,
                 api_key: str | None = None, timeout: float = 120.0):
        self.base_url = (base_url or os.environ.get("OLLAMA_BASE_URL")
                         or DEFAULT_OLLAMA_BASE_URL).rstrip("/")
        # optional bearer token for authenticated/proxied ollama deployments
        self.api_key = api_key or os.environ.get("OLLAMA_API_KEY", "")
        self.timeout = timeout

    # ------------------------------------------------------------- internals
    def _client(self) -> httpx.Client:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return httpx.Client(base_url=self.base_url, headers=headers,
                            timeout=self.timeout)

    @staticmethod
    def _bare(model: str) -> str:
        """Accept 'ollama/llama3.1' gateway ids as well as bare 'llama3.1'."""
        return model.split("/", 1)[1] if model.startswith("ollama/") else model

    # ------------------------------------------------------------------ core
    def generate(self, prompt: str, *, system: str = "", model: str,
                 temperature: float = 0.1, max_tokens: int = 2048,
                 json_mode: bool = False) -> GenerationResult:
        payload = {
            "model": self._bare(model),
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": temperature, "num_predict": max_tokens},
        }
        if system:
            payload["system"] = system
        if json_mode:
            payload["format"] = "json"
        t0 = time.perf_counter()
        try:
            with self._client() as c:
                r = c.post("/api/generate", json=payload)
                r.raise_for_status()
                data = r.json()
        except httpx.HTTPError as exc:
            raise ModelUnavailableError(f"ollama generate failed: {exc}") from exc
        latency = (time.perf_counter() - t0) * 1000.0
        return GenerationResult(
            text=data.get("response", ""),
            model=self._bare(model),
            provider=self.provider_name,
            latency_ms=latency,
            input_tokens=int(data.get("prompt_eval_count", 0) or 0),
            output_tokens=int(data.get("eval_count", 0) or 0),
            raw=data,
        )

    def embed(self, texts: list[str], *, model: str) -> list[list[float]]:
        payload = {"model": self._bare(model), "input": texts}
        try:
            with self._client() as c:
                r = c.post("/api/embed", json=payload)
                r.raise_for_status()
                return [[float(x) for x in vec] for vec in r.json().get("embeddings", [])]
        except httpx.HTTPError as exc:
            raise ModelUnavailableError(f"ollama embed failed: {exc}") from exc

    # ------------------------------------------------------------------ ops
    def health(self) -> bool:
        try:
            with self._client() as c:
                return c.get("/api/tags").status_code == 200
        except httpx.HTTPError:
            return False

    def models(self) -> list[str]:
        try:
            with self._client() as c:
                r = c.get("/api/tags")
                r.raise_for_status()
                return [m["name"] for m in r.json().get("models", [])]
        except httpx.HTTPError as exc:
            raise ModelUnavailableError(f"ollama tags failed: {exc}") from exc

    def capabilities(self, model: str) -> ModelCapabilities:
        bare = self._bare(model)
        vision_markers = ("vision", "llava", "minicpm-v", "qwen2.5vl", "moondream")
        embed_markers = ("embed", "bge", "nomic-embed", "snowflake-arctic-embed", "mxbai-embed")
        is_embed = any(m in bare for m in embed_markers)
        try:
            with self._client() as c:
                r = c.post("/api/show", json={"name": bare})
                info = r.json() if r.status_code == 200 else {}
        except httpx.HTTPError:
            info = {}
        details = str(info.get("details", "")).lower()
        families = str(info).lower()
        ctx = 4096
        params = info.get("model_info") or {}
        for k, v in params.items():
            if k.endswith("context_length") and isinstance(v, int) and v > 0:
                ctx = v
                break
        return ModelCapabilities(
            structured_output=True,      # ollama supports format=json
            tool_calling=("tools" in families or "function" in families),
            vision=(any(m in bare for m in vision_markers) or "mmproj" in families
                    or "vision" in details),
            audio=False,
            embeddings=is_embed,
            context_window=ctx,
            privacy_class="local",
        )
