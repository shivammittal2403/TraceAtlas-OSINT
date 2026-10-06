"""Google Gemini REST adapter (cloud)."""
from __future__ import annotations
import os, time
import httpx
from traceatlas.ai.providers.base import (BaseAIProvider, GenerationResult,
                                          ModelCapabilities, ModelUnavailableError)


class GeminiProvider(BaseAIProvider):
    provider_name = "gemini"
    default_privacy_class = "cloud"

    def __init__(self, api_key: str | None = None, timeout: float = 90.0):
        self.api_key = api_key or os.environ.get("GEMINI_API_KEY", "")
        self.base_url = "https://generativelanguage.googleapis.com/v1beta"
        self.timeout = timeout

    def generate(self, prompt, *, system="", model, temperature=0.1,
                 max_tokens=2048, json_mode=False) -> GenerationResult:
        if not self.api_key:
            raise ModelUnavailableError("gemini: no API key configured")
        cfg = {"temperature": temperature, "maxOutputTokens": max_tokens}
        if json_mode:
            cfg["responseMimeType"] = "application/json"
        payload = {"contents": [{"parts": [{"text": prompt}]}], "generationConfig": cfg}
        if system:
            payload["systemInstruction"] = {"parts": [{"text": system}]}
        t0 = time.perf_counter()
        try:
            with httpx.Client(base_url=self.base_url, timeout=self.timeout) as c:
                r = c.post(f":models/{model}:generateContent", json=payload,
                           params={"key": self.api_key})
                r.raise_for_status()
                data = r.json()
        except httpx.HTTPError as exc:
            raise ModelUnavailableError(f"gemini generate failed: {exc}") from exc
        cand = (data.get("candidates") or [{}])[0]
        text = "".join(p.get("text", "") for p in cand.get("content", {}).get("parts", []))
        usage = data.get("usageMetadata") or {}
        return GenerationResult(text=text, model=model, provider=self.provider_name,
                                latency_ms=(time.perf_counter() - t0) * 1000.0,
                                input_tokens=int(usage.get("promptTokenCount", 0) or 0),
                                output_tokens=int(usage.get("candidatesTokenCount", 0) or 0),
                                raw=data)

    def health(self) -> bool:
        if not self.api_key:
            return False
        try:
            with httpx.Client(base_url=self.base_url, timeout=10.0) as c:
                return c.get("/models", params={"key": self.api_key}).status_code == 200
        except httpx.HTTPError:
            return False

    def models(self) -> list[str]:
        try:
            with httpx.Client(base_url=self.base_url, timeout=15.0) as c:
                r = c.get("/models", params={"key": self.api_key})
                r.raise_for_status()
                return [m["name"].split("/")[-1] for m in r.json().get("models", [])]
        except httpx.HTTPError as exc:
            raise ModelUnavailableError(str(exc)) from exc

    def capabilities(self, model: str) -> ModelCapabilities:
        return ModelCapabilities(structured_output=True, tool_calling=True,
                                 vision=("vision" in model or "gemini-1.5" in model
                                         or "gemini-2" in model),
                                 context_window=1000000, privacy_class="cloud")
