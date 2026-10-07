"""Google Gemini generateContent provider (stdlib-only)."""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

from traceatlas.ai.provider_base import (BaseProvider, ModelRequest,
                                         ModelSpec, ModelUnavailable)


class GeminiProvider(BaseProvider):
    name = "gemini"

    def __init__(self, spec: ModelSpec, api_key: str | None = None,
                 timeout_s: float = 90.0) -> None:
        super().__init__(spec)
        self.api_key = api_key or os.environ.get("GEMINI_API_KEY", "")
        self.timeout_s = timeout_s

    def health(self) -> bool:
        return bool(self.api_key)

    def _complete(self, req: ModelRequest) -> tuple[str, int, int]:
        if not self.api_key:
            raise ModelUnavailable("no GEMINI_API_KEY configured")
        contents = [{"role": "user", "parts": [{"text": req.prompt}]}]
        payload: dict = {"contents": contents}
        gen: dict = {"temperature": req.temperature, "maxOutputTokens": req.max_tokens}
        if req.system:
            payload["systemInstruction"] = {"parts": [{"text": req.system}]}
        if req.schema is not None:
            gen["responseMimeType"] = "application/json"
        payload["generationConfig"] = gen
        url = (f"https://generativelanguage.googleapis.com/v1beta/models/"
               f"{self.spec.model_id}:generateContent?key={self.api_key}")
        body = json.dumps(payload).encode()
        request = urllib.request.Request(url, data=body,
                                         headers={"Content-Type": "application/json"},
                                         method="POST")
        try:
            with urllib.request.urlopen(request, timeout=min(req.timeout_s, self.timeout_s)) as r:
                data = json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            raise ModelUnavailable(f"gemini HTTP {e.code}") from e
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            raise ModelUnavailable(f"gemini unreachable: {e}") from e
        try:
            text = data["candidates"][0]["content"]["parts"][0]["text"]
        except (KeyError, IndexError, TypeError):
            raise ModelUnavailable("gemini malformed response")
        meta = data.get("usageMetadata", {})
        return text, int(meta.get("promptTokenCount", 0)), \
               int(meta.get("candidatesTokenCount", 0))
