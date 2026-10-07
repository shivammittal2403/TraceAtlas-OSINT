"""OpenAI-compatible chat-completions provider.

Serves OpenAI, and any OpenAI-compatible endpoint (Qwen/DeepSeek/Mistral/vLLM
gateways) via a configurable base_url + api_key. Cloud privacy class is set
explicitly in the ModelSpec so LOCAL_ONLY policy can refuse to route here.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

from traceatlas.ai.provider_base import (BaseProvider, ModelRequest,
                                         ModelSpec, ModelUnavailable)


class OpenAICompatibleProvider(BaseProvider):
    name = "openai"

    def __init__(self, spec: ModelSpec, api_key: str | None = None,
                 base_url: str | None = None, timeout_s: float = 90.0) -> None:
        super().__init__(spec)
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY", "")
        self.base_url = (base_url or os.environ.get(
            "TRACEATLAS_OPENAI_BASE_URL", "https://api.openai.com/v1")).rstrip("/")
        self.timeout_s = timeout_s

    def health(self) -> bool:
        if not self.api_key:
            return False
        try:
            req = urllib.request.Request(f"{self.base_url}/models",
                                         headers={"Authorization": f"Bearer {self.api_key}"})
            with urllib.request.urlopen(req, timeout=8.0) as r:
                return r.status == 200
        except Exception:
            return False

    def _complete(self, req: ModelRequest) -> tuple[str, int, int]:
        if not self.api_key:
            raise ModelUnavailable("no API key configured (OPENAI_API_KEY)")
        messages = []
        if req.system:
            messages.append({"role": "system", "content": req.system})
        messages.append({"role": "user", "content": req.prompt})
        payload = {"model": self.spec.model_id, "messages": messages,
                   "max_tokens": req.max_tokens, "temperature": req.temperature}
        if req.schema is not None:
            payload["response_format"] = {"type": "json_object"}
        body = json.dumps(payload).encode()
        request = urllib.request.Request(
            f"{self.base_url}/chat/completions", data=body,
            headers={"Content-Type": "application/json",
                     "Authorization": f"Bearer {self.api_key}"}, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=min(req.timeout_s, self.timeout_s)) as r:
                data = json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            raise ModelUnavailable(f"openai HTTP {e.code}") from e
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            raise ModelUnavailable(f"openai unreachable: {e}") from e
        try:
            choice = data["choices"][0]["message"]["content"]
        except (KeyError, IndexError):
            raise ModelUnavailable("openai malformed response envelope")
        usage = data.get("usage", {})
        return choice, int(usage.get("prompt_tokens", len(req.prompt) // 4)), \
               int(usage.get("completion_tokens", len(choice) // 4))
