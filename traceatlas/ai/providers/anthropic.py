"""Anthropic Messages API provider (stdlib-only)."""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

from traceatlas.ai.provider_base import (BaseProvider, ModelRequest,
                                         ModelSpec, ModelUnavailable)


class AnthropicProvider(BaseProvider):
    name = "anthropic"

    def __init__(self, spec: ModelSpec, api_key: str | None = None,
                 timeout_s: float = 90.0) -> None:
        super().__init__(spec)
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        self.timeout_s = timeout_s

    def health(self) -> bool:
        return bool(self.api_key)

    def _complete(self, req: ModelRequest) -> tuple[str, int, int]:
        if not self.api_key:
            raise ModelUnavailable("no ANTHROPIC_API_KEY configured")
        payload = {"model": self.spec.model_id,
                   "messages": [{"role": "user", "content": req.prompt}],
                   "max_tokens": req.max_tokens}
        if req.system:
            payload["system"] = req.system
        prompt_for_schema = req.prompt
        if req.schema is not None:
            payload["messages"][0]["content"] = prompt_for_schema + "\nReturn ONLY valid JSON."
        body = json.dumps(payload).encode()
        request = urllib.request.Request(
            "https://api.anthropic.com/v1/messages", data=body,
            headers={"Content-Type": "application/json",
                     "x-api-key": self.api_key,
                     "anthropic-version": "2023-06-01"}, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=min(req.timeout_s, self.timeout_s)) as r:
                data = json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            raise ModelUnavailable(f"anthropic HTTP {e.code}") from e
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            raise ModelUnavailable(f"anthropic unreachable: {e}") from e
        try:
            text = "".join(b.get("text", "") for b in data["content"] if b.get("type") == "text")
        except (KeyError, TypeError):
            raise ModelUnavailable("anthropic malformed response")
        usage = data.get("usage", {})
        return text, int(usage.get("input_tokens", 0)), int(usage.get("output_tokens", 0))
