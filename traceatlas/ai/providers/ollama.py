"""Ollama provider — first-class LOCAL model support.

Talks to the Ollama HTTP API (/api/generate) using only stdlib urllib so it
works in air-gapped/local-only deployments with zero extra dependencies.

Configuration (env):
  OLLAMA_BASE_URL            default http://localhost:11434
  TRACEATLAS_PRIMARY_MODEL   e.g. ollama/llama3.1
  TRACEATLAS_SECONDARY_MODEL
  TRACEATLAS_ADJUDICATOR_MODEL
  TRACEATLAS_EMBEDDING_MODEL

Model names are NEVER hardcoded here; they come from config.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

from traceatlas.ai.provider_base import (BaseProvider, ModelRequest,
                                         ModelSpec, ModelUnavailable)

DEFAULT_BASE_URL = "http://localhost:11434"


def _estimate_tokens(text: str) -> int:
    # conservative heuristic ~4 chars/token; used for cost/telemetry only
    return max(1, len(text) // 4)


class OllamaProvider(BaseProvider):
    name = "ollama"

    def __init__(self, spec: ModelSpec, base_url: str | None = None,
                 timeout_s: float = 120.0) -> None:
        super().__init__(spec)
        self.base_url = (base_url or os.environ.get("OLLAMA_BASE_URL", DEFAULT_BASE_URL)).rstrip("/")
        self.timeout_s = timeout_s

    # -- introspection -----------------------------------------------------
    def list_models(self) -> list[str]:
        req = urllib.request.Request(f"{self.base_url}/api/tags", method="GET")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_s) as r:
                data = json.loads(r.read().decode())
            return [m.get("name", "") for m in data.get("models", []) if m.get("name")]
        except Exception as e:
            raise ModelUnavailable(f"ollama tags query failed: {e}") from e

    def models(self) -> list[str]:
        try:
            return self.list_models()
        except ModelUnavailable:
            return []

    def health(self) -> bool:
        try:
            req = urllib.request.Request(f"{self.base_url}/api/version", method="GET")
            with urllib.request.urlopen(req, timeout=5.0) as r:
                return r.status == 200 and b"version" in r.read()
        except Exception:
            return False

    # -- completion ----------------------------------------------------------
    def _complete(self, req: ModelRequest) -> tuple[str, int, int]:
        payload = {
            "model": self.spec.model_id,
            "prompt": req.prompt,
            "system": req.system or None,
            "stream": False,
            "options": {"temperature": req.temperature,
                        "num_predict": req.max_tokens},
        }
        if req.schema is not None:
            # ask Ollama for raw JSON mode; semantic validation still ours
            payload["format"] = "json"
        body = json.dumps({k: v for k, v in payload.items() if v is not None}).encode()
        request = urllib.request.Request(f"{self.base_url}/api/generate",
                                         data=body,
                                         headers={"Content-Type": "application/json"},
                                         method="POST")
        try:
            with urllib.request.urlopen(request, timeout=min(req.timeout_s, self.timeout_s)) as r:
                data = json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            detail = ""
            try:
                detail = e.read().decode()[:300]
            except Exception:
                pass
            raise ModelUnavailable(f"ollama HTTP {e.code}: {detail}") from e
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            raise ModelUnavailable(f"ollama unreachable at {self.base_url}: {e}") from e
        text = data.get("response", "")
        if not text:
            raise ModelUnavailable("ollama returned empty response")
        i_tok = data.get("prompt_eval_count") or _estimate_tokens(req.prompt)
        o_tok = data.get("eval_count") or _estimate_tokens(text)
        return text, int(i_tok), int(o_tok)


def make_ollama_spec(model_id: str, **kw) -> ModelSpec:
    return ModelSpec(provider="ollama", model_id=model_id, privacy_class="local",
                     input_cost_per_1k=0.0, output_cost_per_1k=0.0, **kw)
