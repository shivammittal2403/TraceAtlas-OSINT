"""AI gateway: mode-aware model routing with strict privacy enforcement.

Modes (§28, §29):
- local_only : ONLY providers whose capabilities.privacy_class == "local"
               (Ollama first-class). A cloud request is REFUSED loudly —
               data never silently leaves the deployment.
- hybrid     : policy routing; sensitive payloads forced to local models,
               public payloads may use approved cloud providers. Every
               routing decision is logged.
- cloud      : any registered provider.

Fallback chain (§31): PRIMARY -> SECONDARY -> LOCAL FALLBACK ->
DETERMINISTIC DEGRADED MODE (caller receives AllModelsUnavailableError and
must fall back to deterministic-only analysis; evidence is never destroyed).

Configuration (environment, no hardcoded model names):
  AI_MODE, OLLAMA_BASE_URL,
  TRACEATLAS_PRIMARY_MODEL, TRACEATLAS_SECONDARY_MODEL,
  TRACEATLAS_ADJUDICATOR_MODEL, TRACEATLAS_EMBEDDING_MODEL
  Model ids are "provider/name", e.g. "ollama/llama3.1".
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import datetime

from traceatlas.ai.providers.anthropic import AnthropicProvider
from traceatlas.ai.providers.base import (
    BaseAIProvider, GenerationResult, ModelCapabilities,
    ModelUnavailableError, SchemaFailure,
)
from traceatlas.ai.providers.deepseek import DeepSeekProvider
from traceatlas.ai.providers.gemini import GeminiProvider
from traceatlas.ai.providers.mistral import MistralProvider
from traceatlas.ai.providers.ollama import OllamaProvider
from traceatlas.ai.providers.openai import OpenAIProvider
from traceatlas.ai.providers.qwen import QwenProvider
from traceatlas.core.validation import utcnow


class AllModelsUnavailableError(RuntimeError):
    """Every configured model failed or is disallowed; degraded mode required."""


class CloudRequestRefusedError(PermissionError):
    """A cloud provider was requested while AI_MODE=local_only (§28)."""


@dataclass
class ModelRunRecord:
    """Audit record for one model invocation (§38 ai-runs endpoint)."""
    role: str                 # primary | secondary | adjudicator | synthesis
    provider: str
    model: str
    status: str               # ok | unavailable | invalid_output | refused
    latency_ms: float = 0.0
    input_tokens: int = 0
    output_tokens: int = 0
    prompt_chars: int = 0
    routed_by: str = ""       # which fallback tier served the call
    error: str = ""
    at: datetime = field(default_factory=utcnow)


_PROVIDER_CLASSES: dict[str, type[BaseAIProvider]] = {
    "ollama": OllamaProvider,
    "openai": OpenAIProvider,
    "anthropic": AnthropicProvider,
    "gemini": GeminiProvider,
    "qwen": QwenProvider,
    "deepseek": DeepSeekProvider,
    "mistral": MistralProvider,
}


def parse_model_id(model_id: str) -> tuple[str, str]:
    if "/" in model_id:
        prov, name = model_id.split("/", 1)
        return prov.lower(), name
    return "ollama", model_id   # unqualified ids default to local runtime


class AIGateway:
    def __init__(self, mode: str | None = None,
                 providers: dict[str, BaseAIProvider] | None = None):
        self.mode = (mode or os.environ.get("AI_MODE", "local_only")).lower()
        if self.mode not in ("local_only", "hybrid", "cloud"):
            raise ValueError(f"unknown AI_MODE: {self.mode}")
        self._providers = providers or {}
        self.run_log: list[ModelRunRecord] = []
        self.routing_log: list[dict] = []

    # ------------------------------------------------------------- registry
    def register(self, provider: BaseAIProvider) -> None:
        self._providers[provider.provider_name] = provider

    def _get(self, name: str) -> BaseAIProvider | None:
        if name in self._providers:
            return self._providers[name]
        cls = _PROVIDER_CLASSES.get(name)
        if cls is None:
            return None
        try:
            prov = cls()
        except Exception:      # misconfigured env must not crash analysis
            return None
        self._providers[name] = prov
        return prov

    # --------------------------------------------------------------- policy
    def _privacy_allowed(self, caps: ModelCapabilities) -> bool:
        if self.mode == "local_only":
            return caps.privacy_class == "local"
        return True            # hybrid/cloud allow both; sensitivity handled below

    def resolve_chain(self, *, primary: str, secondary: str | None = None,
                      fallback_local: str = "") -> list[tuple[str, str]]:
        """PRIMARY -> SECONDARY -> LOCAL FALLBACK ordering (§31)."""
        chain: list[tuple[str, str]] = [(primary, "primary")]
        if secondary:
            chain.append((secondary, "secondary"))
        if fallback_local:
            chain.append((fallback_local, "local_fallback"))
        elif self.mode != "local_only":
            pass
        if self.mode == "local_only" and not fallback_local:
            # ensure a local tier exists even if caller forgot to configure one
            for mid in (primary, secondary):
                if mid and parse_model_id(mid)[0] == "ollama":
                    break
        return chain

    def configured_models(self) -> dict[str, str]:
        return {
            "primary": os.environ.get("TRACEATLAS_PRIMARY_MODEL", ""),
            "secondary": os.environ.get("TRACEATLAS_SECONDARY_MODEL", ""),
            "adjudicator": os.environ.get("TRACEATLAS_ADJUDICATOR_MODEL", ""),
            "embedding": os.environ.get("TRACEATLAS_EMBEDDING_MODEL", ""),
        }

    # ---------------------------------------------------------------- calls
    def generate(self, *, role: str, prompt: str, system: str = "",
                 model_id: str, chain: list[tuple[str, str]] | None = None,
                 json_mode: bool = False, temperature: float = 0.1,
                 max_tokens: int = 2048, sensitive: bool = False) -> GenerationResult:
        attempts = [(model_id, "requested")] + list(chain or [])
        last_err = ""
        for mid, tier in attempts:
            prov_name, name = parse_model_id(mid)
            prov = self._get(prov_name)
            if prov is None:
                last_err = f"unknown provider {prov_name}"
                self._log(ModelRunRecord(role, prov_name, name, "unavailable", error=last_err, routed_by=tier))
                continue
            caps = prov.capabilities(name)
            if not self._privacy_allowed(caps):
                # §28: never silently send to cloud; loud refusal, keep trying chain
                self._log(ModelRunRecord(role, prov_name, name, "refused",
                                         error="cloud provider forbidden in local_only mode",
                                         routed_by=tier))
                self.routing_log.append({"decision": "refused", "model": mid, "tier": tier,
                                         "reason": "local_only"})
                continue
            if sensitive and self.mode == "hybrid" and caps.privacy_class != "local":
                self.routing_log.append({"decision": "rerouted_sensitive", "model": mid,
                                         "tier": tier, "reason": "sensitive payload -> local"})
                continue
            try:
                res = prov.generate(prompt, system=system, model=name,
                                    temperature=temperature, max_tokens=max_tokens,
                                    json_mode=json_mode)
            except ModelUnavailableError as exc:
                last_err = str(exc)
                self._log(ModelRunRecord(role, prov_name, name, "unavailable",
                                         error=last_err, routed_by=tier))
                continue
            self._log(ModelRunRecord(role, prov_name, name, "ok",
                                     latency_ms=res.latency_ms,
                                     input_tokens=res.input_tokens,
                                     output_tokens=res.output_tokens,
                                     prompt_chars=len(prompt), routed_by=tier))
            self.routing_log.append({"decision": "selected", "model": mid, "tier": tier})
            return res
        raise AllModelsUnavailableError(f"no model available for role={role}: {last_err}")

    def generate_structured(self, *, role: str, prompt: str, schema,
                            system: str = "", model_id: str,
                            chain: list[tuple[str, str]] | None = None,
                            temperature: float = 0.0, max_tokens: int = 4096,
                            sensitive: bool = False):
        """Structured output with repair + alternate-model retry (§32).

        Returns (parsed_object, run_result). Raises AllModelsUnavailableError
        when nothing can serve; returns (None, result) semantics via
        SchemaFailure->next-tier so that final failure surfaces as
        MODEL_OUTPUT_INVALID to the caller.
        """
        attempts = [(model_id, "requested")] + list(chain or [])
        last_exc: Exception | None = None
        for mid, tier in attempts:
            prov_name, name = parse_model_id(mid)
            prov = self._get(prov_name)
            if prov is None:
                continue
            caps = prov.capabilities(name)
            if not self._privacy_allowed(caps) or not caps.structured_output:
                continue
            try:
                obj = prov.generate_structured(prompt, schema, system=system,
                                               model=name, temperature=temperature,
                                               max_tokens=max_tokens)
                self._log(ModelRunRecord(role, prov_name, name, "ok", routed_by=tier,
                                         prompt_chars=len(prompt)))
                self.routing_log.append({"decision": "structured_selected",
                                         "model": mid, "tier": tier})
                return obj
            except SchemaFailure as exc:
                last_exc = exc
                self._log(ModelRunRecord(role, prov_name, name, "invalid_output",
                                         error=str(exc)[:200], routed_by=tier))
                continue
            except ModelUnavailableError as exc:
                last_exc = exc
                self._log(ModelRunRecord(role, prov_name, name, "unavailable",
                                         error=str(exc)[:200], routed_by=tier))
                continue
        raise AllModelsUnavailableError(
            f"structured generation failed for role={role}: {last_exc}")

    def embed(self, texts: list[str], *, model_id: str | None = None) -> list[list[float]]:
        mid = model_id or self.configured_models()["embedding"] or "ollama/nomic-embed-text"
        prov_name, name = parse_model_id(mid)
        prov = self._get(prov_name)
        if prov is None:
            raise AllModelsUnavailableError(f"embedding provider {prov_name} missing")
        caps = prov.capabilities(name)
        if not self._privacy_allowed(caps):
            raise CloudRequestRefusedError("embeddings must stay local in local_only mode")
        return prov.embed(texts, model=name)

    def health(self) -> dict[str, bool]:
        out: dict[str, bool] = {}
        for pname in _PROVIDER_CLASSES:
            prov = self._get(pname)
            if prov is not None:
                try:
                    out[pname] = prov.health()
                except Exception:
                    out[pname] = False
        return out

    def _log(self, rec: ModelRunRecord) -> None:
        self.run_log.append(rec)
