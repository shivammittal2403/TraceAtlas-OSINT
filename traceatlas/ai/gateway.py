"""AI Model Gateway — routing, privacy policy, fallback chain, cost metering.

Modes (env AI_MODE or ctor arg):
  local_only : ONLY models with privacy_class == "local" (e.g. Ollama).
               Any attempt to route to a cloud model raises PolicyViolation.
               No case data ever leaves the deployment.
  hybrid     : sensitive data -> local; public data -> any approved provider.
  cloud      : any configured provider.
  none       : deterministic-only operation. gateway.available() is False and
               callers must degrade gracefully (evidence/graph keep working).

Fallback chain: PRIMARY -> SECONDARY -> LOCAL FALLBACK -> DETERMINISTIC DEGRADED.
Every routed call is metered into Gateway.cost_usd / usage log.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from traceatlas.ai.provider_base import (BaseProvider, ModelCapabilities,
                                         ModelOutputInvalid, ModelRequest,
                                         ModelResponse, ModelSpec,
                                         ModelUnavailable)
from traceatlas.exceptions import TraceAtlasError


class PolicyViolation(TraceAtlasError):
    """Routing refused by privacy/AI-mode policy."""


@dataclass
class ProviderConfig:
    """One entry in the capability registry."""
    spec: ModelSpec
    role: str = "primary"            # primary | secondary | adjudicator | embedding
    enabled: bool = True

    @property
    def ref(self) -> str:
        return f"{self.spec.provider}/{self.spec.model_id}"


def _parse_ref(ref: str) -> tuple[str, str]:
    if "/" not in ref:
        raise TraceAtlasError(f"model ref must be provider/model, got '{ref}'")
    provider, model = ref.split("/", 1)
    return provider, model


def build_provider(cfg: ProviderConfig) -> BaseProvider:
    p = cfg.spec.provider
    if p == "ollama":
        from traceatlas.ai.providers.ollama import OllamaProvider
        return OllamaProvider(cfg.spec)
    if p == "openai":
        from traceatlas.ai.providers.openai import OpenAICompatibleProvider
        return OpenAICompatibleProvider(cfg.spec)
    if p == "anthropic":
        from traceatlas.ai.providers.anthropic import AnthropicProvider
        return AnthropicProvider(cfg.spec)
    if p == "gemini":
        from traceatlas.ai.providers.gemini import GeminiProvider
        return GeminiProvider(cfg.spec)
    if p == "qwen":
        from traceatlas.ai.providers.qwen import QwenProvider
        return QwenProvider(cfg.spec)
    if p == "deepseek":
        from traceatlas.ai.providers.deepseek import DeepSeekProvider
        return DeepSeekProvider(cfg.spec)
    if p == "mistral":
        from traceatlas.ai.providers.mistral import MistralProvider
        return MistralProvider(cfg.spec)
    raise TraceAtlasError(f"unknown provider '{p}'")


class AIGateway:
    def __init__(self, configs: list[ProviderConfig] | None = None,
                 mode: str | None = None) -> None:
        self.mode = (mode or os.environ.get("AI_MODE", "none")).strip().lower()
        if self.mode not in ("local_only", "hybrid", "cloud", "none"):
            raise TraceAtlasError(f"invalid AI_MODE '{self.mode}'")
        self.configs: list[ProviderConfig] = []
        for c in configs or []:
            self.register(c)
        self._providers: dict[str, BaseProvider] = {}
        self.usage_log: list = []           # ModelUsage entries
        self.cost_usd: float = 0.0
        self.degraded_calls: int = 0        # calls answered without AI

    # -- registry ----------------------------------------------------------
    def register(self, cfg: ProviderConfig) -> None:
        if self.mode == "local_only" and cfg.spec.privacy_class != "local":
            raise PolicyViolation(
                f"AI_MODE=local_only refuses non-local provider {cfg.ref}")
        self.configs.append(cfg)

    def available(self) -> bool:
        return self.mode != "none" and any(c.enabled for c in self.configs)

    def model_diversity(self) -> str:
        distinct = {c.ref for c in self.configs if c.enabled}
        return "HIGH" if len(distinct) >= 3 else ("MEDIUM" if len(distinct) == 2 else "LOW")

    def _get(self, cfg: ProviderConfig) -> BaseProvider:
        if cfg.ref not in self._providers:
            self._providers[cfg.ref] = build_provider(cfg)
        return self._providers[cfg.ref]

    # -- routing -----------------------------------------------------------
    def candidates_for(self, role: str, req: ModelRequest,
                       sensitive: bool = False) -> list[ProviderConfig]:
        out = []
        for c in self.configs:
            if not c.enabled:
                continue
            if self.mode == "local_only" and c.spec.privacy_class != "local":
                continue
            if self.mode == "hybrid" and sensitive and c.spec.privacy_class != "local":
                continue
            prov = self._get(c)
            if prov.can_serve(req):
                out.append(c)
        # preferred role first, then others as fallback
        out.sort(key=lambda c: 0 if c.role == role else 1)
        return out

    def generate(self, prompt: str, *, system: str = "", role: str = "primary",
                 schema=None, repair_hint: str = "", task: str = "generate",
                 sensitive: bool = False, max_tokens: int = 2048,
                 temperature: float = 0.2) -> ModelResponse:
        """Route one completion through the fallback chain.

        Returns a ModelResponse. If every candidate fails, returns an ERROR
        response with error='DETERMINISTIC_DEGRADED' (never raises), so
        investigation continues without AI while preserving evidence.
        """
        req = ModelRequest(prompt=prompt, system=system, schema=schema,
                           schema_repair_hint=repair_hint, max_tokens=max_tokens,
                           temperature=temperature)
        if self.mode == "none" or not self.configs:
            self.degraded_calls += 1
            return ModelResponse(text="", error="AI_MODE_NONE")
        last_err = ""
        for cfg in self.candidates_for(role, req, sensitive=sensitive):
            try:
                prov = self._get(cfg)
                resp, usage = prov.run(req, task=task)
                self.usage_log.append(usage)
                self.cost_usd += usage.cost_usd
                return resp
            except ModelOutputInvalid as e:
                last_err = "MODEL_OUTPUT_INVALID"   # try next model per policy
                continue
            except ModelUnavailable as e:
                last_err = str(e)[:200]
                continue
        self.degraded_calls += 1
        return ModelResponse(text="", error=f"DETERMINISTIC_DEGRADED: all providers failed ({last_err})")

    # -- convenience interfaces -------------------------------------------
    def extract(self, prompt: str, schema, **kw) -> ModelResponse:
        return self.generate(prompt, schema=schema, task="extract", **kw)

    def classify(self, prompt: str, labels: list[str], **kw) -> ModelResponse:
        def _v(d: dict) -> tuple[bool, list[str]]:
            lab = d.get("label")
            if lab not in labels:
                return False, [f"label must be one of {labels}, got {lab!r}"]
            return True, []
        p = prompt + "\nRespond JSON: {\"label\": <one of " + str(labels) + \
            "> , \"confidence\": 0..1}"
        return self.generate(p, schema=_v, task="classify", **kw)

    def summarize(self, prompt: str, **kw) -> ModelResponse:
        return self.generate(prompt, task="summarize", **kw)

    def health_report(self) -> dict:
        report = {}
        for c in self.configs:
            try:
                report[c.ref] = self._get(c).health()
            except Exception as e:
                report[c.ref] = f"error: {e}"
        return {"mode": self.mode, "models": report,
                "diversity": self.model_diversity(),
                "total_cost_usd": round(self.cost_usd, 6),
                "degraded_calls": self.degraded_calls}


def gateway_from_env() -> AIGateway:
    """Build a gateway from TRACEATLAS_{PRIMARY,SECONDARY,ADJUDICATOR}_MODEL env refs."""
    configs = []
    for role, var in (("primary", "TRACEATLAS_PRIMARY_MODEL"),
                      ("secondary", "TRACEATLAS_SECONDARY_MODEL"),
                      ("adjudicator", "TRACEATLAS_ADJUDICATOR_MODEL")):
        ref = os.environ.get(var, "").strip()
        if not ref:
            continue
        provider, model = _parse_ref(ref)
        privacy = "local" if provider == "ollama" else "cloud"
        configs.append(ProviderConfig(ModelSpec(provider=provider, model_id=model,
                                                privacy_class=privacy), role=role))
    return AIGateway(configs)
