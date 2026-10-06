"""Provider-neutral AI model interface for TraceAtlas dual analysis (§26, §30).

Every analytical component (primary analyst, critical analyst, adjudicator,
synthesizer) talks to models ONLY through this abstract interface, so cloud
providers and Ollama/local models are interchangeable. No module in the
analysis pipeline may import a concrete SDK directly.

Privacy classes (§28):
- "local"  : data never leaves the deployment (Ollama, local runtimes).
- "cloud"  : data is sent off-host; forbidden when AI_MODE=local_only.
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from dataclasses import dataclass, field


class ModelUnavailableError(RuntimeError):
    """Raised when a model/provider cannot currently serve requests."""


@dataclass(frozen=True)
class ModelCapabilities:
    """Capability registry entry (§30). Never route a task a model can't do."""

    structured_output: bool = False
    tool_calling: bool = False
    vision: bool = False
    audio: bool = False
    embeddings: bool = False
    context_window: int = 4096
    language_support: tuple[str, ...] = ("en",)
    privacy_class: str = "cloud"   # "local" | "cloud"

    def supports(self, task_modality: str) -> bool:
        return {
            "text": True,
            "structured": self.structured_output,
            "vision": self.vision,
            "audio": self.audio,
            "embedding": self.embeddings,
        }.get(task_modality, False)


@dataclass
class GenerationResult:
    text: str
    model: str
    provider: str
    latency_ms: float = 0.0
    input_tokens: int = 0
    output_tokens: int = 0
    raw: dict = field(default_factory=dict)


class BaseAIProvider(ABC):
    """Abstract provider adapter. Concrete adapters: ollama/openai/...

    Required surface (§26): generate, generate_structured, extract, classify,
    reason, summarize, verify, embed, health, models, capabilities.
    """

    provider_name: str = "base"
    default_privacy_class: str = "cloud"

    # ------------------------------------------------------------------ core
    @abstractmethod
    def generate(self, prompt: str, *, system: str = "", model: str,
                 temperature: float = 0.1, max_tokens: int = 2048,
                 json_mode: bool = False) -> GenerationResult:
        """Raw text generation against `model`."""

    def generate_structured(self, prompt: str, schema, *, system: str = "",
                            model: str, temperature: float = 0.0,
                            max_tokens: int = 4096):
        """Generate + strict-validate against a Pydantic model class.

        Repair protocol (§32): on invalid output, ask the model once to fix
        its JSON against the schema; if still invalid raise SchemaFailure so
        the caller can retry an alternate model / mark MODEL_OUTPUT_INVALID.
        """
        from pydantic import ValidationError

        schema_hint = json.dumps(getattr(schema, "model_json_schema", lambda: {})(),
                                 separators=(",", ":"))[:4000]
        sys = (system or "") + ("\nRespond with ONLY a single JSON object that "
                                f"validates against this JSON Schema:\n{schema_hint}")
        res = self.generate(prompt, system=sys, model=model,
                            temperature=temperature, max_tokens=max_tokens,
                            json_mode=True)
        try:
            return schema.model_validate_json(res.text)
        except (ValidationError, ValueError, json.JSONDecodeError):
            repair = ("Your previous JSON failed schema validation. Repair it and "
                      f"output ONLY valid JSON.\nPrevious output:\n{res.text[:4000]}")
            res2 = self.generate(repair, system=sys, model=model,
                                 temperature=0.0, max_tokens=max_tokens,
                                 json_mode=True)
            try:
                return schema.model_validate_json(res2.text)
            except (ValidationError, ValueError, json.JSONDecodeError) as exc:
                raise SchemaFailure(str(exc)) from exc

    # ------------------------------------------------------------- conveniences
    def extract(self, text: str, fields: list[str], *, model: str) -> dict:
        prompt = (f"Extract these fields from the text below. Return a JSON object "
                  f"with exactly these keys: {fields}. Use null when absent. Do not "
                  f"invent values.\n\nTEXT:\n{text[:12000]}")
        res = self.generate(prompt, model=model, json_mode=True, temperature=0.0)
        try:
            data = json.loads(res.text)
            return data if isinstance(data, dict) else {}
        except json.JSONDecodeError:
            return {}

    def classify(self, text: str, labels: list[str], *, model: str) -> str:
        prompt = (f"Classify the text into exactly one of: {labels}. "
                  f"Answer with only the label.\n\nTEXT:\n{text[:8000]}")
        res = self.generate(prompt, model=model, temperature=0.0, max_tokens=16)
        out = res.text.strip().lower()
        for lab in labels:
            if lab.lower() in out:
                return lab
        return labels[0] if labels else ""

    def reason(self, prompt: str, *, system: str = "", model: str) -> str:
        return self.generate(prompt, system=system, model=model).text

    def summarize(self, text: str, *, model: str, style: str = "brief") -> str:
        prompt = f"Summarize ({style}) the following investigative text:\n\n{text[:16000]}"
        return self.generate(prompt, model=model, temperature=0.0).text

    def verify(self, claim: str, evidence: str, *, model: str) -> bool:
        prompt = ("Does the evidence SUPPORT (not merely relate to) the claim? "
                  f"Answer YES or NO only.\nCLAIM: {claim}\nEVIDENCE: {evidence[:8000]}")
        return self.generate(prompt, model=model, temperature=0.0,
                             max_tokens=8).text.strip().upper().startswith("YES")

    def embed(self, texts: list[str], *, model: str) -> list[list[float]]:
        raise NotImplementedError(f"{self.provider_name}: embeddings unsupported")

    # ------------------------------------------------------------------ ops
    @abstractmethod
    def health(self) -> bool:
        """Cheap liveness probe (used by fallback chain §31)."""

    @abstractmethod
    def models(self) -> list[str]:
        """Model ids this provider can serve."""

    @abstractmethod
    def capabilities(self, model: str) -> ModelCapabilities:
        ...


class SchemaFailure(ValueError):
    """Structured output could not be produced even after one repair (§32)."""
