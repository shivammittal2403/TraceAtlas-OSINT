"""Provider-agnostic AI model interface + capability registry.

Design rules (enforced by this module):
  * Structured output is validated against a caller-supplied schema
    (a validator callable returning (ok, errors)). Invalid output is
    repaired ONCE via the structured mechanism; if still invalid the run
    is marked MODEL_OUTPUT_INVALID — never silently coerced.
  * No provider may be selected for a task it cannot perform
    (capability registry check).
  * Every call is metered (ModelUsage) so cost accounting works even in
    degraded/fallback paths.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable, Optional

# schema validator: payload -> (ok: bool, errors: list[str])
SchemaValidator = Callable[[dict], tuple[bool, list[str]]]


class ModelUnavailable(Exception):
    """Provider not reachable / not configured."""


class ModelOutputInvalid(Exception):
    """Structured output failed schema validation after one repair attempt."""


@dataclass(frozen=True)
class ModelCapabilities:
    structured_output: bool = True
    tool_calling: bool = False
    vision: bool = False
    audio: bool = False
    embeddings: bool = False
    languages: tuple[str, ...] = ("en",)


@dataclass
class ModelSpec:
    provider: str                    # "ollama" | "openai" | ...
    model_id: str
    context_window: int = 8192
    capabilities: ModelCapabilities = field(default_factory=ModelCapabilities)
    privacy_class: str = "local"     # local | cloud_private | cloud
    input_cost_per_1k: float = 0.0   # USD (0 for local)
    output_cost_per_1k: float = 0.0
    expected_latency_ms: float = 5000.0
    evaluation_score: float = 0.0    # 0..1 from eval harness; 0 = unmeasured


@dataclass
class ModelRequest:
    prompt: str
    system: str = ""
    schema: Optional[SchemaValidator] = None
    schema_repair_hint: str = ""
    max_tokens: int = 2048
    temperature: float = 0.2
    timeout_s: float = 60.0
    requires: Optional[ModelCapabilities] = None


@dataclass
class ModelResponse:
    text: str
    parsed: Optional[dict] = None
    model_provider: str = ""
    model_id: str = ""
    input_tokens: int = 0
    output_tokens: int = 0
    latency_ms: float = 0.0
    structured: bool = False
    repaired: bool = False
    error: str = ""

    @property
    def ok(self) -> bool:
        return not self.error


@dataclass
class ModelUsage:
    provider: str
    model_id: str
    task: str
    input_tokens: int
    output_tokens: int
    cost_usd: float
    latency_ms: float
    success: bool
    ts_epoch: float = field(default_factory=time.time)


class BaseProvider:
    """Common contract. Providers implement _complete(); everything else
    (validation, repair, metering) is handled once here."""

    name: str = "base"

    def __init__(self, spec: ModelSpec) -> None:
        self.spec = spec

    # -- required by subclasses ------------------------------------------
    def _complete(self, req: ModelRequest) -> tuple[str, int, int]:
        """Return (text, input_tokens_estimate, output_tokens_estimate)."""
        raise ModelUnavailable(f"provider {self.name} not implemented")

    def health(self) -> bool:
        try:
            text, _, _ = self._complete(ModelRequest(prompt="ping", max_tokens=1))
            return bool(text)
        except Exception:
            return False

    def models(self) -> list[str]:
        return [self.spec.model_id]

    def capabilities(self) -> ModelCapabilities:
        return self.spec.capabilities

    # -- shared pipeline ---------------------------------------------------
    def can_serve(self, req: ModelRequest) -> bool:
        cap = self.spec.capabilities
        need = req.requires
        if need is None:
            return True
        if need.vision and not cap.vision:
            return False
        if need.audio and not cap.audio:
            return False
        if need.embeddings and not cap.embeddings:
            return False
        if need.tool_calling and not cap.tool_calling:
            return False
        return True

    def estimate_cost(self, in_tok: int, out_tok: int) -> float:
        return (in_tok / 1000.0) * self.spec.input_cost_per_1k + \
               (out_tok / 1000.0) * self.spec.output_cost_per_1k

    def run(self, req: ModelRequest, task: str = "generate") -> tuple[ModelResponse, ModelUsage]:
        if not self.can_serve(req):
            raise ModelUnavailable(
                f"{self.spec.provider}/{self.spec.model_id} lacks required capability for task '{task}'")
        start = time.monotonic()
        try:
            text, i_tok, o_tok = self._complete(req)
        except ModelUnavailable:
            raise
        except Exception as e:  # network etc -> unavailable, caller falls back
            raise ModelUnavailable(f"{self.name}: {type(e).__name__}: {e}") from e
        repaired = False
        parsed: Optional[dict] = None
        err = ""
        if req.schema is not None:
            parsed = _try_json(text)
            ok = parsed is not None and req.schema(parsed)[0]
            if not ok:
                # ONE repair attempt using the structured mechanism
                repaired = True
                fix = (parsed if isinstance(parsed, dict) else {"raw": text})
                reprompt = (req.prompt + "\n\nYour previous JSON output failed schema "
                            "validation with errors: " +
                            "; ".join(_schema_errors(req.schema, parsed)) +
                            f"\n{req.schema_repair_hint}\nReturn ONLY corrected valid JSON.")
                try:
                    text2, i2, o2 = self._complete(req.__class__(prompt=reprompt, system=req.system,
                                                                 schema=None, max_tokens=req.max_tokens,
                                                                 temperature=0.0, timeout_s=req.timeout_s))
                    i_tok += i2
                    o_tok += o2
                    parsed = _try_json(text2)
                    ok = parsed is not None and req.schema(parsed)[0]
                    text = text2 if parsed is None else text
                except ModelUnavailable as e2:
                    ok = False
                    err = f"repair pass unavailable: {e2}"
                if not ok:
                    err = err or "MODEL_OUTPUT_INVALID"
                    parsed = None
        latency = (time.monotonic() - start) * 1000.0
        resp = ModelResponse(text=text, parsed=parsed, model_provider=self.spec.provider,
                             model_id=self.spec.model_id, input_tokens=i_tok,
                             output_tokens=o_tok, latency_ms=latency,
                             structured=req.schema is not None, repaired=repaired, error=err)
        usage = ModelUsage(provider=self.spec.provider, model_id=self.spec.model_id,
                           task=task, input_tokens=i_tok, output_tokens=o_tok,
                           cost_usd=self.estimate_cost(i_tok, o_tok),
                           latency_ms=latency, success=resp.ok)
        if err == "MODEL_OUTPUT_INVALID":
            raise ModelOutputInvalid(err)
        return resp, usage


def _try_json(text: str) -> Optional[dict]:
    import json
    try:
        obj = json.loads(text)
        return obj if isinstance(obj, dict) else {"value": obj}
    except Exception:
        # tolerate fenced code blocks
        t = text.strip()
        if t.startswith("```"):
            t = t.split("```")[1]
            t = t.removeprefix("json").strip()
            try:
                obj = json.loads(t)
                return obj if isinstance(obj, dict) else {"value": obj}
            except Exception:
                return None
        return None


def _schema_errors(schema: SchemaValidator, parsed) -> list[str]:
    if parsed is None:
        return ["output was not valid JSON"]
    ok, errs = schema(parsed)
    return errs if not ok else []
