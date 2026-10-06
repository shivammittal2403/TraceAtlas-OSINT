"""Transform engine core: typed, deterministic input→output pipelines.

A Transform consumes a typed `TransformInput` and produces `TransformResult`
containing observations, entities, relationships and evidence references.
Transforms are the ONLY sanctioned way to move between intelligence object
types (Domain → DNS → IP → ASN ...). They never fabricate output: if the
underlying connector fails or returns nothing, the result is an honest empty
or failed result with the error preserved.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from traceatlas.core.observation import Observation
from traceatlas.exceptions import SourceError


@dataclass
class TransformInput:
    kind: str                     # "domain" | "ip" | "asn" | "url" | "email" | ...
    value: str
    case_id: str
    investigation_id: str = ""
    task_id: str = ""
    options: dict = field(default_factory=dict)


@dataclass
class EntityDraft:
    entity_type: str              # matches core.entity_type registry names
    key: str                      # stable natural key, e.g. "domain:example.com"
    display_name: str
    attributes: dict = field(default_factory=dict)


@dataclass
class RelationshipDraft:
    source_key: str
    rel_type: str                 # RESOLVES_TO | HOSTED_BY | ... (core.relationship_type)
    target_key: str
    observation_ids: list[str] = field(default_factory=list)
    evidence_ids: list[str] = field(default_factory=list)
    valid_from: str | None = None
    valid_to: str | None = None
    confidence: float = 1.0       # 1.0 only for direct protocol facts (DNS answer etc.)


@dataclass
class TransformResult:
    transform_id: str
    ok: bool
    inputs: TransformInput
    observations: list[Observation] = field(default_factory=list)
    entities: list[EntityDraft] = field(default_factory=list)
    relationships: list[RelationshipDraft] = field(default_factory=list)
    evidence_ids: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    duration_ms: float = 0.0
    metadata: dict = field(default_factory=dict)


class Transform(ABC):
    """Base class for all transforms. Subclasses declare their contract."""

    id: str = "transform.base"
    name: str = "base"
    input_kind: str = ""
    output_kinds: tuple[str, ...] = ()
    connector_names: tuple[str, ...] = ()   # connectors this transform may use
    requires_network: bool = True

    @abstractmethod
    def run(self, ti: TransformInput) -> TransformResult: ...

    def _result(self, ti: TransformInput, ok: bool) -> TransformResult:
        return TransformResult(transform_id=self.id, ok=ok, inputs=ti)

    def execute(self, ti: TransformInput) -> TransformResult:
        """Guarded execution: validates contract, times, converts exceptions to errors."""
        if ti.kind != self.input_kind:
            r = self._result(ti, ok=False)
            r.errors.append(f"input kind {ti.kind!r} != required {self.input_kind!r}")
            return r
        start = time.monotonic()
        try:
            res = self.run(ti)
        except SourceError as e:
            res = self._result(ti, ok=False)
            res.errors.append(str(e))
        except Exception as e:  # never let one bad record kill a wave
            res = self._result(ti, ok=False)
            res.errors.append(f"{type(e).__name__}: {e}")
        res.duration_ms = (time.monotonic() - start) * 1000
        return res
