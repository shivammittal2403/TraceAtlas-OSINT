"""Provenance: full chain from capture to derived assertion."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from traceatlas.core.identifiers import new_id
from traceatlas.core.serialization import to_jsonable
from traceatlas.core.validation import utcnow


@dataclass
class ProvenanceStep:
    kind: str               # capture | parse | transform | infer | verify
    actor: str              # connector id, worker id, model id, or human id
    input_refs: list[str] = field(default_factory=list)
    output_ref: str = ""
    at: datetime = field(default_factory=utcnow)
    notes: str = ""


@dataclass
class Provenance:
    subject_id: str                     # evidence/observation/claim being traced
    steps: list[ProvenanceStep] = field(default_factory=list)
    id: str = field(default_factory=lambda: new_id("prov"))

    def chain_complete(self) -> bool:
        """True iff every step's output feeds some later step's input."""
        outputs = {s.output_ref for s in self.steps if s.output_ref}
        for step in self.steps[:-1]:
            if step.output_ref and not any(
                step.output_ref in later.input_refs for later in self.steps[1:]
            ):
                return False
        return bool(self.steps)

    def to_dict(self) -> dict:
        return to_jsonable(self)
