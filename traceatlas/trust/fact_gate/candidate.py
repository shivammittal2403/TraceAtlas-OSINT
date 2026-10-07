"""Candidate fact: an observation cluster proposed for promotion, not yet a Fact."""

from __future__ import annotations

from dataclasses import dataclass, field

from traceatlas.core.identifiers import new_id


@dataclass
class FactCandidate:
    statement: str
    case_id: str
    observation_ids: list[str] = field(default_factory=list)
    evidence_ids: list[str] = field(default_factory=list)
    source_ids: list[str] = field(default_factory=list)
    entity_ids: list[str] = field(default_factory=list)
    event_time: str | None = None
    id: str = field(default_factory=lambda: new_id("cand"))

    def to_dict(self) -> dict:
        return {"id": self.id, "statement": self.statement,
                "observation_ids": list(self.observation_ids),
                "evidence_ids": list(self.evidence_ids),
                "source_ids": list(self.source_ids)}
