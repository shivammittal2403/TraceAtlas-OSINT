"""Shared execution context accumulated during one investigation run.

Holds knowledge produced by transforms/tasks: entities, relationships,
observations, evidence records, claims, gaps — plus cost accounting and the
cancellation/kill-switch handles every dispatch must respect.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from traceatlas.core.claim import Claim
from traceatlas.core.entity import Entity
from traceatlas.core.evidence import EvidenceRecord
from traceatlas.core.information_gap import InformationGap
from traceatlas.core.observation import Observation
from traceatlas.core.relationship import Relationship
from traceatlas.exceptions import TraceAtlasError


@dataclass
class InvestigationContext:
    case_id: str
    investigation_id: str
    objective_spec_id: str = ""
    entities: dict[str, Entity] = field(default_factory=dict)          # key -> Entity
    relationships: list[Relationship] = field(default_factory=list)
    observations: list[Observation] = field(default_factory=list)
    evidence: dict[str, EvidenceRecord] = field(default_factory=dict)  # id -> record
    claims: list[Claim] = field(default_factory=list)
    gaps: list[InformationGap] = field(default_factory=list)
    verifications: list = field(default_factory=list)  # VerificationRecord
    contradictions: list = field(default_factory=list)  # Contradiction
    errors: list[str] = field(default_factory=list)
    cost_units_spent: float = 0.0
    budget_max_cost_units: float = 100.0
    completed_task_kinds: list[str] = field(default_factory=list)

    def budget_exhausted(self) -> bool:
        return self.cost_units_spent >= self.budget_max_cost_units

    def charge(self, units: float) -> None:
        if units < 0:
            raise TraceAtlasError("cannot charge negative cost")
        self.cost_units_spent += units

    def upsert_entity(self, key: str, entity_type: str, display_name: str,
                      attributes: dict | None = None) -> Entity:
        """Idempotent entity creation keyed by stable natural key.

        entity_type must be a value of the canonical core.enums.EntityType
        registry (the same vocabulary transforms emit in EntityDrafts); an
        unregistered type fails LOUDLY rather than silently degrading to
        UNKNOWN, so transform/context schema drift is caught in tests.
        """
        existing = self.entities.get(key)
        if existing is not None:
            if attributes:
                merged = dict(existing.attributes)
                merged.update({k: v for k, v in attributes.items() if k not in merged})
                existing.attributes = merged
            return existing
        from traceatlas.core.enums import EntityType

        try:
            etype = EntityType(entity_type)
        except ValueError as exc:
            raise TraceAtlasError(
                f"entity_type {entity_type!r} is not registered in "
                f"core.enums.EntityType (key={key!r})") from exc
        ent = Entity(case_id=self.case_id, entity_type=etype, display_name=display_name,
                     attributes=attributes or {})
        self.entities[key] = ent
        return ent

    def add_evidence(self, record: EvidenceRecord) -> None:
        self.evidence[record.id] = record

    def to_summary(self) -> dict:
        return {
            "case_id": self.case_id,
            "investigation_id": self.investigation_id,
            "entities": len(self.entities),
            "relationships": len(self.relationships),
            "observations": len(self.observations),
            "evidence_records": len(self.evidence),
            "claims": len(self.claims),
            "gaps": len(self.gaps),
            "cost_units_spent": round(self.cost_units_spent, 3),
            "errors": list(self.errors),
        }
