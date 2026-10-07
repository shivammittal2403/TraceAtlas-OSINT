"""Shared execution context accumulated during one investigation run.

Holds knowledge produced by transforms/tasks: entities, relationships,
observations, evidence records, claims, gaps — plus cost accounting and the
cancellation/kill-switch handles every dispatch must respect.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from traceatlas.core.claim import Claim
from traceatlas.core.entity import Entity
from traceatlas.core.enums import (ClaimStatus, EntityType, EvidenceTier,
                                   RelationshipType)
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

    # ------------------------------------------------------------- snapshot
    def to_dict(self) -> dict:
        """Full serializable knowledge snapshot (for durable case state)."""
        return {
            "case_id": self.case_id,
            "investigation_id": self.investigation_id,
            "objective_spec_id": self.objective_spec_id,
            "entities": [e.to_dict() for e in self.entities.values()],
            "relationships": [r.to_dict() for r in self.relationships],
            "observations": [o.to_dict() for o in self.observations],
            "evidence": [ev.to_dict() for ev in self.evidence.values()],
            "claims": [c.to_dict() for c in self.claims],
            "gaps": [g.to_dict() for g in self.gaps],
            "errors": list(self.errors),
            "cost_units_spent": self.cost_units_spent,
            "budget_max_cost_units": self.budget_max_cost_units,
            "completed_task_kinds": list(self.completed_task_kinds),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "InvestigationContext":
        """Rebuild a context from `to_dict()` output (resume across sessions)."""
        ctx = cls(case_id=data["case_id"],
                  investigation_id=data["investigation_id"],
                  objective_spec_id=data.get("objective_spec_id", ""),
                  cost_units_spent=float(data.get("cost_units_spent", 0.0)),
                  budget_max_cost_units=float(data.get("budget_max_cost_units", 100.0)))
        ctx.completed_task_kinds = list(data.get("completed_task_kinds", []))
        ctx.errors = list(data.get("errors", []))
        for d in data.get("entities", []):
            ent = Entity(case_id=d["case_id"], entity_type=EntityType(d["entity_type"]),
                         display_name=d["display_name"], attributes=d.get("attributes", {}),
                         id=d["id"], observation_ids=d.get("observation_ids", []))
            key = f"{d['entity_type']}:{d['display_name']}"
            # transforms key entities as type:value; recover exact key when the
            # attribute set carries it, else fall back to the natural key form.
            ctx.entities[key] = ent
        ctx.relationships = [
            Relationship(case_id=d["case_id"], source_entity_id=d["source_entity_id"],
                         target_entity_id=d["target_entity_id"],
                         relationship_type=RelationshipType(d["relationship_type"]),
                         confidence=d.get("confidence", 0.0),
                         evidence_ids=d.get("evidence_ids", []), id=d["id"])
            for d in data.get("relationships", [])]
        ctx.observations = [
            Observation(case_id=d["case_id"], evidence_id=d["evidence_id"],
                        predicate=d["predicate"], subject=d["subject"], obj=d["obj"],
                        attributes=d.get("attributes", {}), id=d["id"])
            for d in data.get("observations", [])]
        ctx.evidence = {
            d["id"]: EvidenceRecord(case_id=d["case_id"], tier=EvidenceTier(d["tier"]),
                                    sha256=d["sha256"], media_type=d.get("media_type", ""),
                                    size_bytes=d.get("size_bytes", 0),
                                    storage_key=d.get("storage_key", ""),
                                    source_id=d.get("source_id", ""),
                                    connector_id=d.get("connector_id", ""),
                                    url=d.get("url", ""), id=d["id"])
            for d in data.get("evidence", [])}
        ctx.claims = [
            Claim(case_id=d["case_id"], statement=d["statement"],
                  status=ClaimStatus(d.get("status", "proposed")),
                  confidence=d.get("confidence", 0.0),
                  evidence_ids=d.get("evidence_ids", []), id=d["id"])
            for d in data.get("claims", [])]
        ctx.gaps = [
            InformationGap(case_id=d["case_id"], question=d["question"],
                           blocking_required_answer=d.get("blocking_required_answer", False),
                           candidate_actions=d.get("candidate_actions", []), id=d["id"])
            for d in data.get("gaps", [])]
        return ctx

    def remap_entity_keys(self, key_map: dict[str, str]) -> None:
        """Replace auto-derived entity keys with the canonical transform keys.

        Called after resume so subsequent upserts dedupe against restored
        entities exactly the way they did before interruption.
        """
        by_id = {e.id: e for e in self.entities.values()}
        new_entries: dict[str, Entity] = {}
        used: set[str] = set()
        for old_key, ent in self.entities.items():
            new_key = key_map.get(ent.id, old_key)
            while new_key in used:
                new_key = f"{new_key}#dup"
            used.add(new_key)
            new_entries[new_key] = ent
        self.entities = new_entries

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
