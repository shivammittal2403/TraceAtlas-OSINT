"""Shared canonical case state (§24) with scoped working memory (§25).

Rules encoded here:
  * Workers may write only into their own temporary working memory.
  * Only Fact-Gate-approved results enter the canonical case state.
  * Contradictions and unknowns are RETAINED, never silently dropped.
  * Context minimisation: ``build_context`` returns task-scoped slices instead
    of dumping the whole case into every model request.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from traceatlas.core.identifiers import new_id
from traceatlas.trust.model import (
    BiasAssessment,
    Contradiction,
    EvidenceRecord,
    Fact,
    Hypothesis,
    IndependenceAssessment,
    Insight,
    Observation,
    ReliabilityAssessment,
    SourceRecord,
    VerificationStatus,
)


@dataclass
class EntityRecord:
    kind: str            # domain|ip|org|person|asn|email|username|crypto_address...
    value: str
    case_id: str = ""
    merge_justification: str = ""   # required before two entities become one (§40)
    id: str = field(default_factory=lambda: new_id("ent"))

    def to_dict(self) -> dict:
        return {"id": self.id, "kind": self.kind, "value": self.value,
                "merge_justification": self.merge_justification}


@dataclass
class RelationshipRecord:
    source_entity_id: str
    target_entity_id: str
    kind: str            # resolves_to|owns|operates|shares_hosting|employs...
    evidence_ids: list[str] = field(default_factory=list)
    case_id: str = ""
    id: str = field(default_factory=lambda: new_id("rel_obj"))

    def to_dict(self) -> dict:
        return {"id": self.id, "kind": self.kind,
                "source": self.source_entity_id, "target": self.target_entity_id,
                "evidence_ids": list(self.evidence_ids)}


@dataclass
class EventRecord:
    description: str
    when: str = ""
    entity_ids: list[str] = field(default_factory=list)
    evidence_ids: list[str] = field(default_factory=list)
    case_id: str = ""
    id: str = field(default_factory=lambda: new_id("evt"))

    def to_dict(self) -> dict:
        return {"id": self.id, "description": self.description, "when": self.when,
                "entity_ids": list(self.entity_ids), "evidence_ids": list(self.evidence_ids)}


class CaseMemory:
    """Canonical shared truth for one case. The ONLY place approved results live."""

    def __init__(self, case_id: str) -> None:
        self.case_id = case_id
        self.sources: dict[str, SourceRecord] = {}
        self.evidence: dict[str, EvidenceRecord] = {}
        self.observations: dict[str, Observation] = {}
        self.facts: dict[str, Fact] = {}
        self.insights: dict[str, Insight] = {}
        self.hypotheses: dict[str, Hypothesis] = {}
        self.entities: dict[str, EntityRecord] = {}
        self.relationships: dict[str, RelationshipRecord] = {}
        self.events: dict[str, EventRecord] = {}
        self.bias_assessments: dict[str, BiasAssessment] = {}
        self.reliability_assessments: dict[str, ReliabilityAssessment] = {}
        self.independence_assessments: dict[str, IndependenceAssessment] = {}
        self.contradictions: dict[str, Contradiction] = {}
        self.gaps: list[str] = []                 # intelligence gaps
        self.next_actions: list[str] = []
        self.audit_log: list[dict] = []

    # ------------------------------------------------------------------ writes
    def _audit(self, action: str, ref: str) -> None:
        self.audit_log.append({"case_id": self.case_id, "action": action, "ref": ref})

    def add_source(self, src: SourceRecord) -> SourceRecord:
        self.sources[src.id] = src
        self._audit("add_source", src.id)
        return src

    def add_evidence(self, ev: EvidenceRecord) -> EvidenceRecord:
        if ev.source_id not in self.sources:
            raise ValueError(f"evidence references unknown source {ev.source_id}")
        self.evidence[ev.id] = ev
        self._audit("add_evidence", ev.id)
        return ev

    def add_observation(self, obs: Observation) -> Observation:
        for eid in obs.evidence_ids:
            if eid not in self.evidence:
                raise ValueError(f"observation references unknown evidence {eid}")
        self.observations[obs.id] = obs
        self._audit("add_observation", obs.id)
        return obs

    def add_fact(self, fact: Fact) -> Fact:
        """Only gate-approved facts may be added to canonical state."""
        if fact.decision is None:
            raise ValueError(
                f"fact {fact.id} has no FactGate decision — cannot enter canonical case state"
            )
        if fact.verification_status in (
            VerificationStatus.REJECTED,
            VerificationStatus.UNVALIDATED,
        ):
            raise ValueError(
                f"fact {fact.id} status {fact.verification_status.value} is not gate-approved"
            )
        for eid in fact.evidence_ids:
            if eid not in self.evidence:
                raise ValueError(f"fact references unknown evidence {eid}")
        for sid in fact.source_ids:
            if sid not in self.sources:
                raise ValueError(f"fact references unknown source {sid}")
        self.facts[fact.id] = fact
        self._audit("add_fact", fact.id)
        return fact

    def add_insight(self, ins: Insight) -> Insight:
        for fid in ins.supporting_fact_ids:
            if fid not in self.facts:
                raise ValueError(
                    f"insight cites {fid} which is not an approved fact — insights derive only from gated facts"
                )
        self.insights[ins.id] = ins
        self._audit("add_insight", ins.id)
        return ins

    def add_hypothesis(self, hyp: Hypothesis) -> Hypothesis:
        for fid in hyp.supporting_facts + hyp.opposing_facts:
            if fid not in self.facts:
                raise ValueError(f"hypothesis cites non-approved fact {fid}")
        self.hypotheses[hyp.id] = hyp
        self._audit("add_hypothesis", hyp.id)
        return hyp

    def add_contradiction(self, c: Contradiction) -> Contradiction:
        self.contradictions[c.id] = c
        self._audit("add_contradiction", c.id)
        return c

    def add_assessment(self, a) -> None:
        if isinstance(a, BiasAssessment):
            self.bias_assessments[a.id] = a
        elif isinstance(a, ReliabilityAssessment):
            self.reliability_assessments[a.id] = a
        elif isinstance(a, IndependenceAssessment):
            self.independence_assessments[a.id] = a
        else:
            raise TypeError(f"unknown assessment type {type(a)!r}")
        self._audit("add_assessment", a.id)

    def upsert_entity(self, kind: str, value: str, merge_justification: str = "") -> EntityRecord:
        for ent in self.entities.values():
            if ent.kind == kind and ent.value.lower() == value.lower():
                return ent
        if merge_justification:
            pass  # explicit justification retained on record
        ent = EntityRecord(kind=kind, value=value, case_id=self.case_id,
                           merge_justification=merge_justification)
        self.entities[ent.id] = ent
        self._audit("add_entity", ent.id)
        return ent

    # ------------------------------------------------------------------- reads
    @property
    def approved_facts(self) -> list[Fact]:
        return [f for f in self.facts.values()
                if f.verification_status in (VerificationStatus.SUPPORTED,
                                             VerificationStatus.PARTIAL)]

    def fact_summary(self) -> dict:
        """§14 FACT SUMMARY — produced BEFORE any hypothesis summary."""
        by_status: dict[str, list[dict]] = {
            "verified_and_supported": [], "partial": [], "disputed": [],
            "observations": [],
        }
        for f in self.approved_facts:
            bucket = "partial" if f.verification_status == VerificationStatus.PARTIAL else "verified_and_supported"
            by_status[bucket].append({"id": f.id, "statement": f.statement,
                                      "confidence": f.confidence.value,
                                      "independent_clusters": f.independent_cluster_count})
        for c in self.contradictions.values():
            if c.resolution == "open":
                by_status["disputed"].append({"id": c.id, "statement": f"{c.statement_a} vs {c.statement_b}"})
        for o in self.observations.values():
            by_status["observations"].append({"id": o.id, "statement": o.statement})
        return {
            "case_id": self.case_id,
            "verified_facts": by_status["verified_and_supported"],
            "partial_facts": by_status["partial"],
            "disputed_facts": by_status["disputed"],
            "observations": by_status["observations"],
            "source_bias_notes": [b.explanation for b in self.bias_assessments.values()],
            "source_reliability_notes": [
                f"{r.source_id}: {r.level.value}" for r in self.reliability_assessments.values()],
            "independent_sources": [a.cluster_id for a in self.independence_assessments.values()
                                    if a.status.value == "independent"],
            "dependent_sources": [a.shared_basis for a in self.independence_assessments.values()
                                  if a.status.value == "dependent"],
            "temporal_limitations": [lim for f in self.facts.values() for lim in f.limitations
                                     if "temporal" in lim.lower() or "stale" in lim.lower()],
            "identity_limitations": [lim for f in self.facts.values() for lim in f.limitations
                                     if "identity" in lim.lower()],
            "known_contradictions": [c.to_dict() for c in self.contradictions.values()
                                     if c.resolution == "open"],
        }

    def build_context(self, *, skill_names: list[str] | None = None,
                      entity_ids: list[str] | None = None,
                      include_hypotheses: bool = False,
                      max_facts: int = 20) -> dict:
        """Context minimisation (§25): task-specific slice, never the whole case."""
        ctx: dict = {"case_id": self.case_id, "facts": [], "observations": [],
                     "source_ids": set(), "gaps": list(self.gaps)}
        facts = self.approved_facts[:max_facts]
        if entity_ids:
            facts = [f for f in self.approved_facts if set(f.entity_ids) & set(entity_ids)] or facts
        for f in facts:
            ctx["facts"].append({"id": f.id, "statement": f.statement,
                                 "confidence": f.confidence.value})
            ctx["source_ids"].update(f.source_ids)
        if include_hypotheses:
            ctx["hypotheses"] = [h.to_dict() for h in self.hypotheses.values()]
        ctx["source_ids"] = sorted(ctx["source_ids"])
        return ctx

    def timeline(self) -> list[dict]:
        entries = [{"when": e.when, "type": "event", "description": e.description, "id": e.id}
                   for e in self.events.values()]
        for f in self.approved_facts:
            if f.event_time:
                entries.append({"when": f.event_time, "type": "fact",
                                "description": f.statement, "id": f.id})
        entries.sort(key=lambda x: x["when"] or "9999")
        return entries

    def graph(self) -> dict:
        return {
            "nodes": [e.to_dict() for e in self.entities.values()],
            "edges": [r.to_dict() for r in self.relationships.values()],
        }

    def to_dict(self) -> dict:
        return {
            "case_id": self.case_id,
            "sources": [s.to_dict() for s in self.sources.values()],
            "facts": [f.to_dict() for f in self.facts.values()],
            "insights": [i.to_dict() for i in self.insights.values()],
            "observations": [o.to_dict() for o in self.observations.values()],
            "entities": [e.to_dict() for e in self.entities.values()],
            "relationships": [r.to_dict() for r in self.relationships.values()],
            "timeline": self.timeline(),
            "evidence": [e.to_dict() for e in self.evidence.values()],
            "source_assessments": {
                "bias": [b.to_dict() for b in self.bias_assessments.values()],
                "reliability": [r.to_dict() for r in self.reliability_assessments.values()],
                "independence": [i.to_dict() for i in self.independence_assessments.values()],
            },
            "contradictions": [c.to_dict() for c in self.contradictions.values()],
            "hypotheses": [h.to_dict() for h in self.hypotheses.values()],
            "gaps": list(self.gaps),
            "next_actions": list(self.next_actions),
            "audit_log": list(self.audit_log),
        }


class WorkingMemory:
    """Employee-scoped temporary memory (§25). Never merged into canonical state
    except through the Fact Gate / manager approval path."""

    def __init__(self, employee_id: str, task_id: str) -> None:
        self.employee_id = employee_id
        self.task_id = task_id
        self.notes: list[str] = []
        self.raw_findings: list[dict] = []

    def note(self, text: str) -> None:
        self.notes.append(text)

    def finding(self, payload: dict) -> None:
        self.raw_findings.append(payload)
