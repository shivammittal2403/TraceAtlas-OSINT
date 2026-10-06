"""Dual analysis of IMPORTED DATA / unknown schemas (§21).

FILE -> PARSE -> NORMALIZE -> DETERMINISTIC VALIDATION -> PASS 1 mapping
proposal -> PASS 2 independent mapping proposal -> compare. If the two passes
propose different field mappings, the system does NOT auto-map: it marks
SCHEMA_REVIEW_REQUIRED and a human decides. Identical proposals are accepted
but still labelled as AI reasoning agreement, not evidence corroboration.
"""

from __future__ import annotations

import json

from pydantic import BaseModel, Field

from traceatlas.ai.gateway import AllModelsUnavailableError


class SchemaMapping(BaseModel):
    """Proposed semantic mapping for one imported record's fields."""
    mappings: dict[str, str] = Field(default_factory=dict)  # raw_field -> canonical concept
    record_meaning: str = ""
    confidence: float = Field(0.5, ge=0.0, le=1.0)


MAPPING_SYSTEM = (
    "You are analysing an IMPORTED dataset with an unknown schema. Propose a "
    "mapping from each raw field name to a canonical investigative concept "
    "(e.g. ip_address, domain, timestamp_observed, actor_handle, amount, "
    "wallet_address, geo_location, event_description). Use 'unknown' when you "
    "cannot justify a mapping. Do not invent fields. Respond ONLY in JSON.")


def _norm_map(m: SchemaMapping) -> dict[str, str]:
    return {k.strip().lower(): v.strip().lower() for k, v in m.mappings.items()}


def analyze_imported_payload(engine, payload: dict, *, case_id: str,
                             questions: list[dict]) -> dict:
    """Run both passes over the same raw payload; compare mappings (§21)."""
    from traceatlas.analysis.evidence_context import EvidenceContext, EvidenceItem
    from traceatlas.analysis.validation_gate import validate_connector_result

    vr = validate_connector_result(payload)
    item = EvidenceItem(evidence_id="imp-1", source_id="imported_file",
                        connector_id="ingestion_fabric",
                        summary="imported record awaiting schema interpretation",
                        payload=payload, validation_status=vr.status,
                        validation_issues=list(vr.issues))
    ctx = EvidenceContext(case_id=case_id, objective="interpret imported data",
                          questions=questions, evidence=[item])
    prompt = f"IMPORTED RECORD (JSON):\n{json.dumps(payload, sort_keys=True)[:16000]}"
    result = {"validation_status": vr.status, "mapping": {}, "status": "MAPPED",
              "notes": []}
    try:
        m1 = engine.gateway.generate_structured(
            role="primary_mapper", prompt=prompt, schema=SchemaMapping,
            system=MAPPING_SYSTEM, model_id=engine.primary_model,
            chain=engine._chain(engine.primary_model), sensitive=True)
        m2 = engine.gateway.generate_structured(
            role="secondary_mapper", prompt=prompt, schema=SchemaMapping,
            system=MAPPING_SYSTEM, model_id=engine.secondary_model,
            chain=engine._chain(engine.secondary_model), sensitive=True)
    except AllModelsUnavailableError:
        result["status"] = "SCHEMA_REVIEW_REQUIRED"
        result["notes"].append("mappers unavailable; no auto-mapping performed")
        return result

    n1, n2 = _norm_map(m1), _norm_map(m2)
    agreed, conflicts = {}, []
    for key in sorted(set(n1) | set(n2)):
        v1, v2 = n1.get(key), n2.get(key)
        if v1 is not None and v1 == v2:
            agreed[key] = v1
        else:
            conflicts.append({"field": key, "pass1": v1, "pass2": v2})
    if conflicts:
        # §21: mappings differ -> do NOT auto-map differing fields
        result["status"] = "SCHEMA_REVIEW_REQUIRED"
        result["mapping"] = agreed          # agree on identical subset only
        result["conflicting_fields"] = conflicts
        result["notes"].append(
            "passes proposed different meanings for conflicting fields; "
            "human schema review required before ingestion into graph")
    else:
        result["mapping"] = agreed
        result["notes"].append("both passes independently produced identical "
                               "mappings (AI_REASONING_AGREEMENT; not evidence "
                               "corroboration)")
    return result
