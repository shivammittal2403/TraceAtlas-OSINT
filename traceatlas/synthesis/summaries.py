"""Summary modes generated from the SAME canonical synthesis (§14, §36)."""

from __future__ import annotations


def build_summary_modes(synth) -> dict:
    facts = synth.facts
    hyps = [h for h in synth.hypotheses if h.get("kind") != "alternative_explanation"]
    conflicts = synth.contradictions
    return {
        "quick_brief": _quick(facts, hyps, conflicts),
        "executive_summary": _exec(synth, facts, conflicts),
        "analyst_summary": _analyst(synth),
        "detailed_investigation": _detailed(synth),
        "strict_fact_summary": [f["statement"] for f in facts],
        "hypothesis_summary": [
            {"theory": h.get("statement", ""), "evidence_for": h.get("evidence_ids", []),
             "falsification": h.get("note", "requires independent corroboration")}
            for h in hyps],
        "change_summary": _changes(synth),
        "jarvis_brief": jarvis_lines(synth),
    }


def _quick(facts, hyps, conflicts) -> list[str]:
    lines = [f"FACT: {f['statement']}" for f in facts[:6]]
    lines += [f"HYPOTHESIS (unconfirmed): {h.get('statement','')}" for h in hyps[:3]]
    lines += [f"CONFLICT: {c['statement']}" for c in conflicts[:3]]
    return lines[:10]


def _exec(synth, facts, conflicts) -> str:
    parts = [f"Objective: {synth.objective or 'not stated'}.",
             f"{len(facts)} finding(s) are corroborated by independent sources.",
             f"{len(conflicts)} material conflict(s)/disagreement(s) remain."]
    if synth.unknowns:
        parts.append(f"Critical unknowns: {'; '.join(synth.unknowns[:3])}.")
    parts.append(f"Verification posture: {synth.verification.get('supported_facts', 0)} "
                 "supported / awaiting corroboration is the dominant state.")
    return " ".join(parts)


def _analyst(synth) -> dict:
    return {"entities": len(synth.entities),
            "relationships": len(synth.relationships),
            "timeline_events": len(synth.timeline),
            "evidence_citations": len(synth.citations),
            "hypotheses": len(synth.hypotheses),
            "contradictions": len(synth.contradictions),
            "gaps": len(synth.information_gaps),
            "verification": synth.verification}


def _detailed(synth) -> dict:
    return {"by_question": synth.by_question,
            "story": synth.investigation_story,
            "next_actions": synth.recommended_next_actions}


def _changes(synth) -> list[str]:
    out = []
    for item in synth.investigation_story[-8:]:
        out.append(f"{item['label']}: {item['text']}")
    return out or ["no change recorded since previous run"]


JARVIS_TEMPLATES = {
    "cross_checked": "I cross-checked this result using two independent analytical passes.",
    "agree_single_source": ("Both analytical passes agree, but the evidence still "
                            "comes from one upstream source."),
    "temporal": "The second review found a temporal inconsistency.",
    "identity_unresolved": ("The first analysis linked these identities, but the "
                            "second found insufficient evidence, so I left them "
                            "unresolved."),
    "duplicates": ("Two or more source records appear to be copies of the same "
                   "upstream publication."),
    "hypothesis": ("This hypothesis remains plausible but cannot be verified with "
                   "current evidence."),
    "degraded": "AI analysis was unavailable, so I kept only deterministic evidence.",
}


def jarvis_lines(synth) -> list[str]:
    lines = [JARVIS_TEMPLATES["cross_checked"]]
    single = [f for f in synth.observations + synth.hypotheses
              if f.get("ai_reasoning_agreement") and not f.get("evidence_corroboration")]
    if single:
        lines.append(JARVIS_TEMPLATES["agree_single_source"])
    if any("temporal" in str(c) for c in synth.contradictions):
        lines.append(JARVIS_TEMPLATES["temporal"])
    if any(h.get("kind") == "alternative_explanation" for h in synth.hypotheses):
        lines.append(JARVIS_TEMPLATES["hypothesis"])
    for run_ind in synth.source_independence.get("per_run", []):
        if run_ind.get("copied_lineages"):
            lines.append(JARVIS_TEMPLATES["duplicates"])
            break
    if synth.limitations and any("degraded" in l for l in synth.limitations):
        lines.append(JARVIS_TEMPLATES["degraded"])
    return lines
