"""When to invoke the third-stage adjudicator (§7) and cost policy (§39).

Triggers (any of):
- material disagreement between passes (DISAGREE rows);
- high-impact hypothesis present;
- identity merge proposed; attribution proposed;
- important contradiction exists; weak source evidence for a strong claim;
- claim would otherwise carry HIGH/VERY_HIGH confidence.

Cost control (§39): LOW importance -> single pass allowed; MEDIUM -> second
pass only when uncertainty warrants it; HIGH -> mandatory dual; CRITICAL ->
dual + adjudication/human review. Identity merges, attribution, executive
findings, high-risk CTI, corporate ownership and major blockchain attribution
are ALWAYS dual + adjudicated.
"""

from __future__ import annotations

MATERIAL_STATUSES = {"DISAGREE"}
STRONG_CONFIDENCE = 0.75


class AdjudicationPolicy:
    def __init__(self, *, always_dual_kinds=None):
        self.always_dual_kinds = set(always_dual_kinds or (
            "identity_merge", "attribution", "executive_finding",
            "high_risk_cti", "corporate_ownership", "blockchain_attribution",
            "material_contradiction"))

    def dual_required(self, importance: str, *, kind_flags: set[str] | None = None,
                      uncertainty: str = "medium") -> bool:
        if self.always_dual_kinds & (kind_flags or set()):
            return True
        if importance.upper() in ("HIGH", "CRITICAL"):
            return True
        if importance.upper() == "MEDIUM" and uncertainty in ("medium", "high"):
            return True
        return False

    def triggers_for(self, run, *, importance: str = "high",
                     identity_merge: bool = False,
                     attribution: bool = False) -> list[str]:
        """Return trigger names; empty list => no adjudicator call (§7)."""
        triggers: list[str] = []
        cc = run.cross_check
        if cc is not None:
            material = [i for i in cc.items
                        if i.agreement_status in MATERIAL_STATUSES]
            if material:
                triggers.append("material_disagreement")
            strong_unsupported = [
                i for i in cc.items
                if i.ai_reasoning_agreement and not i.evidence_corroboration
                and _max_conf(i.pass1_assessment, i.pass2_assessment) >= STRONG_CONFIDENCE]
            if strong_unsupported:
                triggers.append("strong_claim_weak_evidence")
        if getattr(run, "contradictions", None):
            triggers.append("important_contradiction")
        if identity_merge:
            triggers.append("identity_merge")
        if attribution:
            triggers.append("attribution")
        p1 = run.primary
        if p1 is not None and any(s.kind == "hypothesis" and s.confidence >= 0.8
                                  for s in p1.statements):
            triggers.append("high_impact_hypothesis")
        if importance.upper() == "CRITICAL" and "material_disagreement" not in triggers:
            triggers.append("critical_importance")
        # dedupe, keep order
        seen: set[str] = set()
        return [t for t in triggers if not (t in seen or seen.add(t))]


def _max_conf(a: str, b: str) -> float:
    best = 0.0
    for text in (a, b):
        try:
            best = max(best, float(text.rsplit("conf=", 1)[1]))
        except (ValueError, IndexError):
            continue
    return best
