"""Final synthesis builder (§35, §37) — deterministic by construction.

Assembles the WHAT WE KNOW / THINK / DON'T KNOW / CONFLICTS structure from
cross-check + grounding + adjudication records. False claims cannot survive:
a statement reaches "what we know" ONLY if it is grounded AND corroborated by
independent sources (or adjudicated SUPPORTED). Model agreement alone routes
statements to "what we think".
"""

from __future__ import annotations

from traceatlas.analysis.confidence import cap_for
from traceatlas.analysis.result import FinalSynthesis


def build_final_synthesis(ctx, run) -> FinalSynthesis:
    fs = FinalSynthesis()
    if run.degraded:
        fs.what_we_do_not_know.append(
            "AI analysis unavailable or evidence rejected — deterministic gate "
            f"status {run.validation_status}; raw evidence retained unchanged")
        fs.next_actions.append("re-run dual analysis once models/evidence valid")
        fs.what_conflicts.extend(run.validation_issues[:10])
        return fs

    verdicts = {}
    if run.adjudication is not None:
        verdicts = {d.statement: d.verdict for d in run.adjudication.decisions}

    items = run.cross_check.items if run.cross_check else []
    for item in items:
        verdict = verdicts.get(item.statement)
        if verdict in ("UNSUPPORTED",):
            continue                       # false claim must not be preserved
        if verdict == "HUMAN_REVIEW_REQUIRED" or item.statement in _needs_human(run):
            fs.what_conflicts.append(
                f"[HUMAN REVIEW] {item.statement} — {item.recommended_resolution}")
            continue
        if verdict == "DISPUTED" or item.agreement_status == "DISAGREE":
            fs.what_conflicts.append(
                f"{item.statement} — passes disagree ({item.conflict_reason}); "
                "status INCONCLUSIVE")
            continue
        if verdict == "INCONCLUSIVE":
            if item.statement not in fs.what_we_do_not_know:
                fs.what_we_do_not_know.append(item.statement)
            continue
        supported_strictly = (
            item.evidence_corroboration and item.independence == "independent"
            and item.temporal_consistency not in ("stale", "conflicting")
            and cap_for(item) >= 0.75
            and (verdict in ("SUPPORTED", "PARTIALLY_SUPPORTED")
                 or item.agreement_status in ("AGREE", "SEMANTIC_AGREEMENT")))
        if supported_strictly:
            fs.what_we_know.append(
                f"{item.statement} [evidence: {','.join(item.evidence_ids)}; "
                f"independence: {item.independence}]")
        elif item.ai_reasoning_agreement:
            fs.what_we_think.append(
                f"{item.statement} — both passes agree but corroboration is "
                f"{item.source_support}/{item.independence}")
        elif item.agreement_status in ("PASS1_ONLY", "PASS2_ONLY"):
            fs.what_we_think.append(
                f"{item.statement} — surfaced by one pass only; unconfirmed")
        else:
            fs.what_we_do_not_know.append(item.statement)

    # gaps & next actions from the passes themselves
    for src in (run.primary, run.secondary):
        if src is None:
            continue
        for m in src.missing_information:
            if m not in fs.what_we_do_not_know:
                fs.what_we_do_not_know.append(m)
        for a in src.recommended_next_actions:
            if a not in fs.next_actions:
                fs.next_actions.append(a)
    for c in run.contradictions:
        note = c.get("note") or c.get("resolution") or ""
        line = f"{c.get('statement', c.get('kind', 'contradiction'))}: {note}".strip(": ")
        if line not in fs.what_conflicts:
            fs.what_conflicts.append(line)
    if run.model_diversity == "LOW":
        fs.what_conflicts.append(
            "MODEL_DIVERSITY=LOW: both passes used the same base model; "
            "reasoning agreement carries reduced analytical weight")
    # dedupe preserving order
    for name in ("what_we_know", "what_we_think", "what_we_do_not_know",
                 "what_conflicts", "next_actions"):
        setattr(fs, name, list(dict.fromkeys(getattr(fs, name))))
    if not fs.next_actions:
        fs.next_actions.append("collect an independent source for each "
                               "single-source finding")
    return fs


def _needs_human(run) -> set[str]:
    if run.adjudication is None:
        return set()
    return {d.statement for d in run.adjudication.decisions
            if d.requires_human_review}
