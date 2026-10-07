"""Pass isolation: the secondary analyst must never see primary conclusions.

This module enforces that structurally, not by prompt etiquette:
  * build_primary_prompt() and build_secondary_prompt() render the SAME
    evidence snapshot but different system instructions;
  * the secondary prompt builder has no parameter through which primary
    output could be injected (enforced by test_isolation.py which greps the
    rendered prompt for primary statement text);
  * only comparison.py receives both results.
"""

from __future__ import annotations

from traceatlas.analysis.context import EvidenceContext
from traceatlas.analysis.dual.prompts import (ADJUDICATOR_SYSTEM,
                                              PRIMARY_SYSTEM, SECONDARY_SYSTEM)
from traceatlas.analysis.result import (ANALYSIS_SCHEMA_HINT, AnalysisPassResult)

TASK_INSTRUCTIONS_PRIMARY = (
    "Produce facts (only when directly supported by cited evidence), "
    "observations, insights, inferences, hypotheses, and explicit unknowns. "
    "Every material conclusion MUST cite evidence_ids from the block above. "
    "Answer each investigation QUESTION listed. Note source limitations.")

TASK_INSTRUCTIONS_SECONDARY = (
    "Independently analyze the same evidence. Explicitly identify: what is "
    "directly supported; what is ambiguous; whether stated relationships are "
    "justified; claims that would be too strong; alternative explanations; "
    "identity/temporal mistakes; stale or copied sources; missing context; "
    "contradictions; confirmation-bias risks. Use kind=fact ONLY where the "
    "cited evidence literally supports it.")


def _user_block(evidence: EvidenceContext) -> str:
    return evidence.render_for_prompt() + "\n\n" + ANALYSIS_SCHEMA_HINT


def build_primary_prompt(evidence: EvidenceContext) -> tuple[str, str]:
    return PRIMARY_SYSTEM, TASK_INSTRUCTIONS_PRIMARY + "\n\n" + _user_block(evidence)


def build_secondary_prompt(evidence: EvidenceContext) -> tuple[str, str]:
    # NOTE: deliberately NO access to any primary-pass data structure here.
    return SECONDARY_SYSTEM, TASK_INSTRUCTIONS_SECONDARY + "\n\n" + _user_block(evidence)


def build_adjudication_prompt(evidence: EvidenceContext, primary: AnalysisPassResult,
                              secondary: AnalysisPassResult,
                              cross_check: list[dict]) -> tuple[str, str]:
    """Only the adjudication stage may see BOTH passes."""
    p = [PRIMARY_SYSTEM]
    lines = ["EVIDENCE:\n" + evidence.render_for_prompt(60),
             "", "PRIMARY PASS STATEMENTS:"]
    for s in primary.statements:
        lines.append(f"- [{s.kind.value}/{s.importance.value}] {s.text} "
                     f"(evidence: {', '.join(s.evidence_ids) or 'NONE'})")
    lines.append("")
    lines.append("SECONDARY PASS STATEMENTS:")
    for s in secondary.statements:
        lines.append(f"- [{s.kind.value}/{s.importance.value}] {s.text} "
                     f"(evidence: {', '.join(s.evidence_ids) or 'NONE'})")
    lines.append("")
    lines.append("CROSS-CHECK ITEMS TO ADJUDICATE:")
    for item in cross_check:
        lines.append(f"- {item['statement']} | agreement={item['agreement']} "
                     f"| grounded={item.get('evidence_grounded')} "
                     f"| independent_sources={item.get('independent_sources')}")
    lines.append("")
    lines.append('Respond JSON: {"decisions": [{"statement": str, "outcome": '
                 '"supported|partially_supported|disputed|inconclusive|unsupported'
                 '|human_review_required", "rationale": str, '
                 '"required_evidence": [str]}]}')
    return ADJUDICATOR_SYSTEM, "\n".join(lines)
