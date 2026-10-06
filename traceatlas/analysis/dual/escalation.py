"""Escalation rules: when a finding leaves the AI pipeline for a human (§7, §39)."""

from __future__ import annotations

ESCALATE_VERDICTS = {"HUMAN_REVIEW_REQUIRED"}


def escalations_for(run) -> list[dict]:
    out = []
    if run.adjudication is not None:
        for d in run.adjudication.decisions:
            if d.requires_human_review or d.verdict in ESCALATE_VERDICTS:
                out.append({"statement": d.statement, "verdict": d.verdict,
                            "reason": d.reason})
    for e in getattr(run, "entities", []):
        if e.get("decision") == "ALLOWED_WITH_HUMAN_REVIEW":
            out.append({"statement": e["statement"],
                        "verdict": "IDENTITY_MERGE_REVIEW",
                        "reason": "high-impact merge requires human sign-off (§24)"})
    return out
