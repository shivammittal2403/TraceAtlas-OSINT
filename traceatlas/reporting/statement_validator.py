"""Ensure every reported finding statement traces back to evidence ids."""

from __future__ import annotations


def validate_findings(report: dict) -> list[str]:
    problems = []
    for f in report.get("findings", []):
        if not f.get("evidence_ids"):
            problems.append(f"finding without evidence: {f['statement'][:60]}")
    return problems
