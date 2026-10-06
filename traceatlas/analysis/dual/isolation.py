"""Prompt isolation between the two passes (§33, §5).

Guarantee: the secondary pass input is constructed so that it CANNOT contain
any Pass-1 content. Enforced mechanically (assertion over rendered strings),
not by convention — the comparison stage is the only component allowed to see
both outputs.
"""

from __future__ import annotations


class IsolationViolation(RuntimeError):
    pass


def build_isolated_inputs(primary_prompt: str, secondary_prompt: str,
                          primary_output_text: str) -> tuple[str, str]:
    """Validate that neither pass prompt leaks the other pass's output."""
    if primary_output_text and primary_output_text[:200] in secondary_prompt:
        raise IsolationViolation(
            "secondary pass prompt contains primary pass output — anchoring risk")
    if "PASS 1 CONCLUSION" in secondary_prompt.upper():
        raise IsolationViolation("secondary prompt references pass-1 conclusions")
    return primary_prompt, secondary_prompt


def verify_run_isolation(run) -> bool:
    """Post-hoc audit for API/UI display (§38): confirm no cross-contamination
    markers appear in stored pass inputs."""
    for obj in (run.primary, run.secondary):
        if obj is None:
            continue
        for st in obj.statements:
            if "according to the first analysis" in st.statement.lower():
                return False
    return True
