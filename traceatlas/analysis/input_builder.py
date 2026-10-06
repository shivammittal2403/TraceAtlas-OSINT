"""Input builder facade: constructs pass inputs deterministically (§33).

The SAME rendered evidence text is fed to both passes; only the system prompt
(role) differs. Pass 2's input never contains Pass 1 output — enforced here by
construction and verified by isolation tests.
"""

from __future__ import annotations

from traceatlas.analysis.evidence_context import EvidenceContext
from traceatlas.analysis.prompts import PRIMARY_SYSTEM, SECONDARY_SYSTEM


def build_pass_inputs(ctx: EvidenceContext) -> tuple[dict, dict]:
    body = ctx.render_for_prompt()
    common = {"user_content": body}
    return ({"system": PRIMARY_SYSTEM, **common},
            {"system": SECONDARY_SYSTEM, **common})
