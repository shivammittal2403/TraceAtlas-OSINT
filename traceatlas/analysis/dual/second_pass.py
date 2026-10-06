"""Pass 2 — INDEPENDENT CRITICAL ANALYST entry point (§5, §34).

Runs on the SAME evidence context as pass 1 but with the adversarial system
prompt; receives none of pass 1's conclusions during this initial stage.
"""
from traceatlas.analysis.prompts import SECONDARY_SYSTEM  # noqa: F401
from traceatlas.analysis.engine import DualAnalysisEngine  # noqa: F401


def run_secondary(engine: DualAnalysisEngine, ctx, model: str | None = None):
    from traceatlas.analysis.deterministic_grounding import ground_pass
    pass_obj = engine._run_pass("secondary", SECONDARY_SYSTEM, ctx,
                                model or engine.secondary_model)
    return pass_obj, ground_pass(pass_obj, ctx)
