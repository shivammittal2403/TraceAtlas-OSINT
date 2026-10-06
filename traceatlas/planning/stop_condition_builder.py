"""Build explicit stop conditions so investigations cannot run forever."""

from __future__ import annotations

from traceatlas.core.objective_spec import ObjectiveSpec


def build_stop_conditions(spec: ObjectiveSpec) -> list[str]:
    return [
        "all priority-1 required answers have verified claims or recorded gaps",
        "budget exhausted",
        "kill switch engaged",
        "human reviewer requests stop",
        f"max wall-clock reached (default policy)",
    ]
