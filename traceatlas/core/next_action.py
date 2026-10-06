"""NextBestAction: ranked proposal for the next investigative step."""

from __future__ import annotations

from dataclasses import dataclass, field

from traceatlas.core.serialization import to_jsonable


@dataclass
class NextAction:
    description: str
    action_kind: str          # collect | verify | analyze | ask_human | stop
    expected_information_gain: float = 0.0
    estimated_cost_units: float = 0.0
    requires_human_approval: bool = False
    rationale: str = ""
    score: float = field(default=0.0)

    def to_dict(self) -> dict:
        return to_jsonable(self)
