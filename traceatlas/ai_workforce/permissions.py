"""Permission model for the workforce (§4, §30).

Employees act only within allowed_actions and are hard-blocked by
prohibited_actions. Managers cannot bypass policy either — compliance holds
veto power over any task assignment.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class PermissionSet:
    allowed_actions: set[str] = field(default_factory=set)
    prohibited_actions: set[str] = field(default_factory=set)
    allowed_source_kinds: set[str] = field(default_factory=set)  # empty ⇒ all lawful kinds
    external_models_allowed: bool = True
    write_to_case_state: bool = False   # only gate-approved writes ever happen

    def can(self, action: str) -> bool:
        if action in self.prohibited_actions:
            return False
        return (not self.allowed_actions) or (action in self.allowed_actions)

    def can_use_source(self, kind: str) -> bool:
        return (not self.allowed_source_kinds) or (kind in self.allowed_source_kinds)


# Actions every worker is always forbidden from attempting directly:
GLOBAL_PROHIBITED = {
    "write_final_conclusions",       # only Chief synthesis + approved facts change conclusions
    "bypass_fact_gate",              # §8 hard rule
    "merge_identity_without_justification",
    "fabricate_evidence",
    "contact_private_person",        # no private-data collection
    "active_exploit",                # passive OSINT only
    "dark_market_transaction",
    "access_non_public_data",
}
