"""Generate required answers (sub-questions) from investigation type."""

from __future__ import annotations

from traceatlas.core.objective_spec import RequiredAnswer

_TEMPLATES: dict[str, list[tuple[str, int]]] = {
    "infrastructure": [
        ("What is the current DNS resolution for each target domain?", 1),
        ("Which ASN and hosting provider owns each resolved IP?", 1),
        ("What certificates have been issued for the domains?", 2),
        ("Is there historical evidence of ownership changes?", 2),
    ],
    "company": [
        ("What is the registered legal identity of the company?", 1),
        ("Who are the listed officers/owners in public registries?", 1),
        ("What subsidiaries or related filings exist?", 2),
    ],
    "person": [
        ("Which public profiles plausibly belong to the target person?", 1),
        ("Do candidate identities corroborate across independent sources?", 1),
        ("What affiliations and locations are publicly documented?", 2),
    ],
    "username": [
        ("On which platforms does this username exist publicly?", 1),
        ("Do profile contents consistently point to the same actor?", 1),
    ],
    "social": [
        ("Which public accounts match the target identifiers?", 1),
        ("What public activity timeline can be established?", 2),
    ],
    "cti": [
        ("Are the indicators known malicious in public feeds?", 1),
        ("Which actors/campaigns are publicly associated with them?", 2),
    ],
    "general": [
        ("What entities are named in the objective?", 1),
        ("What public evidence addresses the objective?", 1),
    ],
}


def generate_required_answers(investigation_type: str, text: str) -> list[RequiredAnswer]:
    templates = _TEMPLATES.get(investigation_type, _TEMPLATES["general"])
    return [RequiredAnswer(question=q, priority=p) for q, p in templates]
