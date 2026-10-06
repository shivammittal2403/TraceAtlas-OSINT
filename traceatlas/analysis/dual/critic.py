"""Critic role definition: what the second pass is instructed to hunt for (§34).
Kept as data so prompts/tests can assert coverage of every mandated target."""

CRITIC_TARGETS = [
    "unsupported_claims", "alternative_interpretations", "identity_mistakes",
    "timeline_errors", "stale_evidence", "copied_sources",
    "relationship_overreach", "missing_context", "contradictory_evidence",
    "confirmation_bias",
]
