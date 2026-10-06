"""Policy engine (minimal core): decides whether an action may run.

Enforced rules in this build:
1. Kill switch halts everything.
2. Public-only mode refuses actions flagged as requiring authorization.
3. Prohibited action names from Scope are always refused.
Everything else returns REQUIRE_HUMAN_REVIEW rather than silently allowing.
"""

from __future__ import annotations

from enum import Enum

from traceatlas.core.enums import AuthorizationMode
from traceatlas.core.scope import Scope
from traceatlas.exceptions import KillSwitchActive
from traceatlas.security.kill_switch import is_engaged


class PolicyDecision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_HUMAN_REVIEW = "require_human_review"


_PUBLIC_ONLY_ALLOWED_PREFIXES = ("collect.public.", "analyze.", "verify.", "report.")


def evaluate(action: str, mode: AuthorizationMode, scope: Scope) -> PolicyDecision:
    try:
        if is_engaged():
            return PolicyDecision.DENY
    except KillSwitchActive:
        return PolicyDecision.DENY
    if action in scope.prohibited_actions:
        return PolicyDecision.DENY
    if mode == AuthorizationMode.PUBLIC_ONLY:
        if any(action.startswith(p) for p in _PUBLIC_ONLY_ALLOWED_PREFIXES):
            return PolicyDecision.ALLOW
        return PolicyDecision.DENY
    return PolicyDecision.REQUIRE_HUMAN_REVIEW
