"""Authorization records governing what the operator is permitted to collect."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from traceatlas.core.enums import AuthorizationMode
from traceatlas.core.identifiers import new_id
from traceatlas.core.serialization import to_jsonable
from traceatlas.core.validation import utcnow


@dataclass
class Authorization:
    case_id: str
    mode: AuthorizationMode = AuthorizationMode.PUBLIC_ONLY
    granted_by: str = ""            # human who granted it
    evidence_reference: str = ""    # where the permission is documented
    expires_at: datetime | None = None
    id: str = field(default_factory=lambda: new_id("authz"))
    created_at: datetime = field(default_factory=utcnow)

    def is_expired(self, now: datetime | None = None) -> bool:
        return self.expires_at is not None and (now or utcnow()) >= self.expires_at

    def to_dict(self) -> dict:
        return to_jsonable(self)
