"""Case: the top-level container for an investigation."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from traceatlas.core.identifiers import new_id
from traceatlas.core.serialization import to_jsonable
from traceatlas.core.validation import utcnow


@dataclass
class Case:
    title: str
    description: str = ""
    tenant_id: str = "default"
    id: str = field(default_factory=lambda: new_id("case"))
    created_at: datetime = field(default_factory=utcnow)
    updated_at: datetime = field(default_factory=utcnow)
    tags: list[str] = field(default_factory=list)
    archived: bool = False

    def to_dict(self) -> dict:
        return to_jsonable(self)
