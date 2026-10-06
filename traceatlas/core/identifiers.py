"""Identifier generation and validation."""

from __future__ import annotations

import re
import uuid

_ID_RE = re.compile(r"^[a-z]+_[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$")


def new_id(prefix: str) -> str:
    """Return a sortable, collision-resistant identifier like 'case_<uuid4>'."""
    return f"{prefix}_{uuid.uuid4()}"


def is_valid_id(value: str, prefix: str | None = None) -> bool:
    if not _ID_RE.match(value):
        return False
    return prefix is None or value.startswith(f"{prefix}_")
