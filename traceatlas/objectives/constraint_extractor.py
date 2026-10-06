"""Extract scope constraints expressed in natural language."""

from __future__ import annotations

import re

from traceatlas.core.objective_spec import Constraint

_ONLY_RE = re.compile(r"\bonly\s+(?:look at |search )?([^.;\n]+)", re.I)
_EXCLUDE_RE = re.compile(r"\b(?:exclude|do not|don't|avoid)\s+([^.;\n]+)", re.I)


def extract_constraints(text: str) -> list[Constraint]:
    out: list[Constraint] = []
    for m in _ONLY_RE.finditer(text):
        out.append(Constraint(kind="scope", value=f"only: {m.group(1).strip()}"))
    for m in _EXCLUDE_RE.finditer(text):
        out.append(Constraint(kind="prohibition", value=m.group(1).strip()))
    return out
