"""Extract explicit requirements stated in the objective text."""

from __future__ import annotations

import re

_REQ_RE = re.compile(r"\b(must|need to|should also|required:)\s+([^.;\n]+)", re.I)


def extract_requirements(text: str) -> list[str]:
    return [m.group(2).strip() for m in _REQ_RE.finditer(text)]
