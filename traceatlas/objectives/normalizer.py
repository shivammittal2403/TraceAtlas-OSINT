"""Normalize objective text before parsing (whitespace, unicode NFKC, case)."""

from __future__ import annotations

import re
import unicodedata


def normalize_objective_text(text: str) -> str:
    text = unicodedata.normalize("NFKC", text)
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\s*\n\s*", "\n", text)
    return text.strip()
