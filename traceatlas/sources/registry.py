"""Source registry: loads the governed YAML catalog (no live access implied)."""

from __future__ import annotations

import json
from pathlib import Path

_CATALOG_DIR = Path(__file__).resolve().parents[2] / "sources" / "catalog"


def list_catalog_files() -> list[str]:
    if not _CATALOG_DIR.is_dir():
        return []
    return sorted(p.name for p in _CATALOG_DIR.glob("*.yaml"))


def catalog_summary() -> dict:
    """Return counts per catalog file. Entries are parsed as simple '- id:' lines."""
    summary: dict[str, int] = {}
    for name in list_catalog_files():
        count = 0
        for line in (_CATALOG_DIR / name).read_text(encoding="utf-8").splitlines():
            if line.strip().startswith("- id:"):
                count += 1
        summary[name] = count
    return summary
