"""Kill switch: file-based halt checked before every dispatch."""

from __future__ import annotations

from pathlib import Path

from traceatlas.config import get_settings
from traceatlas.exceptions import KillSwitchActive


def is_engaged(path: str | None = None) -> bool:
    return Path(path or get_settings().security.kill_switch_file).exists()


def ensure_not_engaged(path: str | None = None) -> None:
    if is_engaged(path):
        raise KillSwitchActive("kill switch file present; all autonomous work halted")


def engage(path: str | None = None) -> Path:
    p = Path(path or get_settings().security.kill_switch_file)
    p.write_text("ENGAGED")
    return p


def disengage(path: str | None = None) -> None:
    p = Path(path or get_settings().security.kill_switch_file)
    p.unlink(missing_ok=True)
