"""Typed settings loaded from environment variables (stdlib-only)."""

from __future__ import annotations

import os
from dataclasses import dataclass, field


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def _env_int(name: str, default: int) -> int:
    raw = _env(name)
    try:
        return int(raw) if raw else default
    except ValueError:
        return default


@dataclass(frozen=True)
class DatabaseSettings:
    url: str = field(default_factory=lambda: _env("TRACEATLAS_DB_URL", "sqlite:///traceatlas.db"))


@dataclass(frozen=True)
class AISettings:
    provider: str = field(default_factory=lambda: _env("TRACEATLAS_AI_PROVIDER", "none"))
    model: str = field(default_factory=lambda: _env("TRACEATLAS_AI_MODEL", ""))
    api_key: str = field(default_factory=lambda: _env("TRACEATLAS_AI_API_KEY", ""))
    monthly_budget_usd: float = field(
        default_factory=lambda: float(_env("TRACEATLAS_AI_BUDGET_USD", "0") or 0)
    )


@dataclass(frozen=True)
class SecuritySettings:
    kill_switch_file: str = field(
        default_factory=lambda: _env("TRACEATLAS_KILL_SWITCH_FILE", ".traceatlas_killswitch")
    )
    allow_live_collection: bool = field(
        default_factory=lambda: _env("TRACEATLAS_ALLOW_LIVE_COLLECTION", "false").lower() == "true"
    )


@dataclass(frozen=True)
class Settings:
    environment: str = field(default_factory=lambda: _env("TRACEATLAS_ENV", "development"))
    log_level: str = field(default_factory=lambda: _env("TRACEATLAS_LOG_LEVEL", "INFO"))
    db: DatabaseSettings = field(default_factory=DatabaseSettings)
    ai: AISettings = field(default_factory=AISettings)
    security: SecuritySettings = field(default_factory=SecuritySettings)


_settings: Settings | None = None


def get_settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings
