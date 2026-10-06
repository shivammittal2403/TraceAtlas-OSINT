"""Registry of available employees."""

from __future__ import annotations

from traceatlas.employees.base import BaseEmployee

_REGISTRY: dict[str, type[BaseEmployee]] = {}


def register(cls: type[BaseEmployee]) -> type[BaseEmployee]:
    _REGISTRY[cls.name] = cls
    return cls


def get_employee(name: str) -> BaseEmployee:
    if name not in _REGISTRY:
        raise KeyError(f"unknown employee: {name}")
    return _REGISTRY[name]()


def list_employees() -> list[str]:
    return sorted(_REGISTRY)
