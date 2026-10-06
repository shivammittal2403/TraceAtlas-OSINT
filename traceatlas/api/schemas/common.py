"""Common response envelope."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class ApiErrorBody:
    code: str
    message: str
