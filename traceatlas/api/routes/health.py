"""Health and truthful capability surface."""

from __future__ import annotations

try:
    from fastapi import APIRouter, Request
except ImportError:  # pragma: no cover
    APIRouter = None  # type: ignore

router = APIRouter(prefix="/api", tags=["health"]) if APIRouter else None

if router is not None:

    @router.get("/health")
    def health() -> dict:
        return {"status": "ok"}

    @router.get("/capabilities")
    def capabilities(request: "Request") -> dict:
        app_obj = request.app.state.application
        return app_obj.capabilities
