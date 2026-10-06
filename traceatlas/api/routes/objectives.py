"""Objective drafting + rule-based parsing endpoint."""

from __future__ import annotations

try:
    from fastapi import APIRouter, HTTPException
    from pydantic import BaseModel
except ImportError:  # pragma: no cover
    APIRouter = None  # type: ignore

router = (
    APIRouter(prefix="/api/cases/{case_id}/objectives", tags=["objectives"])
    if APIRouter
    else None
)

_OBJECTIVES: dict[str, list[dict]] = {}

if router is not None:

    class ObjectiveCreate(BaseModel):
        text: str

    @router.post("")
    def add_objective(case_id: str, body: ObjectiveCreate) -> dict:
        from traceatlas.core.objective import Objective
        from traceatlas.objectives.parser import parse_objective

        obj = Objective(case_id=case_id, text=body.text)
        spec = parse_objective(obj)
        record = {"objective": obj.to_dict(), "spec": spec.to_dict()}
        _OBJECTIVES.setdefault(case_id, []).append(record)
        return record

    @router.get("")
    def list_objectives(case_id: str) -> list[dict]:
        return _OBJECTIVES.get(case_id, [])
