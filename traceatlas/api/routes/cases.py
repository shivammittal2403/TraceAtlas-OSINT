"""Case endpoints (in-memory store until the database layer lands)."""

from __future__ import annotations

try:
    from fastapi import APIRouter, HTTPException
    from pydantic import BaseModel
except ImportError:  # pragma: no cover
    APIRouter = None  # type: ignore

router = APIRouter(prefix="/api/cases", tags=["cases"]) if APIRouter else None

# Deliberately process-local: persistence is a documented gap (.ai/CURRENT_STATE.md).
_CASES: dict[str, dict] = {}

if router is not None:

    class CaseCreate(BaseModel):
        title: str
        description: str = ""

    @router.post("")
    def create_case(body: CaseCreate) -> dict:
        from traceatlas.core.case import Case

        case = Case(title=body.title, description=body.description)
        _CASES[case.id] = case.to_dict()
        return _CASES[case.id]

    @router.get("")
    def list_cases() -> list[dict]:
        return list(_CASES.values())

    @router.get("/{case_id}")
    def get_case(case_id: str) -> dict:
        if case_id not in _CASES:
            raise HTTPException(status_code=404, detail="case not found")
        return _CASES[case_id]
