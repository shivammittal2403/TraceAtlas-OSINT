"""Case + case-memory repository over the SQLite persistence layer.

Replaces the process-local ``_CASES`` dict previously used by the API: cases
and their versioned CaseMemory snapshots now survive restarts, and every prior
version stays readable (append-only; nothing is silently overwritten).

Domain-facing API only — raw SQL lives in traceatlas.db.engine.
"""

from __future__ import annotations

from dataclasses import replace

from traceatlas.core.case import Case
from traceatlas.db.engine import Database
from traceatlas.exceptions import ValidationError
from traceatlas.trust.case_memory import CaseMemory
from traceatlas.trust.hydrate import hydrate_case_memory
from traceatlas.trust.model import utcnow


class CaseStore:
    """Repository for cases and their durable, versioned investigation state."""

    def __init__(self, db: Database) -> None:
        self.db = db

    # ------------------------------------------------------------- cases
    def create_case(self, *, title: str, description: str = "",
                    tenant_id: str = "default", tags: list[str] | None = None) -> Case:
        if not title or not title.strip():
            raise ValidationError("case title must be non-empty")
        case = Case(title=title.strip(), description=description,
                    tenant_id=tenant_id, tags=list(tags or []))
        self.db.upsert_case(case.to_dict())
        return case

    def get_case(self, case_id: str, *, tenant_id: str | None = None) -> Case | None:
        row = self.db.get_case(case_id)
        if row is None:
            return None
        if tenant_id is not None and row["tenant_id"] != tenant_id:
            # tenant isolation: a foreign case is indistinguishable from absent
            return None
        return Case(id=row["id"], title=row["title"], description=row["description"],
                    tenant_id=row["tenant_id"], created_at=row["created_at"],
                    updated_at=row["updated_at"], tags=row["tags"],
                    archived=row["archived"])

    def list_cases(self, *, tenant_id: str | None = None,
                   include_archived: bool = False) -> list[Case]:
        rows = self.db.list_cases(tenant_id=tenant_id, include_archived=include_archived)
        return [Case(id=r["id"], title=r["title"], description=r["description"],
                     tenant_id=r["tenant_id"], created_at=r["created_at"],
                     updated_at=r["updated_at"], tags=r["tags"],
                     archived=r["archived"]) for r in rows]

    def set_archived(self, case_id: str, archived: bool) -> Case | None:
        case = self.get_case(case_id)
        if case is None:
            return None
        updated = replace(case, archived=archived, updated_at=utcnow())
        self.db.upsert_case(updated.to_dict())
        return updated

    # -------------------------------------------------------- case memory
    def save_memory(self, memory: CaseMemory) -> int | None:
        """Commit current canonical state as a new snapshot version.

        Returns the new version number, or None when nothing changed since the
        previous commit (canonical-JSON equality check).
        """
        version = self.db.commit_snapshot(memory.case_id, memory.to_dict(),
                                          committed_at=utcnow())
        if version is not None:
            case = self.get_case(memory.case_id)
            if case is not None:
                self.db.upsert_case(replace(case, updated_at=utcnow()).to_dict())
        return version

    def load_memory(self, case_id: str, *, version: int | None = None) -> CaseMemory | None:
        """Hydrate canonical state at ``version`` (default: latest)."""
        snap = (self.db.snapshot_at(case_id, version) if version is not None
                else self.db.latest_snapshot(case_id))
        if snap is None:
            return None
        mem, _warnings = hydrate_case_memory(snap["payload"])
        return mem

    def memory_history(self, case_id: str) -> list[dict]:
        return self.db.snapshot_history(case_id)

    def audit_events(self, case_id: str, *, limit: int = 200) -> list[dict]:
        return self.db.audit_events(case_id, limit=limit)
