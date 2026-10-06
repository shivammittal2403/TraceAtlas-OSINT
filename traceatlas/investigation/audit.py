"""Append-only audit trail emitter.

Every consequential action (dispatch, collection, entity write, verification
decision) is recorded as an immutable JSONL event. Production deployments
should additionally ship these to the DB `audit` table; this file-backed
emitter keeps integrity simple and dependency-free.
"""

from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class AuditEvent:
    case_id: str
    action: str                    # e.g. "task.dispatch", "evidence.capture"
    actor: str                     # employee/connector/system identity
    subject_id: str = ""           # object acted upon
    detail: dict = field(default_factory=dict)
    investigation_id: str = ""
    task_id: str = ""
    ts: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "ts": self.ts, "case_id": self.case_id,
            "investigation_id": self.investigation_id, "task_id": self.task_id,
            "action": self.action, "actor": self.actor,
            "subject_id": self.subject_id, "detail": self.detail,
        }


class AuditTrail:
    def __init__(self, path: Path | str | None = None) -> None:
        self.path = Path(path) if path else None
        self.events: list[AuditEvent] = []
        self._lock = threading.Lock()
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)

    def record(self, event: AuditEvent) -> AuditEvent:
        with self._lock:
            self.events.append(event)
            if self.path:
                with open(self.path, "a", encoding="utf-8") as fh:
                    fh.write(json.dumps(event.to_dict(), sort_keys=True, default=str) + "\n")
        return event

    def emit(self, case_id: str, action: str, actor: str, subject_id: str = "",
             detail: dict | None = None, investigation_id: str = "",
             task_id: str = "") -> AuditEvent:
        return self.record(AuditEvent(
            case_id=case_id, action=action, actor=actor, subject_id=subject_id,
            detail=detail or {}, investigation_id=investigation_id, task_id=task_id,
        ))

    def for_case(self, case_id: str) -> list[AuditEvent]:
        with self._lock:
            return [e for e in self.events if e.case_id == case_id]
