"""Checkpoint writer/reader: durable snapshots for resume & recovery.

A checkpoint is a JSON document capturing everything needed to resume an
investigation: plan, remaining tasks with statuses, and the knowledge context
summary (entity keys, evidence ids, cost spent). Blobs themselves live in the
content-addressed EvidenceStore and are NOT duplicated here.
"""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path


@dataclass
class Checkpoint:
    investigation_id: str
    case_id: str
    wave: int
    task_states: dict = field(default_factory=dict)     # task_id -> status value
    entity_keys: list[str] = field(default_factory=list)
    evidence_ids: list[str] = field(default_factory=list)
    completed_task_kinds: list[str] = field(default_factory=list)
    cost_units_spent: float = 0.0
    notes: dict = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)
    version: int = 1

    def to_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True, indent=2)


class CheckpointStore:
    def __init__(self, root: Path | str = ".traceatlas-checkpoints") -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, investigation_id: str) -> Path:
        safe = "".join(c for c in investigation_id if c.isalnum() or c in "-_")
        return self.root / f"{safe}.json"

    def write(self, cp: Checkpoint) -> Path:
        path = self._path(cp.investigation_id)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(cp.to_json(), encoding="utf-8")
        tmp.replace(path)
        return path

    def read(self, investigation_id: str) -> Checkpoint | None:
        path = self._path(investigation_id)
        if not path.is_file():
            return None
        data = json.loads(path.read_text(encoding="utf-8"))
        if data.get("version") != 1:
            raise ValueError(f"unsupported checkpoint version {data.get('version')}")
        return Checkpoint(**data)

    def delete(self, investigation_id: str) -> None:
        p = self._path(investigation_id)
        if p.exists():
            p.unlink()
