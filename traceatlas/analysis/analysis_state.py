"""Per-case store of dual-analysis runs (memory + JSON persistence)."""

from __future__ import annotations

import json
import os
import threading

from traceatlas.analysis.engine import DualAnalysisRun


class AnalysisStateStore:
    def __init__(self, path: str = "data/state/analysis_runs.json"):
        self.path = path
        self._lock = threading.Lock()
        self._runs: dict[str, dict[str, dict]] = {}   # case_id -> run_id -> dict
        self._load()

    def _load(self) -> None:
        if os.path.exists(self.path):
            try:
                with open(self.path, encoding="utf-8") as fh:
                    data = json.load(fh)
                if isinstance(data, dict):
                    self._runs = data
            except (json.JSONDecodeError, OSError):
                self._runs = {}

    def _save(self) -> None:
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(self._runs, fh, default=str)
        os.replace(tmp, self.path)

    def put(self, run: DualAnalysisRun) -> None:
        with self._lock:
            self._runs.setdefault(run.case_id, {})[run.run_id] = run.to_dict()
            self._save()

    def latest(self, case_id: str) -> dict | None:
        with self._lock:
            runs = self._runs.get(case_id) or {}
            if not runs:
                return None
            return max(runs.values(), key=lambda r: str(r.get("started_at", "")))

    def list_runs(self, case_id: str) -> list[dict]:
        with self._lock:
            return sorted((self._runs.get(case_id) or {}).values(),
                          key=lambda r: str(r.get("started_at", "")))
