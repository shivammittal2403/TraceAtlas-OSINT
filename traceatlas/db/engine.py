"""SQLite persistence layer (stdlib only — SQLAlchemy/Alembic remain optional).

Design: append-only versioned snapshots. ``case_snapshots`` stores one row per
committed state of a case; the newest row is current, and every earlier row can
still be read back (§ "historical facts must not be silently overwritten").
Writes are serialized as canonical JSON (sorted keys), so an unchanged state
produces no new version.

Tables
  cases            – case metadata (core.case.Case)
  case_snapshots   – versioned CaseMemory.to_dict() payloads
  audit_records    – flat audit events for cross-case queries

This module owns DB access; repositories/case_store.py builds the domain-facing
repository API on top of it.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from traceatlas.exceptions import ValidationError

DEFAULT_DB_PATH = Path("var") / "traceatlas.db"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS cases (
    id          TEXT PRIMARY KEY,
    tenant_id   TEXT NOT NULL DEFAULT 'default',
    title       TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL,
    tags        TEXT NOT NULL DEFAULT '[]',
    archived    INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS case_snapshots (
    case_id    TEXT NOT NULL,
    version    INTEGER NOT NULL,
    committed_at TEXT NOT NULL,
    payload    TEXT NOT NULL,
    sha256     TEXT NOT NULL,
    PRIMARY KEY (case_id, version)
);
CREATE TABLE IF NOT EXISTS audit_records (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id   TEXT NOT NULL,
    action    TEXT NOT NULL,
    ref       TEXT NOT NULL,
    at        TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_snap_case ON case_snapshots (case_id, version DESC);
CREATE INDEX IF NOT EXISTS ix_audit_case ON audit_records (case_id, id);
"""


def _canonical_json(payload: dict) -> str:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _sha256(text: str) -> str:
    import hashlib

    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class Database:
    """Thin connection wrapper with schema bootstrap and typed helpers."""

    def __init__(self, path: Path | str = DEFAULT_DB_PATH) -> None:
        self.path = Path(path)
        if str(self.path) != ":memory:" and self.path.parent != Path(""):
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    # ------------------------------------------------------------- lifecycle
    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "Database":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    # ---------------------------------------------------------------- cases
    def upsert_case(self, case: dict) -> None:
        required = ("id", "title", "created_at", "updated_at")
        missing = [k for k in required if not case.get(k)]
        if missing:
            raise ValidationError(f"case record missing fields: {missing}")
        with self._conn:
            self._conn.execute(
                """INSERT INTO cases (id, tenant_id, title, description,
                                      created_at, updated_at, tags, archived)
                   VALUES (:id, :tenant_id, :title, :description,
                           :created_at, :updated_at, :tags, :archived)
                   ON CONFLICT(id) DO UPDATE SET
                      tenant_id=excluded.tenant_id, title=excluded.title,
                      description=excluded.description,
                      updated_at=excluded.updated_at, tags=excluded.tags,
                      archived=excluded.archived""",
                {
                    "id": case["id"],
                    "tenant_id": case.get("tenant_id", "default"),
                    "title": case["title"],
                    "description": case.get("description", ""),
                    "created_at": str(case["created_at"]),
                    "updated_at": str(case["updated_at"]),
                    "tags": _canonical_json(case.get("tags", [])),
                    "archived": 1 if case.get("archived") else 0,
                },
            )

    def get_case(self, case_id: str) -> dict | None:
        row = self._conn.execute("SELECT * FROM cases WHERE id = ?", (case_id,)).fetchone()
        if row is None:
            return None
        d = dict(row)
        d["tags"] = json.loads(d.get("tags") or "[]")
        d["archived"] = bool(d.get("archived"))
        return d

    def list_cases(self, *, tenant_id: str | None = None,
                   include_archived: bool = False) -> list[dict]:
        sql = "SELECT * FROM cases"
        conds, params = [], []
        if tenant_id is not None:
            conds.append("tenant_id = ?")
            params.append(tenant_id)
        if not include_archived:
            conds.append("archived = 0")
        if conds:
            sql += " WHERE " + " AND ".join(conds)
        sql += " ORDER BY created_at DESC"
        rows = self._conn.execute(sql, params).fetchall()
        out = []
        for row in rows:
            d = dict(row)
            d["tags"] = json.loads(d.get("tags") or "[]")
            d["archived"] = bool(d.get("archived"))
            out.append(d)
        return out

    # ------------------------------------------------------------ snapshots
    def commit_snapshot(self, case_id: str, payload: dict, *, committed_at: str) -> int | None:
        """Append a new snapshot version. Returns the version, or None when the
        payload is identical to the current head (no-op commits)."""
        body = _canonical_json(payload)
        digest = _sha256(body)
        with self._conn:
            head = self._conn.execute(
                "SELECT version, sha256 FROM case_snapshots WHERE case_id = ? "
                "ORDER BY version DESC LIMIT 1", (case_id,)).fetchone()
            if head is not None and head["sha256"] == digest:
                return None
            version = 1 if head is None else int(head["version"]) + 1
            self._conn.execute(
                "INSERT INTO case_snapshots (case_id, version, committed_at, payload, sha256)"
                " VALUES (?, ?, ?, ?, ?)",
                (case_id, version, committed_at, body, digest))
            for ev in payload.get("audit_log", [])[-50:]:
                self._conn.execute(
                    "INSERT INTO audit_records (case_id, action, ref, at) VALUES (?,?,?,?)",
                    (case_id, str(ev.get("action", "")), str(ev.get("ref", "")), committed_at))
            return version

    def latest_snapshot(self, case_id: str) -> dict | None:
        row = self._conn.execute(
            "SELECT version, committed_at, payload, sha256 FROM case_snapshots"
            " WHERE case_id = ? ORDER BY version DESC LIMIT 1", (case_id,)).fetchone()
        if row is None:
            return None
        payload = json.loads(row["payload"])
        return {"version": row["version"], "committed_at": row["committed_at"],
                "sha256": row["sha256"], "payload": payload}

    def snapshot_history(self, case_id: str) -> list[dict]:
        rows = self._conn.execute(
            "SELECT version, committed_at, sha256 FROM case_snapshots"
            " WHERE case_id = ? ORDER BY version ASC", (case_id,)).fetchall()
        return [dict(r) for r in rows]

    def snapshot_at(self, case_id: str, version: int) -> dict | None:
        row = self._conn.execute(
            "SELECT version, committed_at, payload, sha256 FROM case_snapshots"
            " WHERE case_id = ? AND version = ?", (case_id, version)).fetchone()
        if row is None:
            return None
        return {"version": row["version"], "committed_at": row["committed_at"],
                "sha256": row["sha256"], "payload": json.loads(row["payload"])}

    # --------------------------------------------------------------- audit
    def audit_events(self, case_id: str, *, limit: int = 200) -> list[dict]:
        rows = self._conn.execute(
            "SELECT case_id, action, ref, at FROM audit_records"
            " WHERE case_id = ? ORDER BY id DESC LIMIT ?", (case_id, limit)).fetchall()
        return [dict(r) for r in reversed(rows)]
