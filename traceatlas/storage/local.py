"""Local filesystem storage backend (the only implemented backend)."""

from __future__ import annotations

from pathlib import Path

from traceatlas.storage.interface import StorageBackend


class LocalStorage(StorageBackend):
    def __init__(self, root: Path | str = ".traceatlas-storage") -> None:
        self.root = Path(root)

    def _path(self, key: str) -> Path:
        # Prevent path traversal via keys.
        safe = Path(key)
        if safe.is_absolute() or ".." in safe.parts:
            raise ValueError(f"invalid storage key: {key!r}")
        return self.root / safe

    def put_bytes(self, key: str, data: bytes) -> None:
        p = self._path(key)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)

    def get_bytes(self, key: str) -> bytes:
        return self._path(key).read_bytes()

    def exists(self, key: str) -> bool:
        return self._path(key).is_file()
