"""Content-addressed local evidence store.

Blobs are stored under .traceatlas-evidence/<case>/<sha256>. Integrity is
verified on read. This is a development-grade store; S3/MinIO backends are
planned (storage/) and not implemented.
"""

from __future__ import annotations

from pathlib import Path

from traceatlas.exceptions import EvidenceError
from traceatlas.evidence.hashing import sha256_hex
from traceatlas.evidence.object import build_evidence  # noqa: F401 (re-export helper)

_ROOT = Path(".traceatlas-evidence")


class EvidenceStore:
    def __init__(self, root: Path | str = _ROOT) -> None:
        self.root = Path(root)

    def put(self, case_id: str, data: bytes) -> str:
        digest = sha256_hex(data)
        path = self.root / case_id / digest
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_bytes(data)
        tmp.replace(path)
        return digest

    def get(self, case_id: str, digest: str) -> bytes:
        path = self.root / case_id / digest
        if not path.is_file():
            raise EvidenceError(f"evidence blob missing: {digest}")
        data = path.read_bytes()
        if sha256_hex(data) != digest:
            raise EvidenceError(f"integrity check failed for {digest}")
        return data

    def exists(self, case_id: str, digest: str) -> bool:
        return (self.root / case_id / digest).is_file()
