"""Evidence object construction from raw bytes (in-memory, local store)."""

from __future__ import annotations

from traceatlas.core.enums import EvidenceTier
from traceatlas.core.evidence import EvidenceRecord
from traceatlas.evidence.hashing import sha256_hex


def build_evidence(case_id: str, data: bytes, *, tier: EvidenceTier = EvidenceTier.RAW,
                   media_type: str = "application/octet-stream", source_id: str = "",
                   url: str = "", derived_from: list[str] | None = None) -> EvidenceRecord:
    return EvidenceRecord(
        case_id=case_id,
        tier=tier,
        sha256=sha256_hex(data),
        media_type=media_type,
        size_bytes=len(data),
        storage_key=f"{case_id}/{sha256_hex(data)}",
        source_id=source_id,
        url=url,
        derived_from=list(derived_from or []),
    )
