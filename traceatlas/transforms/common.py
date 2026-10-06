"""Shared helpers for connector-backed transforms: capture + observation building."""

from __future__ import annotations

from traceatlas.core.observation import Observation
from traceatlas.evidence.capture import CaptureContext, CapturedEvidence, EvidenceCapture
from traceatlas.sources.connectors.base import ConnectorRequest, ConnectorResponse


def capture_response(capture: EvidenceCapture, ti_kind: str, ti: "object", resp: ConnectorResponse,
                     source_id: str) -> CapturedEvidence | None:
    """Store a successful connector response as RAW evidence with replay context."""
    if not resp.ok or not resp.body:
        return None
    ctx = CaptureContext(
        case_id=ti.case_id,  # type: ignore[attr-defined]
        investigation_id=getattr(ti, "investigation_id", ""),
        task_id=getattr(ti, "task_id", ""),
        source_id=source_id,
        connector_id=resp.headers.get("x-connector-id", "") or source_id,
        url=resp.redirect_chain[-1] if resp.redirect_chain else "",
        query=ti_kind,
        http_status=resp.status_code,
        http_headers=resp.headers,
        redirect_chain=resp.redirect_chain,
    )
    media = resp.headers.get("content-type", "application/octet-stream").split(";")[0]
    return capture.collect(ctx, resp.body, media_type=media)


def obs_from_dicts(case_id: str, evidence_id: str, items: list[dict]) -> list[Observation]:
    out: list[Observation] = []
    for it in items:
        out.append(Observation(
            case_id=case_id,
            evidence_id=evidence_id,
            predicate=str(it.get("predicate", "unknown")),
            subject=str(it.get("subject", "")),
            obj=str(it.get("obj", "")),
            attributes=dict(it.get("attributes", {})),
        ))
    return out
