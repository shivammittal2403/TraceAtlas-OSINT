"""Transform: Domain → Certificates (crt.sh Certificate Transparency)."""

from __future__ import annotations

from traceatlas.core.enums import RelationshipType
from traceatlas.evidence.capture import EvidenceCapture
from traceatlas.sources.connectors.base import ConnectorRequest
from traceatlas.sources.connectors.ct_logs import CertificateTransparencyConnector
from traceatlas.transforms.base import EntityDraft, RelationshipDraft, Transform, TransformInput, TransformResult
from traceatlas.transforms.common import capture_response, obs_from_dicts


class DomainToCertificateTransform(Transform):
    id = "transform.domain_to_certificate"
    name = "Domain to Certificates"
    input_kind = "domain"
    output_kinds = ("certificate",)
    connector_names = ("ct_sh",)

    def __init__(self, capture: EvidenceCapture | None = None,
                 connector: CertificateTransparencyConnector | None = None) -> None:
        self.capture = capture or EvidenceCapture()
        self.connector = connector or CertificateTransparencyConnector()

    def run(self, ti: TransformInput) -> TransformResult:
        res = self._result(ti, ok=False)
        domain = ti.value.lower().rstrip(".")
        res.entities.append(EntityDraft("domain", f"domain:{domain}", domain))
        resp = self.connector.fetch(ConnectorRequest(target=domain, query=f"ct {domain}"))
        captured = capture_response(self.capture, "ct.search_domain", ti, resp, "source.crtsh")
        if captured is not None:
            res.evidence_ids.append(captured.record.id)
        if not resp.ok:
            res.errors.append(resp.error)
            return res
        res.ok = True
        certs = self.connector.normalize(resp)
        limit = int(ti.options.get("max_certificates", 25))
        for cert in certs[:limit]:
            cert_key = f"hash:cert:{cert['id']}"
            res.entities.append(EntityDraft("document", cert_key,
                                            f"cert {cert['id']}",
                                            {"issuer": cert["issuer"],
                                             "not_before": cert["not_before"],
                                             "not_after": cert["not_after"]}))
            for san in cert["sans"]:
                san_domain = san.lstrip("*.")
                if not san_domain:
                    continue
                dkey = f"domain:{san_domain}"
                res.entities.append(EntityDraft("domain", dkey, san_domain, {"source": "ct_san"}))
                res.relationships.append(RelationshipDraft(
                    cert_key, RelationshipType.CERTIFICATE_FOR.value, dkey,
                    evidence_ids=res.evidence_ids,
                    valid_from=cert["not_before"], valid_to=cert["not_after"]))
        obs_dicts = self.connector.extract_observations(resp)[:limit * 20]
        res.observations.extend(
            obs_from_dicts(ti.case_id, captured.record.id if captured else "", obs_dicts))
        return res
