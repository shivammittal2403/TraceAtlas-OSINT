"""Transform: IP → ASN / hosting provider / country."""

from __future__ import annotations

from traceatlas.core.enums import RelationshipType
from traceatlas.evidence.capture import EvidenceCapture
from traceatlas.sources.connectors.base import ConnectorRequest
from traceatlas.sources.connectors.ip import IpConnector
from traceatlas.transforms.base import EntityDraft, RelationshipDraft, Transform, TransformInput, TransformResult
from traceatlas.transforms.common import capture_response, obs_from_dicts


class IpToAsnTransform(Transform):
    id = "transform.ip_to_asn"
    name = "IP to ASN"
    input_kind = "ip"
    output_kinds = ("asn", "organization", "location")
    connector_names = ("ip",)

    def __init__(self, capture: EvidenceCapture | None = None,
                 connector: IpConnector | None = None) -> None:
        self.capture = capture or EvidenceCapture()
        self.connector = connector or IpConnector()

    def run(self, ti: TransformInput) -> TransformResult:
        res = self._result(ti, ok=False)
        ip = ti.value
        res.entities.append(EntityDraft("ip_address", f"ip_address:{ip}", ip))
        resp = self.connector.fetch(ConnectorRequest(target=ip, query=f"ip {ip}"))
        captured = capture_response(self.capture, "ip.asn", ti, resp, "source.ipinfo")
        if captured is not None:
            res.evidence_ids.append(captured.record.id)
        if not resp.ok:
            res.errors.append(resp.error)
            return res
        res.ok = True
        obs = obs_from_dicts(ti.case_id, captured.record.id if captured else "",
                             self.connector.extract_observations(resp))
        res.observations.extend(obs)
        for o in obs:
            if o.predicate == "ip.in_asn":
                asn_key = f"asn:{o.obj}"
                res.entities.append(EntityDraft("asn", asn_key, o.obj,
                                                {"provider": o.attributes.get("provider", "")}))
                res.relationships.append(RelationshipDraft(
                    f"ip_address:{ip}", RelationshipType.IN_ASN.value, asn_key,
                    observation_ids=[o.id], evidence_ids=[o.evidence_id]))
            elif o.predicate == "ip.hosted_by":
                org_key = f"organization:{o.obj.lower()}"
                res.entities.append(EntityDraft("organization", org_key, o.obj, {"role": "hosting"}))
                res.relationships.append(RelationshipDraft(
                    f"ip_address:{ip}", RelationshipType.HOSTED_BY.value, org_key,
                    observation_ids=[o.id], evidence_ids=[o.evidence_id]))
            elif o.predicate == "ip.located_in":
                loc_key = f"location:{o.obj}"
                res.entities.append(EntityDraft("location", loc_key, o.obj,
                                                {"loc": o.attributes.get("loc", "")}))
                res.relationships.append(RelationshipDraft(
                    f"ip_address:{ip}", RelationshipType.LOCATED_AT.value, loc_key,
                    observation_ids=[o.id], evidence_ids=[o.evidence_id]))
        return res
