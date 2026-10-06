"""Transform: Domain → DNS records (A/AAAA/MX/NS/TXT)."""

from __future__ import annotations

from traceatlas.transforms.base import EntityDraft, RelationshipDraft, Transform, TransformInput, TransformResult
from traceatlas.transforms.common import capture_response, obs_from_dicts
from traceatlas.core.enums import RelationshipType
from traceatlas.evidence.capture import EvidenceCapture
from traceatlas.sources.connectors.base import ConnectorRequest
from traceatlas.sources.connectors.dns import DnsConnector

_RR_TO_ENTITY = {"A": "ip_address", "AAAA": "ip_address"}


class DomainToDnsTransform(Transform):
    id = "transform.domain_to_dns"
    name = "Domain to DNS"
    input_kind = "domain"
    output_kinds = ("dns_record", "ip_address")
    connector_names = ("dns",)

    def __init__(self, capture: EvidenceCapture | None = None, connector: DnsConnector | None = None) -> None:
        self.capture = capture or EvidenceCapture()
        self.connector = connector or DnsConnector()

    def run(self, ti: TransformInput) -> TransformResult:
        res = self._result(ti, ok=True)
        domain = ti.value.lower().rstrip(".")
        res.entities.append(EntityDraft("domain", f"domain:{domain}", domain))
        types = ti.options.get("types", ["A", "MX", "NS"])
        any_ok = False
        for rr in types:
            resp = self.connector.fetch(ConnectorRequest(target=domain, params={"type": rr},
                                                          query=f"dns {rr} {domain}"))
            captured = capture_response(self.capture, f"dns.{rr}", ti, resp, "source.dns")
            if captured is not None:
                res.evidence_ids.append(captured.record.id)
            if not resp.ok:
                res.errors.append(f"dns {rr}: {resp.error}")
                continue
            any_ok = True
            dicts = self.connector.extract_observations(resp)
            obs = obs_from_dicts(ti.case_id, captured.record.id if captured else "", dicts)
            res.observations.extend(obs)
            for o in obs:
                if rr in _RR_TO_ENTITY and o.obj:
                    key = f"ip_address:{o.obj}"
                    res.entities.append(EntityDraft("ip_address", key, o.obj,
                                                    {"rr_type": rr}))
                    res.relationships.append(RelationshipDraft(
                        f"domain:{domain}", RelationshipType.RESOLVES_TO.value, key,
                        observation_ids=[o.id], evidence_ids=[o.evidence_id]))
                elif rr == "NS" and o.obj:
                    key = f"domain:{o.obj}"
                    res.entities.append(EntityDraft("domain", key, o.obj, {"role": "nameserver"}))
                    res.relationships.append(RelationshipDraft(
                        f"domain:{domain}", RelationshipType.DELEGATED_TO.value, key,
                        observation_ids=[o.id], evidence_ids=[o.evidence_id]))
                elif rr == "MX" and o.obj:
                    key = f"domain:{o.obj}"
                    res.entities.append(EntityDraft("domain", key, o.obj, {"role": "mail_exchanger"}))
                    res.relationships.append(RelationshipDraft(
                        f"domain:{domain}", RelationshipType.HOSTS.value, key,
                        observation_ids=[o.id], evidence_ids=[o.evidence_id]))
        res.ok = any_ok
        return res
