"""Transform: Domain → RDAP registration facts."""

from __future__ import annotations

from traceatlas.core.enums import RelationshipType
from traceatlas.evidence.capture import EvidenceCapture
from traceatlas.sources.connectors.base import ConnectorRequest
from traceatlas.sources.connectors.rdap import RdapConnector
from traceatlas.transforms.base import EntityDraft, RelationshipDraft, Transform, TransformInput, TransformResult
from traceatlas.transforms.common import capture_response, obs_from_dicts


class DomainToRdapTransform(Transform):
    id = "transform.domain_to_rdap"
    name = "Domain to RDAP"
    input_kind = "domain"
    output_kinds = ("registration_event", "registrar", "nameserver")
    connector_names = ("rdap",)

    def __init__(self, capture: EvidenceCapture | None = None,
                 connector: RdapConnector | None = None) -> None:
        self.capture = capture or EvidenceCapture()
        self.connector = connector or RdapConnector()

    def run(self, ti: TransformInput) -> TransformResult:
        res = self._result(ti, ok=False)
        domain = ti.value.lower().rstrip(".")
        res.entities.append(EntityDraft("domain", f"domain:{domain}", domain))
        resp = self.connector.fetch(ConnectorRequest(target=domain, query=f"rdap {domain}"))
        captured = capture_response(self.capture, "rdap.domain", ti, resp, "source.rdap")
        if captured is not None:
            res.evidence_ids.append(captured.record.id)
        if not resp.ok:
            res.errors.append(resp.error)
            return res
        res.ok = True
        dicts = self.connector.extract_observations(resp)
        obs = obs_from_dicts(ti.case_id, captured.record.id if captured else "", dicts)
        res.observations.extend(obs)
        for o in obs:
            if o.predicate == "domain.registered_with":
                key = f"organization:{o.obj.lower()}"
                res.entities.append(EntityDraft("organization", key, o.obj, {"role": "registrar"}))
                res.relationships.append(RelationshipDraft(
                    f"domain:{domain}", RelationshipType.REGISTERED_BY.value, key,
                    observation_ids=[o.id], evidence_ids=[o.evidence_id]))
            elif o.predicate == "domain.has_event":
                res.relationships.append(RelationshipDraft(
                    f"domain:{domain}", RelationshipType.CONTAINS_OBSERVATION.value,
                    f"event:{domain}:{o.obj}",
                    observation_ids=[o.id], evidence_ids=[o.evidence_id],
                    valid_from=o.attributes.get("date")))
                res.entities.append(EntityDraft("event", f"event:{domain}:{o.obj}",
                                                f"{o.obj} {domain}",
                                                {"action": o.obj, "date": o.attributes.get("date", "")}))
        return res
