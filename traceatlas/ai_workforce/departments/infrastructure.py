"""Infrastructure department (§27 TEAM INFRA-01).

Concrete, executable team: a DepartmentManager plus specialist employees whose
skills are bound to REAL deterministic handlers over collected DNS/RDAP/cert/
IP data. No live network is performed here — collection results arrive as
typed inputs (from connectors or clearly-labelled fixtures) and the employees
transform them into observations + candidate facts with evidence references.
"""

from __future__ import annotations

import hashlib

from traceatlas.ai_workforce.employee import Employee, JobDescription, ModelPolicy
from traceatlas.ai_workforce.manager import DepartmentManager
from traceatlas.ai_workforce.result import CandidateFactPayload, EntityMention, RelationshipMention
from traceatlas.trust.case_memory import CaseMemory
from traceatlas.trust.model import SourceRecord


def _ev_id(domain: str, kind: str, value: str) -> str:
    h = hashlib.sha256(f"{kind}:{domain}:{value}".encode()).hexdigest()[:12]
    return f"ev_{kind}_{h}"


# ------------------------------------------------------------------ handlers
def dns_handler(inputs: dict) -> dict:
    """Deterministic DNS analysis over provided records (fixture or live)."""
    domain = inputs.get("domain", "")
    records = inputs.get("dns_records", [])   # [{"type":"A","value":"1.2.3.4"}, ...]
    if not domain or not isinstance(records, list):
        raise ValueError("dns handler needs 'domain' and 'dns_records'")
    observations, candidates, entities, rels, ev_ids, src_ids = [], [], [], [], [], []
    src = inputs.get("source_id", "")
    for rec in records:
        rtype, value = rec.get("type", ""), rec.get("value", "")
        if not rtype or not value:
            continue
        eid = _ev_id(domain, rtype.lower(), value)
        ev_ids.append(eid)
        observations.append({
            "statement": f"DNS {rtype} record for {domain} resolves to {value}",
            "evidence_ids": [eid], "source_ids": [src]})
        entities.append(EntityMention(kind="domain", value=domain))
        entities.append(EntityMention(kind=rtype.lower(), value=value))
        rels.append(RelationshipMention(source=domain, target=value,
                                        kind=f"resolves_to_{rtype.lower()}",
                                        evidence_id=eid))
        if rtype == "A":
            candidates.append(CandidateFactPayload(
                statement=f"{domain} currently resolves to IPv4 {value}",
                evidence_ids=[eid], source_ids=[src]))
    limitations = []
    if not records:
        limitations.append("no DNS records returned — this is NOT proof the domain "
                           "does not exist (coverage limitation)")
    return {"observations": observations, "candidate_facts": candidates,
            "entities": entities, "relationships": rels,
            "evidence_ids": ev_ids, "source_ids": [src] if src else [],
            "limitations": limitations,
            "unknowns": [] if records else ["domain may be new/unpublished; retry later"]}


def rdap_handler(inputs: dict) -> dict:
    """RDAP registration analysis: registrar, dates, status."""
    domain = inputs.get("domain", "")
    data = inputs.get("rdap", {})
    src = inputs.get("source_id", "")
    if not domain or not data:
        raise ValueError("rdap handler needs 'domain' and 'rdap' payload")
    out = []
    ents, rels, evs = [], [], []
    registrar = data.get("registrar", "")
    if registrar:
        eid = _ev_id(domain, "registrar", registrar)
        evs.append(eid)
        out.append({"statement": f"RDAP registry record shows registrar '{registrar}' for {domain}",
                    "evidence_ids": [eid], "source_ids": [src]})
        ents.append(EntityMention(kind="registrar", value=registrar))
        rels.append(RelationshipMention(source=domain, target=registrar,
                                        kind="registered_via", evidence_id=eid))
    created = data.get("created", "")
    if created:
        eid = _ev_id(domain, "created", created)
        evs.append(eid)
        out.append({"statement": f"{domain} registration created {created}",
                    "evidence_ids": [eid], "source_ids": [src]})
    facts = []
    if registrar:
        facts.append(CandidateFactPayload(
            statement=f"Registration authority recorded for {domain}: registrar {registrar}",
            evidence_ids=[_ev_id(domain, "registrar", registrar)], source_ids=[src]))
    return {"observations": out, "candidate_facts": facts, "entities": ents,
            "relationships": rels, "evidence_ids": evs,
            "source_ids": [src] if src else [],
            "bias_notes": ["registry data is primary but registrant identity is often "
                           "privacy-redacted; ownership cannot be inferred from this alone"],
            "limitations": ["redacted registrant fields limit attribution"]}


def cert_handler(inputs: dict) -> dict:
    """Certificate transparency log analysis."""
    domain = inputs.get("domain", "")
    certs = inputs.get("certificates", [])  # [{"san":[...],"issuer":...,"not_after":...}]
    src = inputs.get("source_id", "")
    obs, ents, rels, evs, facts = [], [], [], [], []
    for c in certs:
        san = c.get("san", [])
        issuer = c.get("issuer", "")
        key = ",".join(sorted(san))
        eid = _ev_id(domain, "cert", key)
        evs.append(eid)
        obs.append({"statement": f"Certificate issued by {issuer} covers SANs {san}",
                    "evidence_ids": [eid], "source_ids": [src]})
        if issuer:
            ents.append(EntityMention(kind="ca", value=issuer))
            rels.append(RelationshipMention(source=issuer, target=domain,
                                            kind="issued_cert_for", evidence_id=eid))
        related = [s for s in san if s != domain and not s.endswith("." + domain)]
        if related:
            facts.append(CandidateFactPayload(
                statement=f"{domain} certificate also names related domains {related}",
                evidence_ids=[eid], source_ids=[src]))
    return {"observations": obs, "candidate_facts": facts, "entities": ents,
            "relationships": rels, "evidence_ids": evs,
            "source_ids": [src] if src else [],
            "limitations": ["shared certificates may indicate common hosting provider, "
                            "NOT necessarily common control"]}


def ip_asn_handler(inputs: dict) -> dict:
    """IP → ASN / hosting context analysis."""
    ip = inputs.get("ip", "")
    asn = inputs.get("asn", {})
    src = inputs.get("source_id", "")
    if not ip:
        raise ValueError("ip handler needs 'ip'")
    obs, ents, rels, evs, facts = [], [], [], [], []
    number = asn.get("asn", "")
    org = asn.get("org", "")
    if number:
        eid = _ev_id(ip, "asn", str(number))
        evs.append(eid)
        obs.append({"statement": f"IP {ip} belongs to AS{number} ({org})",
                    "evidence_ids": [eid], "source_ids": [src]})
        ents.append(EntityMention(kind="asn", value=str(number)))
        rels.append(RelationshipMention(source=ip, target=str(number),
                                        kind="belongs_to_asn", evidence_id=eid))
        facts.append(CandidateFactPayload(
            statement=f"IP {ip} is allocated to AS{number} operated by {org}",
            evidence_ids=[eid], source_ids=[src]))
    return {"observations": obs, "candidate_facts": facts, "entities": ents,
            "relationships": rels, "evidence_ids": evs,
            "source_ids": [src] if src else [],
            "limitations": ["ASN membership indicates the network operator, not the "
                            "customer behind it (shared hosting caveat)"]}


# ------------------------------------------------------------------- factory
class InfrastructureManager(DepartmentManager):
    manager_id = "mgr_infrastructure"
    department = "infrastructure"


def build_infra_team(compliance=None) -> tuple[InfrastructureManager, dict[str, Employee]]:
    mgr = InfrastructureManager(compliance=compliance)
    jobs = {
        "DNS Analyst": (["DNS_analysis"], dns_handler),
        "RDAP Analyst": (["RDAP_analysis"], rdap_handler),
        "Certificate Analyst": (["certificate_analysis"], cert_handler),
        "IP Analyst": (["IP_analysis", "ASN_analysis"], ip_asn_handler),
    }
    built: dict[str, Employee] = {}
    for name, (skills, fn) in jobs.items():
        emp = Employee(
            name=name, role=name, department="infrastructure",
            job=JobDescription(
                role=name, mission=f"deterministic {name} analysis of collected records",
                responsibilities=["parse provided records", "emit grounded observations",
                                  "propose candidate facts with evidence ids",
                                  "never infer beyond evidence"],
                required_skills=skills,
                prohibited_actions=["active_exploit", "fabricate_evidence",
                                    "write_final_conclusions"],
                allowed_sources=["api", "registry", "dataset"]),
            skills=skills + ["evidence_capture"],
            model_policy=ModelPolicy(provider="deterministic"),
            cost_per_call=0.1,
        )
        for s in skills:
            emp.register_handler(s, fn)
        mgr.add_employee(emp)
        built[name] = emp
    return mgr, built


def seed_case_memory(memory: CaseMemory, *, sources: list[SourceRecord],
                     evidence: list[tuple[str, str, str]]) -> None:
    """Register sources + raw evidence so employee-cited ids resolve in the gate.

    evidence tuples: (evidence_id, source_id, description)
    """
    existing = set()
    for src in sources:
        memory.add_source(src)
    for eid, sid, desc in evidence:
        if eid in memory.evidence or eid in existing:
            continue
        rec = memory.evidence.get(eid)
        if rec is None:
            from traceatlas.trust.model import EvidenceRecord
            rec = EvidenceRecord(id=eid, description=desc, source_id=sid,
                                 artifact_hash=hashlib.sha256(desc.encode()).hexdigest()[:16])
            memory.add_evidence(rec)
        existing.add(eid)
