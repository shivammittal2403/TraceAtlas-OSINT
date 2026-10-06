"""Deterministic query-family generator (§6, §7, §24).

Given a normalized TargetProfile (names, aliases, domains, people, IPs...) and
the investigation questions, emit scored QuerySpecs per family. This is the
baseline intelligence: AI may PROPOSE extra queries later (§27), but every
query — AI-generated or not — passes through validator + safety policy before
execution. No combinatorial garbage: each template has an explicit purpose.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from traceatlas.search_discovery.query import DateRange, PlannedQuery, QuerySpec

_SAFE_TOKEN = re.compile(r"^[A-Za-z0-9 .&,'_@#/\-+()]+$")


def _safe(term: str) -> bool:
    return bool(_SAFE_TOKEN.match(term)) and 1 <= len(term) <= 120


@dataclass
class TargetProfile:
    """Everything lawfully known about the target at planning time (§2)."""
    primary_name: str = ""
    aliases: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    subdomains: list[str] = field(default_factory=list)
    ips: list[str] = field(default_factory=list)
    asns: list[str] = field(default_factory=list)
    people: list[str] = field(default_factory=list)
    usernames: list[str] = field(default_factory=list)
    emails: list[str] = field(default_factory=list)
    products: list[str] = field(default_factory=list)
    locations: list[str] = field(default_factory=list)
    cves: list[str] = field(default_factory=list)
    hashes: list[str] = field(default_factory=list)      # file hashes (CTI IOC)
    repositories: list[str] = field(default_factory=list)
    related_orgs: list[str] = field(default_factory=list)

    @property
    def names(self) -> list[str]:
        out = ([self.primary_name] if self.primary_name else []) + list(self.aliases)
        return [n for n in dict.fromkeys(out) if _safe(n)]

    def to_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items()}


DEFAULT_DOC_TYPES = ["pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx",
                     "csv", "txt", "json", "xml"]


class QueryGenerator:
    """Builds the canonical family set (§6). Each emitted query carries its
    purpose so the matrix stays auditable."""

    def __init__(self, objective: str, questions: list[dict] | None = None):
        self.objective = objective
        self.questions = questions or []

    def _q(self, spec: QuerySpec, family: str, purpose: str, value: float,
            tags: list[str] | None = None, wave: int = 0) -> PlannedQuery:
        spec.objective = self.objective
        qid = f"{family.lower()}-{abs(hash(spec.signature())) % 10**8}"
        return PlannedQuery(query_id=qid, spec=spec, family=family,
                            purpose=purpose, expected_value=value, wave=wave,
                            tags=tags or [])

    def generate(self, tp: TargetProfile) -> list[PlannedQuery]:
        qs: list[PlannedQuery] = []
        add = qs.append

        # ---- GENERAL DISCOVERY ---------------------------------------------
        for name in tp.names[:5]:
            add(self._q(QuerySpec(exact_terms=[name], priority=0.9),
                        "EXACT_MATCH", f"baseline discovery for '{name}'", 0.85,
                        ["discovery"]))
        if tp.names:
            add(self._q(QuerySpec(terms=[tp.names[0]],
                                  excluded_terms=["jobs", "careers"],
                                  priority=0.6),
                        "EXCLUSIONS", "reduce career-page noise on primary name",
                        0.5, ["discovery"]))
        for alt in tp.aliases[1:4]:
            add(self._q(QuerySpec(exact_terms=[alt]),
                        "EXACT_MATCH", f"alias/transliteration coverage '{alt}'",
                        0.55, ["discovery"]))

        # ---- SITE / DOMAIN --------------------------------------------------
        for dom in tp.domains[:3]:
            add(self._q(QuerySpec(site=dom), "SITE",
                        f"index coverage of {dom}", 0.7, ["site"]))
            add(self._q(QuerySpec(terms=tp.names[:1], site=dom), "DOMAIN",
                        f"target mentions within {dom}", 0.6, ["site"]))
            add(self._q(QuerySpec(site=dom, url_terms=["blog", "news", "press"]),
                        "URL", f"newsroom/blog pages on {dom}", 0.5, ["site"]))

        # ---- DOCUMENT -------------------------------------------------------
        for dom in tp.domains[:2]:
            add(self._q(QuerySpec(site=dom, filetypes=["pdf"]), "DOCUMENT",
                        f"PDF documents hosted on {dom}", 0.65, ["document"]))
        for name in tp.names[:2]:
            add(self._q(QuerySpec(terms=[name], filetypes=["pdf", "doc", "xls"]),
                        "FILETYPE", f"public documents referencing '{name}'",
                        0.6, ["document"]))

        # ---- CORPORATE ------------------------------------------------------
        for name in tp.names[:2]:
            for ctx in ("annual report", "registration", "subsidiary",
                        "director officer"):
                add(self._q(QuerySpec(terms=[name, ctx]), "ORGANIZATION",
                            f"corporate context: {name} + {ctx}", 0.55,
                            ["corporate"]))

        # ---- PERSON ---------------------------------------------------------
        for person in tp.people[:5]:
            add(self._q(QuerySpec(exact_terms=[person],
                                  terms=tp.domains[:1]), "PERSON",
                        f"{person} affiliation with known domain", 0.6,
                        ["person"]))
            add(self._q(QuerySpec(terms=[person, "role OR title OR director"],
                                  excluded_terms=["linkedin.com/in"]), "PERSON",
                        f"{person} public professional references", 0.45,
                        ["person"]))

        # ---- USERNAME / SOCIAL ---------------------------------------------
        for uname in tp.usernames[:5]:
            add(self._q(QuerySpec(terms=[f'"{uname}"'],
                                  site="github.com"), "USERNAME",
                        f"username '{uname}' public code footprint", 0.6,
                        ["social", "code"]))
            add(self._q(QuerySpec(body_terms=[uname],
                                  url_terms=["t.me"]), "SOCIAL",
                        f"public Telegram references to '{uname}'", 0.5,
                        ["social", "telegram"]))

        # ---- EMAIL CONTEXT --------------------------------------------------
        for email in tp.emails[:3]:
            local, _, dom = email.partition("@")
            add(self._q(QuerySpec(terms=[f'"{email}"']), "PUBLIC_EMAIL_CONTEXT",
                        f"public appearances of known address {email}", 0.6,
                        ["email"]))
            add(self._q(QuerySpec(site=dom, body_terms=["privacy OR contact"]),
                        "PUBLIC_EMAIL_CONTEXT",
                        f"published contact addresses on {dom}", 0.4,
                        ["email"]))

        # ---- INFRASTRUCTURE -------------------------------------------------
        for ip in tp.ips[:5]:
            add(self._q(QuerySpec(terms=[ip]), "INFRASTRUCTURE",
                        f"public references to IP {ip}", 0.6, ["infra"]))
        for asn in tp.asns[:3]:
            add(self._q(QuerySpec(terms=[asn, "announced OR prefix"]),
                        "INFRASTRUCTURE", f"ASN {asn} announcement context",
                        0.45, ["infra"]))
        for dom in tp.subdomains[:5]:
            add(self._q(QuerySpec(terms=[dom]), "INFRASTRUCTURE",
                        f"subdomain exposure {dom}", 0.55, ["infra"]))

        # ---- CODE / GITHUB / PACKAGE ----------------------------------------
        for name in tp.names[:2]:
            slug = re.sub(r"[^a-z0-9]", "", name.lower())
            add(self._q(QuerySpec(site="github.com", terms=[name]), "GITHUB",
                        f"GitHub references to '{name}'", 0.7, ["code"]))
            add(self._q(QuerySpec(site="github.com", url_terms=[f"/{slug}"]),
                        "CODE", f"candidate repos/orgs matching slug '{slug}'",
                        0.55, ["code"]))
        for pkg in tp.products[:5]:
            add(self._q(QuerySpec(site="pypi.org", terms=[pkg]), "PACKAGE",
                        f"package registry presence of '{pkg}'", 0.5,
                        ["code", "supply-chain"]))

        # ---- CTI / VULNERABILITY --------------------------------------------
        for ioc in (tp.hashes[:3] + tp.ips[:3]):
            add(self._q(QuerySpec(terms=[ioc],
                                  required_source_type="web"), "CTI",
                        f"threat-intel public reporting on IOC {ioc}", 0.65,
                        ["cti"]))
        for cve in tp.cves[:5]:
            add(self._q(QuerySpec(terms=[cve, tp.names[0] if tp.names else ""]),
                        "VULNERABILITY", f"{cve} relation to target", 0.6,
                        ["cti"]))

        # ---- ARCHIVE ----------------------------------------------------------
        for dom in tp.domains[:2]:
            add(self._q(QuerySpec(required_source_type="archive",
                                  url_terms=[dom]), "ARCHIVE",
                        f"historical content for {dom} (Wayback/CC)", 0.6,
                        ["archive"]))

        # ---- NEWS / ACADEMIC / GOV / PROCUREMENT / LEGAL ---------------------
        for name in tp.names[:2]:
            add(self._q(QuerySpec(terms=[name, "acquired OR merger OR lawsuit"],
                                  required_source_type="news"), "NEWS",
                        f"major events involving {name}", 0.55, ["news"]))
            add(self._q(QuerySpec(terms=[name, "study OR research"],
                                  required_source_type="academic"), "ACADEMIC",
                        f"academic work referencing {name}", 0.35, ["academic"]))
            add(self._q(QuerySpec(terms=[name, "tender OR procurement OR contract"],
                                  site="gov"), "PROCUREMENT",
                        f"public procurement involving {name}", 0.5,
                        ["government", "procurement"]))
            add(self._q(QuerySpec(terms=[name, "court OR ruling OR filing"]),
                        "LEGAL", f"public legal records mentioning {name}",
                        0.45, ["legal"]))

        # ---- LOCATION ---------------------------------------------------------
        for loc in tp.locations[:3]:
            add(self._q(QuerySpec(terms=[tp.names[0] if tp.names else "", loc,
                                          "address OR office OR location"]),
                        "LOCATION", f"location context {loc}", 0.4, ["geo"]))

        # filter any accidental empty-term specs
        return [q for q in qs
                if q.spec.terms or q.spec.exact_terms or q.spec.site
                or q.spec.url_terms or q.spec.body_terms]
