#!/usr/bin/env python3
"""Generate the intelligence subsystem scaffold for TraceAtlas.

Creates every file listed in the intelligence manifest with honest STUB
markers, following the repository convention (a docstring reading
'STUB - <area>: planned, not implemented.' plus a gap-register comment).

CREATED != IMPLEMENTED. No file produced here contains domain logic,
source access, tests or acceptance evidence.
"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

STUB_PY = '''"""STUB — {label}: planned, not implemented."""

# Intentionally unimplemented; see .ai/CURRENT_STATE.md and docs/program/MASTER_GAP_REGISTER.md.
# CREATED != IMPLEMENTED. This file reserves a location only; it contains no
# domain logic, source access, evidence rules or acceptance validation.
'''

STUB_ROUTE = '''"""STUB - API route group "{name}": planned, not implemented.

This module intentionally defines no router so it cannot be silently mounted.
"""
'''

STUB_TSX = '''// STUB — {label}: planned, not implemented.
// Intentionally unimplemented; see .ai/CURRENT_STATE.md and docs/program/MASTER_GAP_REGISTER.md.
// CREATED != IMPLEMENTED. This component reserves a location only; it renders nothing
// and must not be imported into working pages until domain logic, evidence rules and
// acceptance validation exist.
'''

STUB_MD = '''# {title}

**Status: PLANNED — this document is a placeholder. CREATED != IMPLEMENTED.**

Intended responsibility: {purpose}

No content in this area has been written yet. Before this document can be
delivered it must reflect implemented behavior verified by tests and
acceptance gates (see `docs/INTELLIGENCE_ACCEPTANCE_GATES.md`).

See `.ai/CURRENT_STATE.md` and `docs/program/MASTER_GAP_REGISTER.md` for the
authoritative gap register.
'''


def stub_py(rel: str) -> str:
    label = rel.removesuffix(".py").replace("/", ".").replace("traceatlas.", "traceatlas/")
    return STUB_PY.format(label=label)


MODULES = [
    # (family, name, purpose)
    ("company", "company", "Company registry lookup and verification"),
    ("company", "ownership", "Beneficial-ownership chain analysis"),
    ("company", "procurement", "Procurement and tender record analysis"),
    ("company", "trade", "Trade-flow and customs record analysis"),
    ("company", "address", "Registered-address correlation"),
    ("company", "legal", "Court and legal-record review"),
    ("company", "sanctions", "Sanctions and watchlist screening"),
    ("company", "finance", "Documented financial-statement analysis"),
    ("cyber", "ioc", "Indicator-of-compromise collection and triage"),
    ("cyber", "vulnerability", "Vulnerability advisory correlation"),
    ("cyber", "threat_actor", "Threat-actor profile assessment"),
    ("cyber", "campaign", "Campaign attribution evidence review"),
    ("cyber", "malware", "Malware sample and family analysis"),
    ("cyber", "package", "Package-registry (typosquat) analysis"),
    ("cyber", "repository", "Source-repository provenance analysis"),
    ("cyber", "supply_chain", "Supply-chain dependency risk review"),
    ("cyber", "incident", "Incident record reconstruction"),
    ("cyber", "log", "Authorized log evidence processing"),
    ("web", "web", "Public website observation processing"),
    ("web", "search", "Permitted search-engine collection"),
    ("web", "dork", "Structured search-operator query construction"),
    ("osint", "username", "Cross-platform username availability checks"),
    ("osint", "archive", "Web-archive historical snapshot review"),
    ("osint", "news", "News-feed and article monitoring"),
    ("osint", "academic", "Academic publication and author records"),
    ("osint", "dataset", "Open-dataset discovery and licensing review"),
    ("geo", "geo", "Geospatial context resolution"),
    ("geo", "map", "Map-provider observation processing"),
    ("geo", "satellite", "Satellite-imagery review"),
    ("geo", "transport", "Transport-route and tracking evidence"),
    ("geo", "event", "Observed-event timeline correlation"),
    ("person", "email", "Email identifier analysis (authorized scope)"),
    ("person", "phone", "Phone-number identifier analysis"),
    ("person", "social", "Public social-profile evidence review"),
    ("person", "messenger", "Authorized messenger record analysis"),
    ("person", "interview", "Interview/testimony record handling"),
    ("infra", "domain", "Domain registration (RDAP) analysis"),
    ("infra", "dns", "Scoped DNS record collection"),
    ("infra", "certificate", "Certificate-transparency observation"),
    ("infra", "ip", "IP address allocation and geolocation context"),
    ("infra", "asn", "Autonomous-system relationship analysis"),
    ("infra", "bgp", "BGP routing observation review"),
    ("infra", "network", "Network-range context assembly"),
    ("infra", "cloud", "Cloud-hosting fingerprint analysis"),
    ("media", "document", "Document parsing and extraction routing"),
    ("media", "metadata", "File-metadata provenance review"),
    ("media", "image", "Image similarity and EXIF analysis"),
    ("media", "video", "Video frame and content review"),
    ("media", "audio", "Audio transcription handling"),
    ("media", "disinformation", "Disinformation pattern assessment"),
    ("device", "app", "Application store listing analysis"),
    ("device", "mobile", "Authorized device record processing"),
    ("device", "iot", "IoT exposure observation review"),
    ("device", "ot", "OT/ICS environment context"),
    ("fraud", "fraud", "Fraud-scheme pattern analysis"),
    ("fraud", "payment", "Payment-rail transaction evidence review"),
    ("fraud", "crypto", "Cryptocurrency ledger tracing support"),
    ("brand", "brand", "Brand-impersonation evidence analysis"),
    ("brand", "ad", "Advertising-placement evidence review"),
    ("brand", "marketplace", "Marketplace listing evidence analysis"),
    ("brand", "job", "Job-posting legitimacy review"),
    ("brand", "complaint", "Complaint-record aggregation"),
    ("brand", "exposure", "Credential/exposure record handling"),
    ("darkweb", "darkweb", "Licensed dark-web provider evidence handling"),
]

FAMILIES = sorted({fam for fam, _, _ in MODULES})

CORE_FILES = [
    "traceatlas/intelligence/__init__.py",
    "traceatlas/intelligence/registry.py",
    "traceatlas/intelligence/router.py",
    "traceatlas/intelligence/planner.py",
    "traceatlas/intelligence/sequence.py",
    "traceatlas/intelligence/permissions.py",
    "traceatlas/intelligence/source_readiness.py",
    "traceatlas/intelligence/fact_gate.py",
    "traceatlas/intelligence/hypothesis_gate.py",
    "traceatlas/intelligence/graph_bridge.py",
    "traceatlas/intelligence/memory_bridge.py",
    "traceatlas/intelligence/reporting.py",
    "traceatlas/intelligence/playbooks.py",
    "traceatlas/intelligence/manager_tree.py",
    "traceatlas/intelligence/skills.py",
    "traceatlas/intelligence/next_action.py",
]

DARKWEB_FILES = [
    "traceatlas/intelligence/modules/darkweb/limitations.py",
    "traceatlas/intelligence/modules/darkweb/report.py",
]

API_ROUTE_FILES = [
    "traceatlas/api/routes/intelligence.py",
    "traceatlas/api/routes/intelligence_modules.py",
    "traceatlas/api/routes/intelligence_runs.py",
    "traceatlas/api/routes/intelligence_sequences.py",
    "traceatlas/api/routes/intelligence_playbooks.py",
    "traceatlas/api/routes/intelligence_reviews.py",
]

WEB_FILES = [
    "web/app/intelligence/page.tsx",
    "web/app/intelligence/[module]/page.tsx",
    "web/app/investigations/[id]/intelligence/page.tsx",
    "web/components/intelligence/IntelligenceModuleGrid.tsx",
    "web/components/intelligence/IntelligenceModuleCard.tsx",
    "web/components/intelligence/IntelligenceRunPanel.tsx",
    "web/components/intelligence/SequenceQueue.tsx",
    "web/components/intelligence/SourceReadiness.tsx",
    "web/components/intelligence/EvidenceReview.tsx",
    "web/components/intelligence/ModuleResult.tsx",
    "web/components/intelligence/ModuleStatus.tsx",
    "web/components/intelligence/ManagerTree.tsx",
    "web/components/intelligence/SkillBadges.tsx",
    "web/components/intelligence/NextActionPanel.tsx",
]

DOC_FILES = {
    "docs/INTELLIGENCE_MODULES.md": "Catalog of all intelligence modules: responsibilities, inputs, outputs, source requirements and status.",
    "docs/INTELLIGENCE_HIERARCHY.md": "Manager/subordinate structure: how the lead investigator routes work to module families and specialists.",
    "docs/INTELLIGENCE_SOURCE_BOUNDARIES.md": "Which sources are public, licensed or configured; entitlements, egress rules and coverage gaps.",
    "docs/INTELLIGENCE_PLAYBOOKS.md": "Question-led module sequences (investment scam, domain investigation) and their gates.",
    "docs/INTELLIGENCE_ACCEPTANCE_GATES.md": "Measurable gates each module must pass before being marked IMPLEMENTED.",
    "docs/INTELLIGENCE_FILE_MAP.md": "Map of every intelligence file, its responsibility and milestone status.",
}

TEST_FILES = [
    "tests/intelligence/test_registry.py",
    "tests/intelligence/test_router.py",
    "tests/intelligence/test_planner.py",
    "tests/intelligence/test_sequence.py",
    "tests/intelligence/test_permissions.py",
    "tests/intelligence/test_source_readiness.py",
    "tests/intelligence/test_fact_gate.py",
    "tests/intelligence/test_hypothesis_gate.py",
    "tests/intelligence/test_graph_bridge.py",
    "tests/intelligence/test_memory_bridge.py",
    "tests/intelligence/test_reporting.py",
] + [f"tests/intelligence/modules/test_{name}.py" for _, name, _ in MODULES]

MANIFEST_PATH = "docs/intelligence_file_manifest.json"


def write(path: Path, text: str, created: list, skipped: list) -> None:
    if path.exists():
        skipped.append(str(path.relative_to(ROOT)))
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    created.append(str(path.relative_to(ROOT)))


def main() -> None:
    created: list[str] = []
    skipped: list[str] = []

    # Package markers first (real, minimal markers so imports remain possible).
    for pkg in (
        ["traceatlas/intelligence/modules"]
        + [f"traceatlas/intelligence/modules/{f}" for f in FAMILIES]
        + ["tests/intelligence", "tests/intelligence/modules"]
    ):
        p = ROOT / pkg / "__init__.py"
        if not p.exists():
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text("", encoding="utf-8")
            created.append(str(p.relative_to(ROOT)))

    def add(rel: str, text: str) -> None:
        write(ROOT / rel, text, created, skipped)

    for rel in CORE_FILES:
        if rel.endswith("__init__.py"):
            add(rel, '"""TraceAtlas intelligence package (scaffold)."""\n')
        else:
            add(rel, stub_py(rel))

    for rel in DARKWEB_FILES:
        add(rel, stub_py(rel))

    # One stub implementation module per catalogued intelligence module.
    for fam, name, _purpose in MODULES:
        add(f"traceatlas/intelligence/modules/{fam}/{name}.py",
            stub_py(f"traceatlas/intelligence/modules/{fam}/{name}.py"))

    for rel in API_ROUTE_FILES:
        name = Path(rel).stem
        add(rel, STUB_ROUTE.format(name=name))

    for rel in WEB_FILES:
        label = rel.replace("web/", "").removesuffix(".tsx")
        add(rel, STUB_TSX.format(label=f"web/{label}"))

    for rel, purpose in DOC_FILES.items():
        title = Path(rel).stem.replace("_", " ").title()
        add(rel, STUB_MD.format(title=title, purpose=purpose))

    for rel in TEST_FILES:
        add(rel, stub_py(rel))

    manifest = {
        "generated_by": "scripts/generate_intelligence_scaffold.py",
        "status": "SCAFFOLD — files created, none implemented",
        "implementation_rule": (
            "CREATED != IMPLEMENTED. Each module requires domain logic, tests, "
            "source readiness, evidence rules and acceptance validation."
        ),
        "core": CORE_FILES + DARKWEB_FILES,
        "api_routes": API_ROUTE_FILES,
        "web": WEB_FILES,
        "docs": sorted(DOC_FILES),
        "modules": [
            {"family": fam, "name": name, "package": f"traceatlas/intelligence/modules/{fam}",
             "implementation": f"traceatlas/intelligence/modules/{fam}/{name}.py",
             "test": f"tests/intelligence/modules/test_{name}.py",
             "purpose": purpose}
            for fam, name, purpose in MODULES
        ],
        "tests": TEST_FILES,
    }
    # Write manifest deterministically (regenerate every run).
    p = ROOT / MANIFEST_PATH
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    print(json.dumps({
        "created": len(created),
        "skipped_existing": len(skipped),
        "manifest": MANIFEST_PATH,
        "modules_planned": len(MODULES),
    }, indent=2))


if __name__ == "__main__":
    main()
