# TRACEATLAS: COMPLETE PORTABLE CONVERSATION & GRAPH MEMORY

**Snapshot:** 2026-10-09  |  **Scope:** TraceAtlas/OSINT project only  |  **Artifact:** memory/handover, not a code audit

> **Coverage warning:** This is a consolidated structured memory from available chat content, context summaries, and three prior Library artifacts. It is not a verbatim export of all earlier chats. Missing messages are never invented. Current GitHub HEAD, tests, sources, pushes and deployments were not inspected or verified for this export.

## 1. Project identity and ambition
- **Primary repo reported:** `https://github.com/shivammittal2403/TraceAtlas-OSINT`
- **Earlier repo:** `https://github.com/shivammittal2403/TraceAtlas-Automator`
- **Historical baseline, 30 Sep 2026:** `2a8789eb7cc401b327796e32458b9733674ecbc9` (not necessarily current).
- Build an evidence-first, objective-driven, enterprise-grade autonomous **investigation** platform, not an unsupervised external-action/attack agent.
- Comparison aspirations: Maltego, Social Links/SL Crimewall, SpiderFoot HX, Recon-ng, Recorded Future, Palantir Gotham, Flashpoint, DarkOwl, ShadowDragon, Fivecast ONYX, Siren, IBM i2 Analyst’s Notebook, Cellebrite Pathfinder, Shodan, Censys, Chainalysis Reactor, Elliptic Investigator. Not verified parity.
- Architecture preference: existing code first, working integrations and tests, minimal file sprawl; do not erase core functions.

## 2. What the user expects next chat to remember
- One entry: TARGET + OBJECTIVE + EXPLICIT AUTHORIZED SCOPE. AI interprets objective, but cannot expand permission.
- Hierarchy: Chief Intelligence AI Manager → Department/Team Lead → specialist AI Employee Engines → skills (e.g., SKILL.md manifest) → trusted deterministic executors and governed connectors.
- Managers delegate/coordinate; specialist engines perform tasks; skill metadata != Python implementation; never create one pointless file per idea.
- All material findings must be traceable to immutable evidence, observations, source pedigree, valid time, facts, hypotheses and verification.
- Always distinguish fact/observation/inference/insight/hypothesis/speculation/unknown; model agreement is not independent corroboration.
- Graph must support temporal relationship eras, reversible entity merges, claim corrections, contradictions, source independence, human review, replay.
- LOCAL_ONLY/Ollama as a real, tested option; hybrid/cloud only behind approved redaction and routing.
- Autonomy limited to lawful authorized research and analysis. No private access, credential use, intrusion, illicit acquisition, deception or consequential autonomous actions.
- Broad intelligence taxonomy is long-term product design; implementation status requires live code/source tests, not prompt or registry existence.
- JARVIS should surface who is working, facts, hypotheses, skeptic disagreement, source independence, missing evidence, next action and boundaries.

## 3. Canonical end-to-end intelligence workflow

```text
TARGET + OBJECTIVE + AUTHORIZED SCOPE  →
    Objective Understanding  →
Target Resolution  →
    Authorization Check  →
Questions / PIR / SIR / EEI  →
    Knowledge State  →
Gaps  →
    Discipline Selection  →
Capability/Skill Planning  →
    Source Planning  →
Transform/Tool Planning  →
    Worker Planning  →
Collection Waves  →
    Governed Collection  →
Raw Evidence  →
    Normalization  →
Observations  →
    Entity Resolution  →
Relationships  →
    Temporal Graph  →
Timeline / Map / Media  →
    Claims and Hypotheses  →
Source Independence  →
    Contradiction Search  →
Adversarial Verification  →
    Knowledge Update  →
Next Best Action  →
    Bounded Iteration  →
Stop with Reason  →
    Human Review Where Required  →
Evidence-linked Report  →
    Replay / Audit
```

## 4. Workforce, skill packs, engines

```text
Chief Intelligence AI Manager
    ↓
Domain/Department Intelligence Manager
    ↓
Specialist Team Lead/Manager
    ↓
AI Employee Engine / skill packs
    ↓
Governed tool/transform/connector workers
    ↓
Evidence/Fact Gate
    ↓
Verification/Quality Supervisor
    ↓
Final Manager + JARVIS synthesis
```

**Design rule:** `skills/*.md` or `SKILL.md` may define purpose, inputs/outputs, permissions, policies, source requirements and examples. Python/TS contains executable engines/adapters. These are complementary, not mutually exclusive. Reuse shared engine/registry; do not create empty file sprawl.

## 5. Evidence, identity, temporal truth model

**Evidence ladder:** Raw Source → EvidenceObject → Observation → Entity/Relationship/Event → Claim → Fact Gate → Insight / Inference → Hypothesis → Competing Hypotheses → Contradiction / Falsification → VerificationResult → ReportStatement

**Claim states:** SUPPORTED, PARTIALLY_SUPPORTED, DISPUTED, INCONCLUSIVE, UNSUPPORTED

**Independent source states:** INDEPENDENT, PARTIALLY_DEPENDENT, DEPENDENT, UNKNOWN

**Knowledge states:** KNOWN, SUPPORTED, PARTIAL, DISPUTED, UNKNOWN, MISSING_EVIDENCE, UNRESOLVED_ENTITY, UNRESOLVED_RELATIONSHIP, STALE_EVIDENCE, UNSEARCHED_RELEVANT_SOURCE

**Stop reasons:** OBJECTIVE_SATISFIED, SUFFICIENT_VERIFICATION, SOURCES_EXHAUSTED, LOW_EXPECTED_INFORMATION_VALUE, BUDGET_EXHAUSTED, TIME_EXHAUSTED, AUTHORIZATION_BOUNDARY, RATE_LIMIT_BOUNDARY, POLICY_BLOCK, HUMAN_REVIEW_REQUIRED, CANCELLED, SYSTEM_FAILURE

**Never collapse these distinctions:**
- `EVIDENCE != FACT`
- `INFERENCE != EVIDENCE`
- `AI_AGREEMENT != INDEPENDENT_CORROBORATION`
- `IDENTICAL_NAME != SAME_PERSON_OR_ORGANIZATION`
- `SHARED_IP != SAME_OPERATOR`
- `SHARED_ADDRESS != COMMON_OWNERSHIP`
- `DOMAIN != ORGANIZATION`
- `EMAIL_DOMAIN_IN_LEAK != COMPANY_BREACH`
- `EXPOSED_SECRET != VALID_SECRET`
- `OPEN_PORT != VULNERABILITY`
- `CVE != EXPLOITED_ASSET`
- `VENDOR_BREACH != CUSTOMER_BREACH`
- `INVOICE != PAYMENT`
- `SHIPMENT != PAYMENT`
- `TRADE_ANOMALY != SMUGGLING`
- `TRANSACTION_ANOMALY != FINANCIAL_CRIME`
- `VICTIM_COMPLAINT != VERIFIED_FRAUD`
- `HUMAN_SOURCE_CONFIDENCE != CLAIM_ACCURACY`
- `ORG_CHART != ACTUAL_AUTHORITY`
- `PACKAGE_PRESENT != DEPLOYED_REACHABLE_PACKAGE`
- `MAINTAINER != SUPPLY_CHAIN_ACTOR`
- `DEEPFAKE_DETECTOR_OUTPUT != PROOF_OF_FABRICATION`

## 6. 65 canonical modules (retrieved master specification)

### Corporate Governance
- **REGINT**: registration, regulated entities, licenses and official records
- **COMPANYINT**: legal companies, directors, shareholders, filings and corporate structure
- **OWNERSHIPINT**: legal/economic/beneficial ownership and control
- **PROCUREMENTINT**: tenders, awards, contracts and procurement oversight
- **TRADEINT**: imports/exports, cargo parties, HS classifications and shipments
- **ADDRESSINT**: address types, history and non-identifying geospatial context
- **LEGALINT**: case law, filings, legal claims and judicial statuses
- **SANCTIONSINT**: screening, true entity resolution and jurisdiction-specific sanctions context
- **FININT**: authorized financial records, counterparties, payment flows and economic relationships

### Cyber Threat Software
- **IOCINT**: indicators, sightings, freshness, reputation and defensive relevance
- **VULNINT**: CVE/KEV/EPSS, affected products, assets, exposure and remediation priority
- **THREATACTORINT**: threat labels, intrusion sets, TTPs, actor attribution hypotheses
- **CAMPAIGNINT**: incident/campaign boundaries, linked infrastructure, malware and temporal clustering
- **MALWAREINT**: authorized malware sample/report intelligence, family and behavior analysis
- **PACKAGEINT**: package registries, version/dependency risk and provenance
- **REPOINT**: GitHub/repository intelligence, commits and software ecosystem relationships
- **SUPPLYCHAININT**: vendor, 4th/nth-party, software/physical dependencies, criticality and resilience
- **INCIDENTINT**: authorized incident case/telemetry evidence, timelines and response intelligence
- **LOGINT**: normalized authorized logs, events and detection correlation

### Discovery Web Research
- **WEBINT**: bounded public web collection, parsing, archiving and web evidence
- **SEARCHINT**: provider-neutral search discovery
- **DORKINT**: bounded lawful query generation; no secret harvesting
- **USERNAMEINT**: public username/handle footprints with false-match safeguards
- **ARCHIVEINT**: historical web/doc snapshots and historical change
- **NEWSINT**: news intelligence with source pedigree and recency
- **ACADEMICINT**: scholarly literature, researchers, institutions, research groups, grants and citation quality
- **DATASETINT**: dataset discovery, metadata, licenses, schema, lineage and quality

### Geo Event Transport
- **GEOINT**: geospatial analysis with anti-overprecision safeguards
- **MAPINT**: map layers, geographic relationships, location evidence
- **SATINT**: public/authorized satellite imagery, dates and visual uncertainty
- **TRANSPORTINT**: public/authorized transport records and historical routes
- **EVENTINT**: event timeline, organizer, schedule, occurrence and sources

### Identity Communication
- **EMAILINT**: authorized email artifact/header intelligence and provenance
- **PHONEINT**: public/authorized phone/number metadata with reassignment caution
- **SOCMINT**: public social-media content and platform relationships
- **MESSENGERINT**: public/authorized chat/message intelligence
- **INTERVIEWINT**: consensual interviews, claim decomposition and source handling

### Internet Infrastructure
- **DOMAININT**: domain registration, lifecycle, control eras and organization association
- **DNSINT**: current/passive/historical DNS and temporal provider relationships
- **CERTINT**: X.509, CT, chains, cert history and cautious reuse analysis
- **IPINT**: IP/prefix/RIR/RDAP/ASN context, usage eras and reputation
- **ASNINT**: autonomous system identity and public network relationships
- **BGPINT**: routing announcements/history, AS paths, ROAs/RPKI context
- **NETINT**: passive network topology/flows and infrastructure relationships
- **CLOUDINT**: authorized cloud asset metadata, tenant/provider boundary and security posture

### Documents Media Verification
- **DOCINT**: document extraction, provenance and contradiction handling
- **METADATAINT**: file/document/media metadata analysis and tamper caveats
- **IMINT**: image evidence, provenance, visual clues and careful interpretation
- **VIDINT**: video/frame/timeline evidence and safe scene/event analysis
- **AUDINT**: audio metadata/transcript/acoustic and integrity analysis
- **DISINFOINT**: misinformation narratives, provenance and independent verification

### Mobile Iot Ot
- **APPINT**: application intelligence from lawful app stores, code/artifact metadata
- **MOBILEINT**: authorized mobile app/device artifact intelligence
- **IOTINT**: IoT device/firmware/dependency intelligence
- **OTINT**: industrial/OT asset intelligence in authorized/defensive scope

### Fraud Exposure Brand Market
- **FRAUDINT**: fraud/scam patterns, claims, transactions and non-accusatory investigation support
- **PAYMENTINT**: authorized payment instruments/rails, merchant and settlement context
- **CRYPTOINT**: public/authorized blockchain evidence, wallet/transaction context without doxxing
- **BRANDINT**: brands, trademark links, impersonation and reputation context
- **ADINT**: public advertisement transparency, campaign content and source claims
- **MARKETPLACEINT**: public marketplace listings, sellers and fraud/brand context
- **JOBINT**: public job postings and workforce/capability signals
- **COMPLAINTINT**: public/authorized complaints, duplication and status
- **EXPOSUREINT**: credential/secret/external exposure and remediation context
- **DARKWEBINT**: lawful dark-web metadata and defensive research without illicit acquisition

**Canonical aliases:** `CORPINT → COMPANYINT`, `CHATINT → MESSENGERINT`, `MALINT → MALWAREINT`, `SCAMINT → FRAUDINT`, `DARKINT → DARKWEBINT`, `BREACH Intelligence → BREACHINT`, `Credential Intelligence → CREDINT`.

**Additional umbrella / extended disciplines and requests:**
- **OSINT** (umbrella): Open-source intelligence collection and synthesis, public/authorized sources
- **CTI** (umbrella): Cyber threat intelligence strategic/tactical/technical/operational
- **CYBINT** (umbrella): Broad defensive cyber intelligence across IOC, vuln, actor, malware, infrastructure, incidents
- **INFRAINT** (extended): Internet-facing infrastructure identity, hosting, CDN, CT and historic topology
- **TECHINT** (extended): Technical products/models/revisions/capabilities and BOMs without exploitation
- **HUMINT** (extended): Consensual human-source testimony, source access and independent corroboration
- **SIGINT** (extended): Authorized passive spectrum/signals metadata, not interception or targeting
- **COMINT** (extended): Authorized/public communications records, threads and networks
- **ELINT** (extended): Authorized non-communication emitter/spectrum measurements, no jamming/targeting
- **MASINT** (extended): Measurement/signature intelligence from lawful authorized public sensor data
- **BREACHINT** (extended): Breach/exposure claims, datasets, origin, duplication, verified counts and privacy
- **CREDINT** (extended): Defensive credential/token/key exposure; never log in or replay secrets
- **EXPLOITINT** (extended): Defensive exploitation trends and asset exposure, no exploits or attack guidance
- **TTPINT** (extended): Adversary TTP observations and ATT&CK mapping, not procedural offensive execution
- **DECEPTIONINT** (requested): Evidence-based deception/manipulation indicators without lie detection or manipulation tactics
- **ORGINT** (extended): Governance, teams, reporting lines, roles vs persons, formal vs functional authority
- **AIINT** (extended): Research/AI ecosystem intelligence; do not invent model capabilities
- **PERSONINT** (extended): Lawful high-level entity identity with strict anti-doxxing controls
- **CODEINT** (extended): Authorized code and code-provenance intelligence

**Maturity warning:** These are conversation-level taxonomy and requested capability definitions. They are NOT proof of existing code, source availability or production readiness.

## 7. Detailed discipline memory

### HUMINT
**Skills and focus:** consensual interviews, basis of knowledge, firsthand vs hearsay, source reliability separate from claim credibility, memory/time limits, independent corroboration.
**Strict distinctions:** source confidence ≠ accuracy; consistent testimony ≠ verified fact; demeanor ≠ lie detector; refusal ≠ guilt.
**Restrictions:** no covert recruitment, coercion, blackmail, deception or identity impersonation; no private interception or sensitive profiling.

### FININT
**Skills and focus:** authorized financial records, cash/payment flow, beneficiary vs processor, source-of-funds claims, benign alternatives, deterministic currency/amount arithmetic.
**Strict distinctions:** invoice ≠ payment; account holder ≠ operator; anomaly ≠ crime; flow ≠ ownership.
**Restrictions:** no unauthorized bank access or fund movement; no money laundering, fraud or sanctions evasion.

### TRADEINT
**Skills and focus:** shipper/consignee/buyer/seller roles, HS version, quantities/values, origin vs transit, BOL vs invoice, Incoterms, sanctions/export control context.
**Strict distinctions:** shipper ≠ manufacturer; consignee ≠ end user; invoice ≠ shipment; route anomaly ≠ evasion.
**Restrictions:** no customs/sanctions/export-control evasion or illicit logistics.

### COMPANYINT
**Skills and focus:** legal identity, registrations, directors/officers, share classes, shareholders, beneficial owners, corporate control eras, filing time.
**Strict distinctions:** director ≠ owner; owner ≠ beneficial owner; shared address ≠ same owner; brand ≠ company.
**Restrictions:** no doxxing directors or hidden ownership evasion design.

### ORGINT
**Skills and focus:** formal vs functional reporting, unit/role/person separations, delegated authority, governance, program/project, capacity and dependencies, historical changes.
**Strict distinctions:** title ≠ authority; role ≠ person; org chart ≠ actual structure.
**Restrictions:** no social engineering or private-employee targeting.

### SUPPLYCHAININT
**Skills and focus:** direct/4th/nth-party dependency, SBOM/VEX/PURL, cloud/IdP/CI/CD common failures, criticality/substitution, vendor incidents, supplier alternatives.
**Strict distinctions:** contract ≠ active use; SBOM ≠ deployed reality; supplier incident ≠ customer compromise; single provider ≠ SPOF.
**Restrictions:** no vendor intrusion, sabotage, malicious packages, or dependency attack prioritization.

### FRAUDINT
**Skills and focus:** scam typologies, claimed vs observed fraud, impersonation, payment/complaints, campaign clustering, reversals/refunds and net loss, benign alternatives.
**Strict distinctions:** complaint ≠ proven fraud; chargeback ≠ fraud; account holder ≠ fraud operator; anomaly ≠ crime.
**Restrictions:** no phishing, scam scripts, laundering, forged documents or fraud-evasion guidance.

### CREDINT
**Skills and focus:** exposed passwords/hashes, session tokens/keys/MFA secrets, stealer/combo source, account relevance, rotation/revocation, privacy-preserving fingerprinting.
**Strict distinctions:** exposed ≠ valid ≠ compromised; password reset ≠ sessions revoked; stealer log ≠ website breach.
**Restrictions:** never test or use passwords, keys, cookies, refresh tokens, recovery codes, or log in.

### BREACHINT
**Skills and focus:** breach claim vs fact, sample/dataset authenticity, lineage/recycled leaks, record counts, first vs third-party origin, data class/impact.
**Strict distinctions:** email in leak ≠ company breached; sample ≠ full dataset; new listing ≠ new breach.
**Restrictions:** no illicit purchase, full stolen-data acquisition, or reuse of exposed secrets.

### MALWAREINT
**Skills and focus:** safe sample/report analysis, static vs dynamic observations, family/variant resolution, IOC freshness, C2 claims, ATT&CK evidence mapping.
**Strict distinctions:** static clue ≠ executed behavior; sample ≠ family; family ≠ actor; embedded IOC ≠ contacted IOC.
**Restrictions:** no malware development, execution on host, evasion optimization or live C2 tasking.

### VULNINT
**Skills and focus:** CVE/CWE/CPE/PURL, vendor fixed/affected versions, CVSS/EPSS/KEV, backports, VEX/SBOM, asset applicability, defensive priority.
**Strict distinctions:** severity ≠ exploitability; exposure ≠ exploitation; component presence ≠ reachability.
**Restrictions:** no exploit execution or target-specific weaponization.

### NETINT
**Skills and focus:** passive infrastructure and authorized network telemetry, IP/ASN/BGP/cloud relationships, temporal routing, NAT/CDN context.
**Strict distinctions:** allocated_to ≠ owned_by; open port ≠ exploit; RPKI invalid ≠ hijack.
**Restrictions:** no unauthorized active scans, interception, route manipulation or exploitation.

### DOMAININT
**Skills and focus:** RDAP/registrar/registry, domain control eras, historical DNS, associated companies, brands and typosquatting context.
**Strict distinctions:** registrar ≠ registrant; domain age ≠ benignity; historic owner ≠ current owner.
**Restrictions:** no domain takeover, unauthorized enumeration, registrar modification.

### DNSINT
**Skills and focus:** A/AAAA/CNAME/MX/NS/TXT/SOA/SRV/CAA/PTR, pDNS, authoritative DNS, history, CDN/wildcard, DNSSEC and time.
**Strict distinctions:** pDNS first_seen ≠ creation; shared NS ≠ common owner; CDN edge ≠ origin.
**Restrictions:** no poisoning, unauthorized AXFR, DNS abuse.

### IPINT
**Skills and focus:** RIR/RDAP/ASN/BGP, IP usage eras, cloud/CDN sharing, reputation freshness, passive service evidence.
**Strict distinctions:** IP allocation ≠ tenant; IP geolocation ≠ exact person; old malicious reputation ≠ current maliciousness.
**Restrictions:** no unauthorized scans, brute-force, traffic interception.

### IMINT
**Skills and focus:** source preservation, image metadata, visual clues, duplicate/synthetic/manipulation indicators, GEOINT handoff.
**Strict distinctions:** detector output ≠ proven fake; image real ≠ caption true; similar face ≠ identity.
**Restrictions:** no face identification, biometric search, private tracking or sensitive trait inference.

### VIDINT
**Skills and focus:** shots/keyframes, temporal scene reasoning, source provenance, manipulation/clips reuse, audio handoff.
**Strict distinctions:** clip date ≠ event date; visual event ≠ inferred intent.
**Restrictions:** no face identity or private CCTV access.

### AUDINT
**Skills and focus:** safe audio preservation, ASR/diarization, acoustic events, sync/edit/synthetic clues, source independence.
**Strict distinctions:** voice confidence ≠ truth; accent ≠ nationality; one deepfake detector ≠ proof.
**Restrictions:** no voice biometric identity, private interception, lie detection.

### SIGINT
**Skills and focus:** authorized spectrum/IQ/metadata, temporal emission pattern, sensor calibration, RF context.
**Strict distinctions:** RSSI ≠ exact distance; device ≠ person; unknown signal ≠ hostile.
**Restrictions:** no private interception, jamming, spoofing, tracking or targeting.

### COMINT
**Skills and focus:** consented/public communications, participants/threads/forward chains, claims vs observations, attachments and metadata.
**Strict distinctions:** account ≠ person; message claim ≠ truth; chat frequency ≠ leadership.
**Restrictions:** no private intercept, stolen sessions, deceptive private-group joins.

### ELINT
**Skills and focus:** non-communications RF/emitter descriptors, pulse/spectrum observations, emitter class vs platform.
**Strict distinctions:** emitter class ≠ exact platform; non-detection ≠ absence.
**Restrictions:** no jamming, electronic-attack waveforms, evasion/targeting guidance.

### CYBINT
**Skills and focus:** defensive IOC, infra/malware/actor/campaign, vulnerability context, authorized SOC/logs, reporting.
**Strict distinctions:** IOC ≠ attribution; CVE presence ≠ exploitation; IP provider ≠ attacker.
**Restrictions:** no exploits, credential attacks or offensive operations.

### CTI
**Skills and focus:** threat intelligence PIR, TTPs/ATT&CK versioning, indicators and sightings, actor-label caution, STIX/TAXII/MISP.
**Strict distinctions:** campaign ≠ actor; malware family ≠ real-world operator; threat reports may share upstream source.
**Restrictions:** no malware deployment or intrusive threat-actor interaction.

### ACADEMICINT
**Skills and focus:** public scholarly metadata, papers/research groups, institutions/grants/citations, preprint vs peer review, retractions/corrections, source/author and topical relevance.
**Strict distinctions:** citation count ≠ research quality; preprint ≠ peer-reviewed; coauthor ≠ personal affiliation; affiliation ≠ ownership.
**Restrictions:** no paywall/access bypass, plagiarism, fabrication, unauthorized private researcher profiling.

### DECEPTIONINT
**Skills and focus:** source-claim consistency, provenance/cross-source contradictions, document/media manipulation signals, context and narrative framing, alternative explanations.
**Strict distinctions:** inconsistency ≠ deliberate lie; tone ≠ deceit; manipulation indicator ≠ actor attribution.
**Restrictions:** no lie detection based on face/voice/emotion; no psychological manipulation tactics or political targeting.

## 8. Authorized source and connector ecosystem (requested, not verified)
- **Open Source:** SpiderFoot, Recon-ng, Amass, Nuclei, Maigret, SearXNG, Wayback Machine, WHOIS/RDAP, DNS, GitHub dorks, Shodan InternetDB, JA4, passive DNS.
- **Commercial Or Licensed:** Shodan, Censys, HIBP (authorization-dependent), Apify, Firecrawl, Exa, Docling, Social Links, ThreatMon.
- **Additional:** OSINT IQ, MISP, STIX/TAXII, MITRE ATT&CK, YARA, Sigma, OT/ICS telemetry, public datasets, public web/search/archive, public social feeds.

A registry entry is not a working integration, a mock is not a live source, and a successful HTTP response is not production qualification.

## 9. Code, architecture, documents and deployment history

**Tech:** Python 3.12+, FastAPI, Pydantic, TypeScript, React/Next.js, PostgreSQL/PostGIS, S3/MinIO, Ollama/local model as default, optional cloud model adapters, OpenTelemetry, Docker; Kubernetes only when justified.

**Historical deployment intent:** Vercel frontend (past user intent), Supabase backend (past user intent), private investigator workspace, Oracle worker removed from prior requested architecture. This export did not verify a URL.

**Docs that user asks engineering agents to inspect/maintain:**

`AGENTS.md`, `README`, `EXECUTIVE_VERDICT`, `ENTERPRISE_ASSESSMENT`, `PROBLEM_STATEMENTS`, `ARCHITECTURE`, `FLOW`, `DATA_MODEL`, `INTEGRATION_MAP`, `REPAIR`, `ACCEPTANCE_GATES`, `SOURCE_STRATEGY`, `CHANGE_CONTROL`

**Persistent engineering memory and ledgers:**

`.ai/CURRENT_STATE.md`, `.ai/ACTIVE_WORK.md`, `.ai/TASKS.md`, `.ai/MEMORY.md`, `.ai/DECISIONS.md`, `.ai/KNOWN_ISSUES.md`, `.ai/SESSION_CONTEXT.md`, `docs/program/MASTER_GAP_REGISTER.md`, `docs/program/10_SCORECARD.md`, `docs/program/IMPLEMENTATION_LEDGER.md`, `docs/program/SOURCE_LEDGER.md`, `docs/program/EVALUATION_LEDGER.md`, `docs/program/SECURITY_LEDGER.md`, `docs/program/COMPETITIVE_BENCHMARK.md`

**Priority repair sequence:**
1. Fix P0 runtime, source truth, security, evidence and replay
2. Fix P1 integrations, agent routing and product usability
3. Qualify representative real sources and workflows
4. Expand specialized domains only with gates
5. Enterprise ops and independent market benchmarking

**First vertical slice:** Authorized public domain/IP/company objective → collection → evidence → normalization → entity/temporal graph → contradiction verification → reproducible report. Build this before broad novelty.

**Non-negotiable code quality:** Extend existing working code first; minimum files necessary, maximum testable functionality, no stubs, no decorative architecture, no duplicate engines, no fabricated connectors.

## 10. Historical scorecards and acceptance gates
- {"period": "early", "overall": "~2.1/10"}
- {"period": "improved", "overall": "~4.4/10"}
- {"period": "late September self-reported", "live_source": "6/10", "social": "5/10", "darkweb": "6/10", "ai_media": "6/10", "ux": "7/10", "enterprise": "6/10", "overall": "~6.0/10"}
- {"period": "realistic audit (historical, not rerun)", "repo_code": "6.5–7/10", "implementation_depth": "4.5/10", "live_source": "2.5/10", "investigator_ready": "3.5/10", "production_ops": "2/10", "enterprise_readiness": "2.5/10", "overall_market_maturity": "~3.5/10"}

These are **historical and non-comparable snapshots**, not today's factual project rating. Do not extrapolate enterprise readiness from them.

**Acceptance gates:**
- Real source connectivity tested with permission and provenance
- No fixture/mock promoted as live provider
- Reproducible end-to-end objective-to-report golden cases
- Unknown/blocked states truthful
- Entity merges reversible and explainable
- Evidence immutable and replayable
- Source pedigree and independence proven
- Contradictions found and preserved
- LOCAL_ONLY/Ollama actually works
- Security IAM/tenant boundaries tested
- Deployment/CI/logging/backup health proven
- Performance/cost/latency observed
- Docs match implementation

**Capability maturity states:** DISCOVERED, DESIGNED, STUB, CODED, UNIT_TESTED, INTEGRATION_TESTED, LIVE_TESTED, LIVE_VERIFIED, PRODUCTION_QUALIFIED

**Benchmarks:** source counts and 250+ golden investigation cases are user/program ambitions, not achieved claims.

## 11. Conversation request chronology (summaries, not verbatim transcripts)
- **2026-09** | Architect AI employees with manager/team lead/worker engines and SKILL.md packs | `architecture request` | `requested`
- **2026-09-23** | Critical gaps, 9+/10 enterprise roadmap and Maltego-level comparison | `product direction` | `requested`
- **2026-09-28** | Merge and integrate existing TraceAtlas with live OSINT sources; push main | `engineering request` | `not_verified`
- **2026-09-29** | Private interactive investigation website, entity/evidence/timeline, deploy privately | `product request` | `deployment_not_verified`
- **2026-09-30** | Enterprise repair blueprint audit-first phase 0 at historical baseline commit | `engineering request` | `requested`
- **2026-10-03** | Complete blueprint documents, AI employee upgrades, sources and autonomous workflows | `engineering request` | `not_verified`
- **2026-10-04** | Aggressive repo/code comparison vs leading tools, do not fake maturity | `audit request` | `historical_only`
- **2026-10-07** | Consolidate 65 intelligence disciplines and architecture | `architecture request` | `document_retrieved`
- **2026-10-07** | Repair entire code before GitHub push; no placeholders, tests, compatibility | `engineering request` | `not_verified`
- **2026-10-08** | Manager → team lead → employee engine → skills distinction and reuse | `architecture request` | `conversation_explicit`
- **2026-10-08** | PROCUREMENTINT AI employee prompt with skills/restrictions | `prompt request` | `history_summary`
- **2026-10-08** | OSINT + cross-discipline taxonomy, 65-module master implementation | `architecture request` | `retrieved_library`
- **2026-10** | EXPLOITINT AI employee prompt | `prompt request` | `requested_in_recent_conversation`
- **2026-10** | THREATACTORINT AI employee prompt | `prompt request` | `requested_in_recent_conversation`
- **2026-10** | IOCINT AI employee prompt | `prompt request` | `requested_in_recent_conversation`
- **2026-10** | TTPINT AI employee prompt | `prompt request` | `requested_in_recent_conversation`
- **2026-10** | DARKINT AI employee prompt | `prompt request` | `requested_in_recent_conversation`
- **2026-10** | BREACHINT AI employee prompt | `prompt request` | `draft_visible`
- **2026-10** | CREDINT AI employee prompt | `prompt request` | `draft_visible`
- **2026-10** | HUMINT AI employee prompt | `prompt request` | `draft_visible`
- **2026-10** | FININT AI employee prompt | `prompt request` | `draft_visible`
- **2026-10** | TRADEINT AI employee prompt | `prompt request` | `draft_visible`
- **2026-10** | CORPINT / COMPANYINT AI employee prompt | `prompt request` | `draft_visible`
- **2026-10** | ORGINT AI employee prompt | `prompt request` | `draft_visible`
- **2026-10** | SUPPLYCHAININT AI employee prompt | `prompt request` | `draft_visible`
- **2026-10** | SCAMINT / FRAUDINT AI employee prompt | `prompt request` | `draft_visible`
- **2026-10-09** | ACADEMICINT AI employee prompt | `prompt request` | `requested_not_answered_in_visible_excerpt`
- **2026-10-09** | DECEPTIONINT AI employee prompt | `prompt request` | `requested_not_answered_in_visible_excerpt`
- **2026-10-09** | Portable graph memory as JSON, Markdown, TXT for transfer to another chat | `memory export request` | `this_export`

### Open/recent attention items
- **ACADEMICINT** prompt requested on 2026-10-09, full completed answer not available in provided excerpt.
- **DECEPTIONINT** prompt requested on 2026-10-09, full completed answer not available in provided excerpt.
- No claim about code integration, pushes, current HEAD, CI, Vercel readiness, Supabase health or real sources until freshly verified.

## 12. Portable graph data model
- **434 nodes**, **671 directed edges**, **65 canonical modules**, **19 extended disciplines**, **29 request records**.
- Main graph file `TraceAtlas_COMPLETE_Graph_Memory.json` contains metadata, requirements, module details, conversation request timeline, nodes and edges with provenance warnings.
- `TraceAtlas_Graph.graphml` and CSV exports are import-friendly; GraphML may flatten complex nested attributes to compact JSON strings.
- Every graph edge is a **memory link**, not an independently proven real-world association.

## 13. Next-chat restore procedure

1. Upload `TraceAtlas_Memory_Pack_2026-10-09.zip`, or upload JSON + this Markdown.
2. Ask the next chat to read `NEXT_CHAT_CONTEXT.txt` and this handover first, then parse the graph JSON.
3. Instruct: continue existing TraceAtlas architecture, reconcile with **current** repo HEAD/AGENTS.md, never call design status implementation success.
4. Before any GitHub push, run safe tests, check CI and explicitly authorize external changes.
5. Use original reference master prompts for exact historical instructions, not for unsupported implementation claims.

## 14. Provenance / explicit omissions
- Current conversation: recent prompts and project architecture were visible and summarized.
- Earlier graph and 65-module master: retrieved from the user's Library, archived without changing original content.
- Enterprise 10/10 program: retrieved from user Library, archived. Targets not equal verified achievement.
- Historical dates/scores/commit baseline: drawn from prior-context summary, not freshly audited.
- Unavailable exact past exchanges: **not reproduced**. Unrelated personal/medical/private context intentionally excluded.
