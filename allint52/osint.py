import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import json
from datetime import datetime, timezone
from typing import Any, Dict, List


FIELDS = [
    ("case_id", "Case ID", "entry"),
    ("task_id", "Task ID", "entry"),
    ("objective", "Objective", "text"),
    ("target", "Target", "entry"),
    ("target_type", "Target Type", "combo"),
    ("questions", "Intelligence Questions", "text"),
    ("scope", "Scope / Allowed Sources", "text"),
    ("authorization", "Authorization Basis", "text"),
    ("time_range", "Time Range", "text"),
    ("jurisdiction", "Jurisdiction", "entry"),
    ("known_entities", "Known Entities", "text"),
    ("known_identifiers", "Known Identifiers", "text"),
    ("existing_facts", "Existing Facts", "text"),
    ("existing_hypotheses", "Existing Hypotheses", "text"),
    ("existing_contradictions", "Existing Contradictions", "text"),
    ("source_limits", "Source Limits", "text"),
    ("budget", "Budget", "entry"),
    ("deadline", "Deadline", "entry"),
    ("available_evidence", "Available Evidence / URLs / Files", "text"),
    ("configured_connectors", "Configured Connectors / APIs", "text"),
]

TARGET_TYPES = [
    "person",
    "company",
    "organization",
    "domain",
    "ip",
    "asn",
    "username",
    "public_account",
    "repository",
    "document",
    "malware",
    "campaign",
    "location",
    "event",
    "wallet",
    "product",
    "topic",
    "infrastructure_cluster",
    "regulatory_matter",
    "procurement_record",
    "sanctions_entity",
    "unknown",
]

COMBO_CHOICES = {
    "target_type": TARGET_TYPES,
}


def parse_list(value: str) -> List[Any]:
    """
    Parse multiline / comma-separated / JSON-list input into a list.
    """
    value = value.strip()
    if not value:
        return []

    # Try JSON first
    try:
        parsed = json.loads(value)
        if isinstance(parsed, list):
            return parsed
        if isinstance(parsed, dict):
            return [parsed]
    except Exception:
        pass

    # Otherwise split by newline or comma
    normalized = value.replace(",", "\n")
    parts = [p.strip() for p in normalized.splitlines()]
    return [p for p in parts if p]


def parse_dict(value: str) -> Dict[str, Any]:
    """
    Parse JSON object or simple key: value lines into dict.
    """
    value = value.strip()
    if not value:
        return {}

    # Try JSON first
    try:
        parsed = json.loads(value)
        if isinstance(parsed, dict):
            return parsed
    except Exception:
        pass

    result: Dict[str, Any] = {}
    for line in value.splitlines():
        line = line.strip()
        if not line:
            continue
        if ":" not in line:
            continue
        key, val = line.split(":", 1)
        result[key.strip()] = val.strip()

    return result


class TraceAtlasOSINTPanel(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("TraceAtlas OSINT AI Employee — Task Panel")
        self.geometry("1280x860")
        self.minsize(1000, 700)

        self.entries: Dict[str, Any] = {}

        self._configure_style()
        self._build_ui()
        self._set_defaults()

    def _configure_style(self) -> None:
        style = ttk.Style(self)

        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        self.configure(bg="#0f1115")

        style.configure(
            "TFrame",
            background="#0f1115",
        )

        style.configure(
            "TLabel",
            background="#0f1115",
            foreground="#e6e6e6",
            font=("Segoe UI", 10),
        )

        style.configure(
            "Header.TLabel",
            background="#0f1115",
            foreground="#7dd3fc",
            font=("Segoe UI", 17, "bold"),
        )

        style.configure(
            "Subheader.TLabel",
            background="#0f1115",
            foreground="#94a3b8",
            font=("Segoe UI", 9),
        )

        style.configure(
            "TNotebook",
            background="#0f1115",
            borderwidth=0,
        )

        style.configure(
            "TNotebook.Tab",
            padding=[14, 7],
            font=("Segoe UI", 10, "bold"),
        )

        style.configure(
            "TEntry",
            fieldbackground="#151922",
            foreground="#e6e6e6",
            insertcolor="#ffffff",
            bordercolor="#263044",
            lightcolor="#263044",
            darkcolor="#263044",
        )

        style.configure(
            "TCombobox",
            fieldbackground="#151922",
            foreground="#e6e6e6",
            arrowcolor="#e6e6e6",
            bordercolor="#263044",
            lightcolor="#263044",
            darkcolor="#263044",
        )

        style.configure(
            "TButton",
            padding=7,
            font=("Segoe UI", 10, "bold"),
            background="#1e293b",
            foreground="#e6e6e6",
            bordercolor="#334155",
            lightcolor="#334155",
            darkcolor="#334155",
        )

        style.map(
            "TButton",
            background=[("active", "#334155")],
            foreground=[("active", "#ffffff")],
        )

        style.configure(
            "Vertical.TScrollbar",
            background="#1e293b",
            troughcolor="#0f1115",
            arrowcolor="#e6e6e6",
        )

    def _build_ui(self) -> None:
        header_frame = ttk.Frame(self)
        header_frame.pack(fill="x", padx=16, pady=(14, 8))

        ttk.Label(
            header_frame,
            text="TraceAtlas OSINT AI Employee",
            style="Header.TLabel",
        ).pack(anchor="w")

        ttk.Label(
            header_frame,
            text=(
                "Evidence-first • Public / authorized sources only • Passive by default • "
                "Planning-only unless live connectors are implemented"
            ),
            style="Subheader.TLabel",
            wraplength=1150,
            justify="left",
        ).pack(anchor="w", pady=(2, 0))

        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=16, pady=(8, 16))

        self.input_tab = ttk.Frame(self.notebook)
        self.output_tab = ttk.Frame(self.notebook)

        self.notebook.add(self.input_tab, text="Task Input")
        self.notebook.add(self.output_tab, text="Output / Search Plan")

        self._build_input_tab()
        self._build_output_tab()

    def _build_input_tab(self) -> None:
        container = ttk.Frame(self.input_tab)
        container.pack(fill="both", expand=True)

        self.canvas = tk.Canvas(
            container,
            bg="#0f1115",
            highlightthickness=0,
        )

        scrollbar = ttk.Scrollbar(
            container,
            orient="vertical",
            command=self.canvas.yview,
        )

        self.form = ttk.Frame(self.canvas)

        self.form.bind(
            "<Configure>",
            lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")),
        )

        self.canvas_window = self.canvas.create_window(
            (0, 0),
            window=self.form,
            anchor="nw",
        )

        self.canvas.configure(yscrollcommand=scrollbar.set)

        self.canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        row = 0

        for key, label, kind in FIELDS:
            ttk.Label(self.form, text=label).grid(
                row=row,
                column=0,
                sticky="nw",
                padx=10,
                pady=6,
            )

            if kind == "entry":
                widget = ttk.Entry(self.form, width=92)

            elif kind == "combo":
                widget = ttk.Combobox(
                    self.form,
                    values=COMBO_CHOICES.get(key, []),
                    width=90,
                    state="readonly",
                )

            else:
                widget = tk.Text(
                    self.form,
                    height=3,
                    width=92,
                    bg="#151922",
                    fg="#e6e6e6",
                    insertbackground="white",
                    relief="flat",
                    highlightthickness=1,
                    highlightbackground="#263044",
                    font=("Segoe UI", 10),
                    wrap="word",
                )

            widget.grid(
                row=row,
                column=1,
                sticky="ew",
                padx=10,
                pady=6,
            )

            self.entries[key] = widget
            row += 1

        self.form.columnconfigure(1, weight=1)

        button_frame = ttk.Frame(self.input_tab)
        button_frame.pack(fill="x", padx=10, pady=12)

        ttk.Button(
            button_frame,
            text="Generate Search Plan",
            command=self.generate_plan,
        ).pack(side="left", padx=4)

        ttk.Button(
            button_frame,
            text="Export Task JSON",
            command=self.export_task_json,
        ).pack(side="left", padx=4)

        ttk.Button(
            button_frame,
            text="Copy Output",
            command=self.copy_output,
        ).pack(side="left", padx=4)

        ttk.Button(
            button_frame,
            text="Clear Form",
            command=self.clear_form,
        ).pack(side="left", padx=4)

    def _build_output_tab(self) -> None:
        container = ttk.Frame(self.output_tab)
        container.pack(fill="both", expand=True)

        self.output = tk.Text(
            container,
            wrap="word",
            bg="#0b0f17",
            fg="#d7ffe8",
            insertbackground="white",
            relief="flat",
            highlightthickness=1,
            highlightbackground="#263044",
            font=("Consolas", 11),
        )

        output_scroll = ttk.Scrollbar(
            container,
            orient="vertical",
            command=self.output.yview,
        )

        self.output.configure(yscrollcommand=output_scroll.set)

        self.output.pack(side="left", fill="both", expand=True)
        output_scroll.pack(side="right", fill="y")

    def _set_defaults(self) -> None:
        self.set_widget_value("case_id", "CASE-001")
        self.set_widget_value("task_id", "TASK-001")
        self.set_widget_value(
            "objective",
            "Identify publicly available, authorized information about the target "
            "and produce an evidence-backed OSINT search plan.",
        )
        self.set_widget_value("target", "")
        self.set_widget_value("target_type", "company")
        self.set_widget_value(
            "questions",
            "What is the legal entity?\n"
            "Which official identifiers exist?\n"
            "What domains are publicly associated?\n"
            "Who are publicly disclosed directors/officers?\n"
            "Which public filings exist?\n"
            "What historical names exist?\n"
            "What public infrastructure is linked?\n"
            "What contradictory information exists?",
        )
        self.set_widget_value(
            "scope",
            json.dumps(
                {
                    "allowed_source_types": [
                        "public websites",
                        "public search APIs",
                        "public archives",
                        "news sources",
                        "public government portals",
                        "public corporate registries",
                        "public procurement portals",
                        "public court/regulatory records",
                        "public sanctions lists",
                        "public company filings",
                        "public professional profiles",
                        "public social-media content",
                        "public forums",
                        "public GitHub/GitLab repositories",
                        "public package registries",
                        "public academic sources",
                        "public datasets",
                        "public certificate transparency",
                        "public DNS/RDAP data",
                        "public WHOIS where lawfully available",
                        "public ASN/BGP data",
                        "public map/geospatial sources",
                        "public CTI/advisory sources",
                        "public vulnerability catalogs",
                        "public blockchain data",
                    ],
                    "prohibited_sources": [
                        "private accounts",
                        "stolen credentials",
                        "illegal data markets",
                        "unauthorized scanning",
                        "paywall bypass",
                        "CAPTCHA bypass",
                    ],
                    "data_minimization_rules": [
                        "collect only objective-relevant data",
                        "avoid unnecessary personal data",
                        "redact incidental secrets",
                    ],
                    "authorized_use": "internal intelligence analysis only",
                },
                indent=2,
            ),
        )
        self.set_widget_value(
            "authorization",
            json.dumps(
                {
                    "authorized_by": "OSINT Manager",
                    "authorization_basis": "customer-authorized public OSINT engagement",
                    "permitted_actions": [
                        "public search",
                        "public archive review",
                        "public registry lookup",
                        "passive infrastructure lookup",
                    ],
                    "prohibited_actions": [
                        "hacking",
                        "social engineering",
                        "private surveillance",
                        "credential use",
                        "active scanning without separate authorization",
                    ],
                },
                indent=2,
            ),
        )
        self.set_widget_value(
            "time_range",
            json.dumps(
                {
                    "from": "",
                    "to": "",
                    "timezone": "UTC",
                },
                indent=2,
            ),
        )
        self.set_widget_value("jurisdiction", "")
        self.set_widget_value("known_entities", "")
        self.set_widget_value("known_identifiers", "")
        self.set_widget_value("existing_facts", "")
        self.set_widget_value("existing_hypotheses", "")
        self.set_widget_value("existing_contradictions", "")
        self.set_widget_value("source_limits", "")
        self.set_widget_value("budget", "")
        self.set_widget_value("deadline", "")
        self.set_widget_value("available_evidence", "")
        self.set_widget_value(
            "configured_connectors",
            "None configured. Output is planning-only unless live connectors are added.",
        )

    def get_widget_value(self, key: str) -> str:
        widget = self.entries.get(key)

        if widget is None:
            return ""

        if isinstance(widget, tk.Text):
            return widget.get("1.0", "end-1c").strip()

        if isinstance(widget, ttk.Combobox):
            return widget.get().strip()

        if isinstance(widget, ttk.Entry):
            return widget.get().strip()

        return ""

    def set_widget_value(self, key: str, value: str) -> None:
        widget = self.entries.get(key)

        if widget is None:
            return

        if isinstance(widget, tk.Text):
            widget.delete("1.0", "end")
            widget.insert("1.0", value)

        elif isinstance(widget, ttk.Combobox):
            widget.set(value)

        elif isinstance(widget, ttk.Entry):
            widget.delete(0, "end")
            widget.insert(0, value)

    def collect_payload(self) -> Dict[str, Any]:
        payload: Dict[str, Any] = {}

        list_fields = {
            "questions",
            "known_entities",
            "known_identifiers",
            "existing_facts",
            "existing_hypotheses",
            "existing_contradictions",
            "source_limits",
            "available_evidence",
            "configured_connectors",
        }

        dict_fields = {
            "scope",
            "authorization",
            "time_range",
        }

        for key, _, _ in FIELDS:
            raw = self.get_widget_value(key)

            if key in list_fields:
                payload[key] = parse_list(raw)
            elif key in dict_fields:
                payload[key] = parse_dict(raw)
            else:
                payload[key] = raw

        payload["generated_at"] = datetime.now(timezone.utc).isoformat()
        payload["panel_version"] = "TraceAtlas OSINT Panel v0.1"
        payload["operating_mode"] = "PLANNING_ONLY"

        return payload

    def validate_payload(self, payload: Dict[str, Any]) -> List[str]:
        warnings: List[str] = []

        required = [
            "case_id",
            "task_id",
            "objective",
            "target",
            "jurisdiction",
        ]

        for field in required:
            if not payload.get(field):
                warnings.append(f"Missing required field: {field}")

        if not payload.get("questions"):
            warnings.append("No intelligence questions provided. Default questions will be inferred.")

        if not payload.get("authorization"):
            warnings.append("No authorization basis provided. Treat as policy-limited planning only.")

        if not payload.get("scope"):
            warnings.append("No scope provided. Default public/authorized-only assumptions applied.")

        time_range = payload.get("time_range", {})
        if isinstance(time_range, dict):
            if not time_range.get("from") and not time_range.get("to"):
                warnings.append("No time range provided. Temporal freshness checks may be incomplete.")

        return warnings

    def generate_plan(self) -> None:
        payload = self.collect_payload()
        warnings = self.validate_payload(payload)

        result = {
            "mode": "PLANNING_ONLY",
            "policy": (
                "This output does not execute live searches. "
                "It produces a reproducible OSINT search plan using public/authorized source assumptions only. "
                "No hacking, private account access, credential misuse, CAPTCHA bypass, "
                "unauthorized scanning, doxxing, or social engineering is permitted."
            ),
            "warnings": warnings,
            "payload": payload,
            "intelligence_questions": payload.get("questions") or self._default_questions(payload),
            "search_plan": self._build_search_plan(payload),
            "fact_gate_criteria": self._fact_gate_criteria(),
            "evidence_schema": self._evidence_schema(),
            "observation_schema": self._observation_schema(),
            "source_assessment_schema": self._source_assessment_schema(),
            "contradiction_schema": self._contradiction_schema(),
            "knowledge_gap_schema": self._knowledge_gap_schema(),
            "recommended_stop_conditions": self._stop_conditions(),
            "specialist_handoffs": self._specialist_handoffs(payload),
            "next_best_action": self._next_best_action(payload),
        }

        self.output.delete("1.0", "end")
        self.output.insert(
            "1.0",
            json.dumps(result, ensure_ascii=False, indent=2),
        )

        self.notebook.select(self.output_tab)

        if warnings:
            messagebox.showwarning(
                "Validation Warnings",
                "Search plan generated with warnings:\n\n" + "\n".join(warnings),
            )

    def _default_questions(self, payload: Dict[str, Any]) -> List[str]:
        target = payload.get("target", "target")
        target_type = payload.get("target_type", "unknown")

        base = [
            f"What is the verified public identity of {target}?",
            f"Which official identifiers are publicly associated with {target}?",
            f"What public sources mention {target}?",
            f"What historical public records exist for {target}?",
            f"What contradictions exist across public sources about {target}?",
            f"What information is missing to answer the objective?",
        ]

        if target_type == "company":
            base.extend(
                [
                    "What is the legal entity name and registration identifier?",
                    "Who are publicly disclosed directors, officers, or agents?",
                    "Which domains, filings, procurement records, or sanctions entries are linked?",
                ]
            )

        elif target_type == "domain":
            base.extend(
                [
                    "What is the current registration status?",
                    "Which DNS records are publicly observable?",
                    "Which certificates have been publicly issued?",
                    "What archived versions exist?",
                ]
            )

        elif target_type == "ip":
            base.extend(
                [
                    "What ASN and public routing context is associated?",
                    "Which domains or certificates publicly resolve to this IP?",
                    "Are there public advisories or threat reports referencing this IP?",
                ]
            )

        elif target_type == "person":
            base.extend(
                [
                    "Which public professional profiles are associated?",
                    "Which public mentions exist in news, filings, or organizational pages?",
                    "Are there same-name collision risks?",
                ]
            )

        return base

    def _build_search_plan(self, payload: Dict[str, Any]) -> List[Dict[str, Any]]:
        questions = payload.get("questions") or self._default_questions(payload)
        target = payload.get("target", "")
        target_type = payload.get("target_type", "unknown")

        plan: List[Dict[str, Any]] = []
        priority = 1

        for question in questions:
            families = self._query_families_for_target(target_type, str(question))

            for query_family, provider, source_type, purpose in families:
                query = self._compile_query(query_family, payload, str(question))

                plan.append(
                    {
                        "question": question,
                        "query_family": query_family,
                        "query": query,
                        "provider": provider,
                        "source_type": source_type,
                        "purpose": purpose,
                        "priority": priority,
                        "expected_information_value": self._estimate_information_value(
                            query_family,
                            target_type,
                        ),
                        "estimated_cost": self._estimate_cost(query_family, provider),
                        "authorization_status": "ALLOWED_PUBLIC_OR_AUTHORIZED",
                        "policy_risk": "LOW_IF_PASSIVE_PUBLIC",
                        "execution_status": "NOT_EXECUTED_PLANNING_ONLY",
                    }
                )

                priority += 1

        return plan

    def _query_families_for_target(
        self,
        target_type: str,
        question: str,
    ) -> List[tuple]:
        target_type = (target_type or "").lower()

        common = [
            (
                "web_search",
                "configured_public_search_api",
                "public_website",
                "general public discovery",
            ),
            (
                "news_search",
                "configured_news_api",
                "news_source",
                "recent public reporting",
            ),
            (
                "archive_search",
                "configured_archive_api",
                "public_archive",
                "historical public snapshots",
            ),
            (
                "document_search",
                "configured_public_document_api",
                "public_document",
                "filings, reports, PDFs, and public documents",
            ),
        ]

        mapping: Dict[str, List[tuple]] = {
            "company": [
                (
                    "registry_search",
                    "configured_corporate_registry_api",
                    "public_corporate_registry",
                    "legal entity, registration number, status, officers",
                ),
                (
                    "public_company_research",
                    "configured_company_data_api",
                    "public_company_profile",
                    "corporate hierarchy, historical names, filings",
                ),
                (
                    "sanctions_search",
                    "configured_sanctions_api",
                    "public_sanctions_list",
                    "sanctions, watchlists, restricted party screening",
                ),
                (
                    "procurement_search",
                    "configured_procurement_api",
                    "public_procurement_portal",
                    "tenders, contracts, supplier records",
                ),
                (
                    "legal_search",
                    "configured_court_records_api",
                    "public_court_regulatory_record",
                    "litigation, regulatory actions, judgments",
                ),
            ],
            "domain": [
                (
                    "domain_research",
                    "configured_domain_api",
                    "public_domain_data",
                    "registration context, historical domain signals",
                ),
                (
                    "dns_context",
                    "configured_dns_api",
                    "public_dns",
                    "current and historical DNS records",
                ),
                (
                    "rdap_context",
                    "configured_rdap_api",
                    "public_rdap",
                    "registration data where lawfully available",
                ),
                (
                    "cert_context",
                    "configured_certificate_transparency_api",
                    "public_certificate_transparency",
                    "issued certificates and subject alternative names",
                ),
            ],
            "ip": [
                (
                    "ip_context",
                    "configured_ip_intel_api",
                    "public_ip_intelligence",
                    "public IP attribution and hosting context",
                ),
                (
                    "asn_context",
                    "configured_asn_api",
                    "public_asn_data",
                    "autonomous system and organization context",
                ),
                (
                    "bgp_context",
                    "configured_bgp_api",
                    "public_bgp_data",
                    "routing announcements and prefix context",
                ),
                (
                    "cert_context",
                    "configured_certificate_transparency_api",
                    "public_certificate_transparency",
                    "certificates associated with IP or infrastructure",
                ),
            ],
            "asn": [
                (
                    "asn_context",
                    "configured_asn_api",
                    "public_asn_data",
                    "ASN organization, prefixes, registration context",
                ),
                (
                    "bgp_context",
                    "configured_bgp_api",
                    "public_bgp_data",
                    "routing and prefix propagation context",
                ),
                (
                    "ip_context",
                    "configured_ip_intel_api",
                    "public_ip_intelligence",
                    "associated public IP ranges and hosting signals",
                ),
            ],
            "person": [
                (
                    "public_person_research",
                    "configured_public_profile_api",
                    "public_professional_profile",
                    "public biographical and professional context",
                ),
                (
                    "username_research",
                    "configured_username_search_api",
                    "public_account_directory",
                    "username reuse across public platforms",
                ),
                (
                    "public_social_search",
                    "configured_public_social_api",
                    "public_social_media",
                    "public posts, profiles, and mentions",
                ),
                (
                    "news_search",
                    "configured_news_api",
                    "news_source",
                    "public reporting and mentions",
                ),
            ],
            "username": [
                (
                    "username_research",
                    "configured_username_search_api",
                    "public_account_directory",
                    "platform presence and username collisions",
                ),
                (
                    "public_social_search",
                    "configured_public_social_api",
                    "public_social_media",
                    "public posts and account context",
                ),
                (
                    "github_search",
                    "configured_github_api",
                    "public_repository",
                    "public code, commits, issues, and profile metadata",
                ),
            ],
            "repository": [
                (
                    "github_search",
                    "configured_github_api",
                    "public_repository",
                    "repository metadata, commits, releases, issues",
                ),
                (
                    "package_registry_search",
                    "configured_package_registry_api",
                    "public_package_registry",
                    "published packages and dependency metadata",
                ),
                (
                    "code_search",
                    "configured_code_search_api",
                    "public_code_index",
                    "public code references and identifiers",
                ),
            ],
            "document": [
                (
                    "document_search",
                    "configured_public_document_api",
                    "public_document",
                    "document text, metadata, references",
                ),
                (
                    "metadata_analysis",
                    "configured_metadata_parser",
                    "document_metadata",
                    "author, timestamps, embedded links, anomalies",
                ),
                (
                    "archive_search",
                    "configured_archive_api",
                    "public_archive",
                    "historical document versions",
                ),
            ],
            "malware": [
                (
                    "ioc_search",
                    "configured_cti_api",
                    "public_threat_intelligence",
                    "hashes, domains, IPs, URLs, YARA, behavioral indicators",
                ),
                (
                    "vuln_search",
                    "configured_vulnerability_api",
                    "public_vulnerability_catalog",
                    "CVE, advisory, exploit context",
                ),
                (
                    "repository_search",
                    "configured_github_api",
                    "public_repository",
                    "public malware research, samples, analysis notes",
                ),
            ],
            "wallet": [
                (
                    "blockchain_search",
                    "configured_blockchain_api",
                    "public_blockchain_data",
                    "addresses, transactions, balances, clustering signals",
                ),
                (
                    "public_forum_search",
                    "configured_forum_search_api",
                    "public_forum",
                    "public discussion and attribution claims",
                ),
                (
                    "news_search",
                    "configured_news_api",
                    "news_source",
                    "reported wallet activity or sanctions context",
                ),
            ],
            "location": [
                (
                    "geospatial_context",
                    "configured_geospatial_api",
                    "public_map_geospatial",
                    "coordinates, landmarks, administrative context",
                ),
                (
                    "map_search",
                    "configured_map_api",
                    "public_map",
                    "visual and geographic correlation",
                ),
                (
                    "event_search",
                    "configured_event_api",
                    "public_event_source",
                    "events occurring at or near location",
                ),
            ],
            "event": [
                (
                    "event_search",
                    "configured_event_api",
                    "public_event_source",
                    "timelines, participants, locations, outcomes",
                ),
                (
                    "news_search",
                    "configured_news_api",
                    "news_source",
                    "contemporaneous reporting",
                ),
                (
                    "archive_search",
                    "configured_archive_api",
                    "public_archive",
                    "historical event records",
                ),
            ],
        }

        return mapping.get(target_type, []) + common

    def _compile_query(
        self,
        query_family: str,
        payload: Dict[str, Any],
        question: str,
    ) -> str:
        target = payload.get("target", "").strip()
        objective = payload.get("objective", "").strip()
        jurisdiction = payload.get("jurisdiction", "").strip()

        question = question.strip()

        if query_family == "web_search":
            return f"{target} {question}"

        if query_family == "news_search":
            return f"{target} {question} news"

        if query_family == "archive_search":
            return f"{target} {question} archive OR wayback OR historical"

        if query_family == "document_search":
            return f"{target} {question} filetype:pdf OR filetype:doc OR filetype:xls"

        if query_family == "registry_search":
            return f"{target} company registry OR incorporation OR filing {jurisdiction}"

        if query_family == "public_company_research":
            return f"{target} corporate profile OR directors OR officers OR subsidiaries"

        if query_family == "sanctions_search":
            return f"{target} sanctions OR watchlist OR restricted party"

        if query_family == "procurement_search":
            return f"{target} tender OR contract OR procurement OR supplier"

        if query_family == "legal_search":
            return f"{target} court OR judgment OR regulatory OR enforcement {jurisdiction}"

        if query_family == "domain_research":
            return f"{target} domain registration OR DNS OR certificate OR archived site"

        if query_family == "dns_context":
            return f"{target} DNS records A AAAA MX TXT CNAME"

        if query_family == "rdap_context":
            return f"{target} RDAP registration status nameservers"

        if query_family == "cert_context":
            return f"{target} certificate transparency SSL certificate SAN"

        if query_family == "ip_context":
            return f"{target} IP hosting reverse DNS ASN public intel"

        if query_family == "asn_context":
            return f"{target} ASN organization prefix registry"

        if query_family == "bgp_context":
            return f"{target} BGP prefix routing announcement"

        if query_family == "public_person_research":
            return f"{target} public profile biography organization role"

        if query_family == "username_research":
            return f"{target} username profile social code repository"

        if query_family == "public_social_search":
            return f"{target} public post profile mention"

        if query_family == "github_search":
            return f"{target} github repository commit issue release"

        if query_family == "package_registry_search":
            return f"{target} npm pypi package registry maintainer"

        if query_family == "code_search":
            return f"{target} code reference public repository"

        if query_family == "metadata_analysis":
            return f"{target} document metadata author created modified embedded link"

        if query_family == "ioc_search":
            return f"{target} IOC hash domain URL malware indicator"

        if query_family == "vuln_search":
            return f"{target} CVE vulnerability advisory exploit"

        if query_family == "blockchain_search":
            return f"{target} wallet address transaction blockchain explorer"

        if query_family == "geospatial_context":
            return f"{target} location coordinates map landmark"

        if query_family == "map_search":
            return f"{target} satellite map street view geographic context"

        if query_family == "event_search":
            return f"{target} event timeline participants location outcome"

        if query_family == "public_forum_search":
            return f"{target} forum discussion thread public post"

        return f"{target} {question} {objective}".strip()

    def _estimate_information_value(
        self,
        query_family: str,
        target_type: str,
    ) -> str:
        high_value = {
            "registry_search",
            "legal_search",
            "sanctions_search",
            "domain_research",
            "dns_context",
            "cert_context",
            "ip_context",
            "asn_context",
            "blockchain_search",
            "ioc_search",
            "document_search",
        }

        medium_value = {
            "public_company_research",
            "procurement_search",
            "rdap_context",
            "bgp_context",
            "public_person_research",
            "username_research",
            "github_search",
            "package_registry_search",
            "vuln_search",
            "geospatial_context",
            "event_search",
        }

        if query_family in high_value:
            return "HIGH"

        if query_family in medium_value:
            return "MEDIUM"

        return "LOW_TO_MEDIUM"

    def _estimate_cost(self, query_family: str, provider: str) -> str:
        if "configured" in provider:
            return "CONFIG_DEPENDENT"

        if query_family in {"web_search", "news_search", "archive_search"}:
            return "LOW"

        return "MEDIUM"

    def _fact_gate_criteria(self) -> List[Dict[str, str]]:
        return [
            {
                "check": "evidence_present",
                "description": "A retrievable evidence object must exist for the claim.",
            },
            {
                "check": "source_identifiable",
                "description": "The source URL, publisher, dataset, or artifact must be identifiable.",
            },
            {
                "check": "entity_resolved",
                "description": "The entity referenced must be resolved with acceptable confidence.",
            },
            {
                "check": "temporal_context_valid",
                "description": "Event time, publication time, observation time, and retrieval time must be distinguished.",
            },
            {
                "check": "source_reliability_evaluated",
                "description": "Authority, primary/secondary status, methodology, and freshness must be assessed.",
            },
            {
                "check": "source_bias_evaluated",
                "description": "Commercial, institutional, advocacy, adversarial, promotional, or linguistic bias must be noted.",
            },
            {
                "check": "source_independence_known",
                "description": "Copied, syndicated, mirrored, or derived sources must not be counted as independent corroboration.",
            },
            {
                "check": "contradiction_checked",
                "description": "Conflicting evidence must be searched for and recorded.",
            },
        ]

    def _evidence_schema(self) -> Dict[str, str]:
        return {
            "evidence_id": "Unique evidence identifier",
            "case_id": "Case identifier",
            "task_id": "Task identifier",
            "source_id": "Source identifier",
            "url": "Source URL or artifact locator",
            "retrieved_at": "UTC retrieval timestamp",
            "content_hash": "Hash of preserved content",
            "raw_artifact_reference": "Path or object storage reference",
            "content_type": "HTML, PDF, JSON, image, text, etc.",
            "acquisition_method": "public_search, archive_api, uploaded_file, authorized_dataset, etc.",
            "parser_version": "Parser or connector version",
            "connector_version": "Connector version",
            "metadata": "Additional source metadata",
            "redactions": "List of redacted fields and reasons",
        }

    def _observation_schema(self) -> Dict[str, str]:
        return {
            "observation_id": "Unique observation identifier",
            "statement": "Explicit statement found in evidence",
            "evidence_id": "Evidence supporting the observation",
            "source_id": "Source identifier",
            "observed_at": "Timestamp when observation was made",
            "event_time": "Time of the described event, if known",
            "published_at": "Publication time, if known",
            "extraction_method": "manual, parser, LLM extraction, regex, etc.",
            "limitations": "Known limitations of the observation",
        }

    def _source_assessment_schema(self) -> Dict[str, str]:
        return {
            "source_id": "Source identifier",
            "source_name": "Human-readable source name",
            "source_type": "registry, news, archive, social, government, corporate, etc.",
            "authority": "VERY_HIGH, HIGH, MODERATE, LOW, VERY_LOW, UNKNOWN",
            "primary_or_secondary": "primary, secondary, tertiary, unknown",
            "proximity_to_event": "direct, near, indirect, unknown",
            "methodology": "How the source produces information",
            "transparency": "Whether methods, corrections, and ownership are clear",
            "freshness": "Current, recent, stale, unknown",
            "historical_consistency": "Consistent, inconsistent, unknown",
            "corroboration": "Independent corroboration status",
            "bias": "First-party, commercial, advocacy, institutional, adversarial, promotional, etc.",
            "independence": "INDEPENDENT, PARTIALLY_DEPENDENT, DEPENDENT, UNKNOWN",
        }

    def _contradiction_schema(self) -> Dict[str, str]:
        return {
            "contradiction_id": "Unique contradiction identifier",
            "claim_a": "First conflicting claim",
            "claim_b": "Second conflicting claim",
            "sources": "Sources for each claim",
            "evidence_ids": "Evidence identifiers",
            "type": "ownership, employment, address, status, date, attribution, entity mismatch, etc.",
            "temporal_explanation": "Whether contradiction is explained by time",
            "entity_mismatch_possibility": "Whether different entities may be confused",
            "resolution_status": "UNRESOLVED, RESOLVED, DISPUTED, INCONCLUSIVE",
        }

    def _knowledge_gap_schema(self) -> Dict[str, str]:
        return {
            "gap_id": "Unique gap identifier",
            "question": "Intelligence question affected",
            "missing_evidence": "What evidence is missing",
            "likely_source": "Source type that could fill the gap",
            "specialist_owner": "Employee or specialist responsible",
            "priority": "HIGH, MEDIUM, LOW",
            "expected_information_value": "Expected value if filled",
            "policy_boundary": "Any authorization or privacy constraint",
        }

    def _stop_conditions(self) -> List[str]:
        return [
            "OBJECTIVE_SATISFIED",
            "SUFFICIENT_VERIFICATION",
            "SOURCES_EXHAUSTED",
            "LOW_EXPECTED_INFORMATION_VALUE",
            "BUDGET_EXHAUSTED",
            "TIME_EXHAUSTED",
            "AUTHORIZATION_BOUNDARY",
            "RATE_LIMIT_BOUNDARY",
            "POLICY_BLOCK",
            "HUMAN_REVIEW_REQUIRED",
            "SYSTEM_FAILURE",
            "CANCELLED",
        ]

    def _specialist_handoffs(self, payload: Dict[str, Any]) -> List[Dict[str, str]]:
        target_type = (payload.get("target_type") or "").lower()
        handoffs: List[Dict[str, str]] = []

        if target_type in {"domain", "ip", "asn", "infrastructure_cluster"}:
            handoffs.append(
                {
                    "specialist": "Infrastructure Employee",
                    "reason": "Deeper passive DNS, RDAP, certificate transparency, ASN/BGP, and hosting context required.",
                    "expected_output": "Infrastructure graph, temporal DNS changes, certificate lineage, ASN relationships.",
                }
            )

        if target_type in {"malware", "campaign", "threat_actor", "ioc"}:
            handoffs.append(
                {
                    "specialist": "Malware / CTI Employee",
                    "reason": "IOC enrichment, sandbox context, YARA, CVE, campaign clustering, and threat-intel correlation required.",
                    "expected_output": "IOC dossier, campaign timeline, malware family linkage, defensive recommendations.",
                }
            )

        if target_type in {"location", "event", "geospatial_cluster"}:
            handoffs.append(
                {
                    "specialist": "GEOINT Employee",
                    "reason": "Map imagery, geolocation, landmark correlation, and spatial-temporal analysis required.",
                    "expected_output": "Geospatial observations, confidence levels, coordinate provenance, visual corroboration.",
                }
            )

        if target_type in {"company", "organization", "sanctions_entity", "procurement_record"}:
            handoffs.append(
                {
                    "specialist": "Corporate Employee",
                    "reason": "Registry filings, beneficial ownership where public, corporate hierarchy, and historical names required.",
                    "expected_output": "Entity resolution memo, filing citations, ownership graph, status timeline.",
                }
            )

        if target_type in {"regulatory_matter", "legal_filing", "court_record"}:
            handoffs.append(
                {
                    "specialist": "LEGALINT Employee",
                    "reason": "Court records, regulatory filings, case status, and jurisdiction-specific interpretation required.",
                    "expected_output": "Legal record summary, docket timeline, party roles, jurisdictional caveats.",
                }
            )

        if target_type in {"wallet", "transaction", "crypto_asset"}:
            handoffs.append(
                {
                    "specialist": "CRYPTOINT Employee",
                    "reason": "Blockchain clustering, transaction graph, exchange attribution, and public ledger analysis required.",
                    "expected_output": "Wallet cluster report, transaction timeline, attribution confidence, sanctions overlap.",
                }
            )

        if target_type in {"document", "media", "image", "video", "audio"}:
            handoffs.append(
                {
                    "specialist": "Media / Document Employee",
                    "reason": "Metadata, OCR, transcript, visual verification, and document lineage analysis required.",
                    "expected_output": "Document/media evidence pack, metadata findings, authenticity caveats.",
                }
            )

        if not handoffs:
            handoffs.append(
                {
                    "specialist": "OSINT Manager",
                    "reason": "No specialized handoff triggered from target type alone.",
                    "expected_output": "Review plan, approve connectors, assign follow-up tasks.",
                }
            )

        return handoffs

    def _next_best_action(self, payload: Dict[str, Any]) -> Dict[str, str]:
        target = payload.get("target", "target")
        target_type = payload.get("target_type", "unknown")

        return {
            "action": "Review generated search plan, confirm authorization, then configure only permitted public/authorized connectors.",
            "reason": (
                "Live collection should begin only after scope, jurisdiction, privacy rules, "
                "and source authorization are confirmed by the OSINT Manager."
            ),
            "owner": "OSINT Manager",
            "expected_output": (
                "Approved connector list, prioritized query batch, evidence capture schema, "
                "and fact-gate thresholds for the next collection wave."
            ),
            "policy_note": (
                f"Do not execute private, credentialed, illicit, or active-scanning queries for {target} "
                f"under {target_type} without separate authorization."
            ),
        }

    def export_task_json(self) -> None:
        payload = self.collect_payload()

        path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            initialfile=f"{payload.get('case_id', 'case')}_{payload.get('task_id', 'task')}.json",
        )

        if not path:
            return

        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(payload, f, ensure_ascii=False, indent=2)

            messagebox.showinfo("Export Complete", f"Task JSON saved to:\n{path}")
        except Exception as exc:
            messagebox.showerror("Export Failed", str(exc))

    def copy_output(self) -> None:
        text = self.output.get("1.0", "end-1c").strip()

        if not text:
            messagebox.showinfo("Copy Output", "No output to copy.")
            return

        self.clipboard_clear()
        self.clipboard_append(text)
        messagebox.showinfo("Copy Output", "Output copied to clipboard.")

    def clear_form(self) -> None:
        confirm = messagebox.askyesno(
            "Clear Form",
            "Are you sure you want to clear all fields and reset defaults?",
        )

        if not confirm:
            return

        self._set_defaults()
        self.output.delete("1.0", "end")


if __name__ == "__main__":
    app = TraceAtlasOSINTPanel()
    app.mainloop()