import tkinter as tk
from tkinter import ttk, filedialog, messagebox

if __package__:
    from . import _support
else:
    import _support
import json
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple


APP_TITLE = "TraceAtlas SOCMINT AI Employee — Planning Panel"
APP_VERSION = "TraceAtlas SOCMINT Panel v0.1"


FIELDS = [
    ("case_id", "Case ID", "entry"),
    ("task_id", "Task ID", "entry"),
    ("objective", "Objective", "text"),
    ("target", "Target", "entry"),
    ("target_type", "Target Type", "combo"),
    ("platforms", "Preferred Public Platforms", "text"),
    ("questions", "Intelligence Questions", "text"),
    ("known_usernames", "Known Usernames", "text"),
    ("known_accounts", "Known Public Accounts / Handles", "text"),
    ("known_aliases", "Known Aliases / Display Names", "text"),
    ("known_domains", "Known Domains", "text"),
    ("known_urls", "Known URLs", "text"),
    ("known_hashtags", "Known Hashtags", "text"),
    ("time_range", "Time Range", "text"),
    ("jurisdiction", "Jurisdiction", "entry"),
    ("scope", "Scope / Allowed Sources", "text"),
    ("authorization", "Authorization Basis", "text"),
    ("source_limits", "Source Limits / Rate Limits", "text"),
    ("budget", "Budget", "entry"),
    ("deadline", "Deadline", "entry"),
    ("available_evidence", "Available Evidence / Public Posts / Exports", "text"),
    ("configured_connectors", "Configured Connectors / APIs", "text"),
]


TARGET_TYPES = [
    "person",
    "organization",
    "company",
    "brand",
    "username",
    "alias",
    "public_account",
    "topic",
    "hashtag",
    "event",
    "campaign",
    "domain",
    "url",
    "repository",
    "malware_campaign",
    "threat_actor_label",
    "location",
    "public_community",
    "unknown",
]


DEFAULT_PLATFORMS = [
    "X/Twitter",
    "Reddit",
    "Telegram",
    "GitHub",
    "YouTube",
    "LinkedIn-visible",
    "Facebook-visible",
    "Instagram-visible",
    "TikTok-visible",
    "Mastodon/Fediverse",
    "public forums",
    "public blogs",
    "public web index",
]


LIST_FIELDS = {
    "platforms",
    "questions",
    "known_usernames",
    "known_accounts",
    "known_aliases",
    "known_domains",
    "known_urls",
    "known_hashtags",
    "source_limits",
    "available_evidence",
    "configured_connectors",
}


DICT_FIELDS = {
    "scope",
    "authorization",
    "time_range",
}


POLICY_BLOCK_PATTERNS = [
    r"\bprivate account\b",
    r"\bprivate group\b",
    r"\brestricted group\b",
    r"\blogin\b",
    r"\bpassword\b",
    r"\bcredential",
    r"\bstolen token\b",
    r"\bstolen cookie",
    r"\bleaked session",
    r"\bsession hijack",
    r"\bbypass captcha\b",
    r"\bcaptcha bypass\b",
    r"\bbypass paywall\b",
    r"\bscrap behind login\b",
    r"\bscrape private\b",
    r"\bhack\b",
    r"\bhacked\b",
    r"\bexploit account\b",
    r"\bcontact (the )?target\b",
    r"\bmessage (the )?target\b",
    r"\bfriend request\b",
    r"\bfollow request\b",
    r"\bimpersonat",
    r"\bfake account\b",
    r"\bdeceptive account\b",
    r"\bcovert\b",
    r"\bsurveil",
    r"\btrack live location\b",
    r"\bprecise location\b",
    r"\bhome address\b",
    r"\bresidential address\b",
    r"\bidentify .* from face",
    r"\bfacial recognition\b",
    r"\bbiometric identification\b",
    r"\binfer religion\b",
    r"\binfer political\b",
    r"\binfer sexual orientation\b",
    r"\binfer medical condition\b",
    r"\binfer ethnicity\b",
    r"\bmental condition\b",
    r"\bis depressed\b",
    r"\bis dangerous\b",
    r"\bis mentally unstable\b",
]


SAFE_ALTERNATIVES = [
    "Use only publicly accessible posts/profiles where lawful and permitted.",
    "Use authorized platform APIs or customer-provided exports.",
    "Use public archives for historically public content only.",
    "Use official corporate, legal, sanctions, or registry sources for affiliation verification.",
    "Use passive infrastructure sources for domains/IPs/URLs referenced publicly.",
    "Hand off image/video geolocation to GEOINT/IMINT/VIDINT instead of inferring private location.",
    "Hand off malware/IOC artifacts to MALWAREINT/CTI instead of executing or interacting.",
    "Keep identity matches as candidates unless multi-signal evidence supports them.",
]


def parse_list(value: str) -> List[Any]:
    value = value.strip()
    if not value:
        return []

    try:
        parsed = json.loads(value)
        if isinstance(parsed, list):
            return parsed
        if isinstance(parsed, dict):
            return [parsed]
    except Exception:
        pass

    normalized = value.replace(",", "\n")
    parts = [p.strip() for p in normalized.splitlines()]
    return [p for p in parts if p]


def parse_dict(value: str) -> Dict[str, Any]:
    value = value.strip()
    if not value:
        return {}

    try:
        parsed = json.loads(value)
        if isinstance(parsed, dict):
            return parsed
    except Exception:
        pass

    result: Dict[str, Any] = {}
    for line in value.splitlines():
        line = line.strip()
        if not line or ":" not in line:
            continue
        key, val = line.split(":", 1)
        result[key.strip()] = val.strip()
    return result


def normalize_text(value: str) -> str:
    return re.sub(r"\s+", " ", value or "").strip().lower()


def truncate_list(items: List[Any], limit: int) -> Tuple[List[Any], bool]:
    if len(items) <= limit:
        return items, False
    return items[:limit], True


class TraceAtlasSOCMINTPanel(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("1320x900")
        self.minsize(1050, 720)

        self.entries: Dict[str, Any] = {}
        self.last_result: Dict[str, Any] = {}

        self._configure_style()
        self._build_ui()
        self._set_defaults()

    def _configure_style(self) -> None:
        style = ttk.Style(self)

        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        self.configure(bg="#0b1020")

        style.configure("TFrame", background="#0b1020")
        style.configure("TLabel", background="#0b1020", foreground="#e5e7eb", font=("Segoe UI", 10))
        style.configure(
            "Header.TLabel",
            background="#0b1020",
            foreground="#22d3ee",
            font=("Segoe UI", 17, "bold"),
        )
        style.configure(
            "Subheader.TLabel",
            background="#0b1020",
            foreground="#94a3b8",
            font=("Segoe UI", 9),
        )
        style.configure("TNotebook", background="#0b1020", borderwidth=0)
        style.configure("TNotebook.Tab", padding=[14, 7], font=("Segoe UI", 10, "bold"))

        style.configure(
            "TEntry",
            fieldbackground="#111827",
            foreground="#e5e7eb",
            insertcolor="#ffffff",
            bordercolor="#334155",
            lightcolor="#334155",
            darkcolor="#334155",
        )

        style.configure(
            "TCombobox",
            fieldbackground="#111827",
            foreground="#e5e7eb",
            arrowcolor="#e5e7eb",
            bordercolor="#334155",
            lightcolor="#334155",
            darkcolor="#334155",
        )

        style.configure(
            "TButton",
            padding=7,
            font=("Segoe UI", 10, "bold"),
            background="#1f2937",
            foreground="#e5e7eb",
            bordercolor="#475569",
            lightcolor="#475569",
            darkcolor="#475569",
        )

        style.map(
            "TButton",
            background=[("active", "#334155")],
            foreground=[("active", "#ffffff")],
        )

        style.configure(
            "Vertical.TScrollbar",
            background="#1f2937",
            troughcolor="#0b1020",
            arrowcolor="#e5e7eb",
        )

    def _build_ui(self) -> None:
        header = ttk.Frame(self)
        header.pack(fill="x", padx=16, pady=(14, 8))

        ttk.Label(header, text="TraceAtlas SOCMINT AI Employee", style="Header.TLabel").pack(anchor="w")

        ttk.Label(
            header,
            text=(
                "Public / authorized social intelligence only • Planning-only unless safe connectors are configured • "
                "No private accounts • No credentials • No CAPTCHA bypass • No covert contact • No sensitive profiling"
            ),
            style="Subheader.TLabel",
            wraplength=1200,
            justify="left",
        ).pack(anchor="w", pady=(2, 0))

        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=16, pady=(8, 16))

        self.input_tab = ttk.Frame(self.notebook)
        self.output_tab = ttk.Frame(self.notebook)

        self.notebook.add(self.input_tab, text="SOCMINT Task Input")
        self.notebook.add(self.output_tab, text="Output / SOCMINT Plan")

        self._build_input_tab()
        self._build_output_tab()

    def _build_input_tab(self) -> None:
        container = ttk.Frame(self.input_tab)
        container.pack(fill="both", expand=True)

        self.canvas = tk.Canvas(container, bg="#0b1020", highlightthickness=0)
        scrollbar = ttk.Scrollbar(container, orient="vertical", command=self.canvas.yview)
        self.form = ttk.Frame(self.canvas)

        self.form.bind("<Configure>", lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self.canvas_window = self.canvas.create_window((0, 0), window=self.form, anchor="nw")
        self.canvas.configure(yscrollcommand=scrollbar.set)

        self.canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        row = 0

        for key, label, kind in FIELDS:
            ttk.Label(self.form, text=label).grid(row=row, column=0, sticky="nw", padx=10, pady=6)

            if kind == "entry":
                widget = ttk.Entry(self.form, width=96)

            elif kind == "combo":
                widget = ttk.Combobox(
                    self.form,
                    values=TARGET_TYPES if key == "target_type" else [],
                    width=94,
                    state="readonly",
                )

            else:
                widget = tk.Text(
                    self.form,
                    height=3,
                    width=96,
                    bg="#111827",
                    fg="#e5e7eb",
                    insertbackground="white",
                    relief="flat",
                    highlightthickness=1,
                    highlightbackground="#334155",
                    font=("Segoe UI", 10),
                    wrap="word",
                )

            widget.grid(row=row, column=1, sticky="ew", padx=10, pady=6)
            self.entries[key] = widget
            row += 1

        self.form.columnconfigure(1, weight=1)

        buttons = ttk.Frame(self.input_tab)
        buttons.pack(fill="x", padx=10, pady=12)

        ttk.Button(buttons, text="Run Policy Screen", command=self.run_policy_screen).pack(side="left", padx=4)
        ttk.Button(buttons, text="Generate SOCMINT Plan", command=self.generate_plan).pack(side="left", padx=4)
        ttk.Button(buttons, text="Export JSON", command=self.export_json).pack(side="left", padx=4)
        ttk.Button(buttons, text="Copy Output", command=self.copy_output).pack(side="left", padx=4)
        ttk.Button(buttons, text="Clear Form", command=self.clear_form).pack(side="left", padx=4)

    def _build_output_tab(self) -> None:
        container = ttk.Frame(self.output_tab)
        container.pack(fill="both", expand=True)

        self.output = tk.Text(
            container,
            wrap="word",
            bg="#020617",
            fg="#bbf7d0",
            insertbackground="white",
            relief="flat",
            highlightthickness=1,
            highlightbackground="#334155",
            font=("Consolas", 11),
        )

        output_scroll = ttk.Scrollbar(container, orient="vertical", command=self.output.yview)
        self.output.configure(yscrollcommand=output_scroll.set)

        self.output.pack(side="left", fill="both", expand=True)
        output_scroll.pack(side="right", fill="y")

    def _set_defaults(self) -> None:
        self.set_widget_value("case_id", "SOCMINT-CASE-001")
        self.set_widget_value("task_id", "SOCMINT-TASK-001")
        self.set_widget_value(
            "objective",
            "Identify publicly available or explicitly authorized social-media information relevant to the target "
            "and produce an evidence-backed SOCMINT search plan.",
        )
        self.set_widget_value("target", "")
        self.set_widget_value("target_type", "organization")
        self.set_widget_value("platforms", "\n".join(DEFAULT_PLATFORMS[:8]))
        self.set_widget_value(
            "questions",
            "Which public accounts are plausibly associated with the target?\n"
            "Which public posts mention the target, domain, URL, hashtag, or event?\n"
            "What public affiliation claims exist?\n"
            "Which relationships are explicitly visible and evidence-backed?\n"
            "Which content is historical versus current?\n"
            "Which claims depend on the same upstream source?\n"
            "What contradictions exist across public social sources?\n"
            "What information is missing and which specialist should investigate next?",
        )
        self.set_widget_value("known_usernames", "")
        self.set_widget_value("known_accounts", "")
        self.set_widget_value("known_aliases", "")
        self.set_widget_value("known_domains", "")
        self.set_widget_value("known_urls", "")
        self.set_widget_value("known_hashtags", "")
        self.set_widget_value(
            "time_range",
            json.dumps({"from": "", "to": "", "timezone": "UTC"}, indent=2),
        )
        self.set_widget_value("jurisdiction", "")
        self.set_widget_value(
            "scope",
            json.dumps(
                {
                    "allowed_source_types": [
                        "publicly accessible social-media content",
                        "authorized platform/API data",
                        "authorized exports",
                        "customer-provided social-media records",
                        "public channels/groups where permitted",
                        "public comments/replies",
                        "public profile metadata",
                        "public posts",
                        "public media",
                        "public usernames",
                        "public URLs",
                        "public hashtags",
                        "public mentions",
                        "public follower/following data only where genuinely exposed and permitted",
                    ],
                    "prohibited_sources": [
                        "private accounts",
                        "restricted/private groups without authorization",
                        "stolen cookies",
                        "stolen tokens",
                        "leaked sessions",
                        "credentials",
                        "illegal data markets",
                        "covert surveillance tools",
                        "CAPTCHA bypass",
                        "login bypass",
                        "paywall bypass",
                    ],
                    "data_minimization_rules": [
                        "collect only objective-relevant public social data",
                        "avoid unnecessary personal data",
                        "do not infer sensitive traits from weak signals",
                        "do not infer precise live location of private individuals",
                        "redact incidental secrets or private data",
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
                    "authorized_by": "",
                    "authorization_basis": "",
                    "permitted_actions": [
                        "public profile search",
                        "public post search",
                        "public channel search",
                        "public hashtag search",
                        "authorized API search",
                        "authorized export analysis",
                        "public archive review where permitted",
                    ],
                    "prohibited_actions": [
                        "private account access",
                        "credential use",
                        "session reuse",
                        "social engineering",
                        "subject contact",
                        "impersonation",
                        "deceptive account creation",
                        "covert tracking",
                        "active platform abuse",
                    ],
                },
                indent=2,
            ),
        )
        self.set_widget_value("source_limits", "")
        self.set_widget_value("budget", "")
        self.set_widget_value("deadline", "")
        self.set_widget_value("available_evidence", "")
        self.set_widget_value(
            "configured_connectors",
            "None configured. Output is planning-only unless safe public/authorized connectors are added.",
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

        for key, _, _ in FIELDS:
            raw = self.get_widget_value(key)

            if key in LIST_FIELDS:
                payload[key] = parse_list(raw)
            elif key in DICT_FIELDS:
                payload[key] = parse_dict(raw)
            else:
                payload[key] = raw

        payload["generated_at"] = datetime.now(timezone.utc).isoformat()
        payload["panel_version"] = APP_VERSION
        payload["operating_mode"] = "PLANNING_ONLY"
        payload["source_boundary"] = "PUBLIC_OR_AUTHORIZED_SOCIAL_ONLY"
        return payload

    def validate_payload(self, payload: Dict[str, Any]) -> List[str]:
        warnings: List[str] = []

        required = ["case_id", "task_id", "objective", "target", "target_type"]
        for field in required:
            if not payload.get(field):
                warnings.append(f"Missing required field: {field}")

        if not payload.get("questions"):
            warnings.append("No intelligence questions provided. Default SOCMINT questions will be inferred.")

        if not payload.get("platforms"):
            warnings.append("No preferred platforms provided. Platform selection will be inferred from target type.")

        if not _support.has_authorization(payload.get("authorization")):
            warnings.append("No authorization basis provided. Treat as policy-limited planning only.")

        if not payload.get("scope"):
            warnings.append("No scope provided. Default public/authorized-only assumptions applied.")

        time_range = payload.get("time_range", {})
        if isinstance(time_range, dict):
            if not time_range.get("from") and not time_range.get("to"):
                warnings.append("No time range provided. Temporal analysis may be incomplete.")

        return warnings

    def policy_screen(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        scanned_text = " ".join(
            [
                str(payload.get("objective", "")),
                " ".join(str(q) for q in payload.get("questions", [])),
                str(payload.get("target", "")),
            ]
        ).lower()

        blocked_reasons: List[str] = []

        for pattern in POLICY_BLOCK_PATTERNS:
            if re.search(pattern, scanned_text):
                blocked_reasons.append(pattern)

        target_type = str(payload.get("target_type", "")).lower()
        if target_type == "person":
            person_risky_patterns = [
                r"\bhome address\b",
                r"\bresidential address\b",
                r"\blive location\b",
                r"\bprecise location\b",
                r"\bfamily details\b",
                r"\bprivate phone\b",
                r"\bprivate email\b",
            ]
            for pattern in person_risky_patterns:
                if re.search(pattern, scanned_text):
                    blocked_reasons.append(pattern)

        if blocked_reasons:
            return {
                "status": "POLICY_BLOCKED",
                "reasons": sorted(set(blocked_reasons)),
                "explanation": (
                    "The requested task appears to require private-account access, credential misuse, "
                    "covert tracking, subject contact, sensitive profiling, or other prohibited SOCMINT behavior."
                ),
                "safe_alternatives": SAFE_ALTERNATIVES,
            }

        return {
            "status": "ALLOWED_PUBLIC_OR_AUTHORIZED",
            "reasons": [],
            "explanation": (
                "No obvious policy violation detected in objective/questions/target. "
                "Execution remains planning-only and must use only public/authorized sources."
            ),
            "safe_alternatives": [],
        }

    def run_policy_screen(self) -> None:
        payload = self.collect_payload()
        policy = self.policy_screen(payload)

        self.output.delete("1.0", "end")
        self.output.insert(
            "1.0",
            json.dumps(
                {
                    "mode": "POLICY_SCREEN_ONLY",
                    "panel_version": APP_VERSION,
                    "policy_screen": policy,
                    "payload_preview": {
                        "case_id": payload.get("case_id"),
                        "task_id": payload.get("task_id"),
                        "objective": payload.get("objective"),
                        "target": payload.get("target"),
                        "target_type": payload.get("target_type"),
                    },
                },
                ensure_ascii=False,
                indent=2,
            ),
        )

        self.notebook.select(self.output_tab)

        if policy["status"] == "POLICY_BLOCKED":
            messagebox.showwarning(
                "Policy Blocked",
                "This SOCMINT request is policy-blocked.\n\n"
                + "\n".join(policy["reasons"])
                + "\n\nUse only public/authorized alternatives.",
            )
        else:
            messagebox.showinfo("Policy Screen", "No obvious policy violation detected. Planning-only mode remains active.")

    def generate_plan(self) -> None:
        payload = self.collect_payload()
        warnings = self.validate_payload(payload)
        policy = self.policy_screen(payload)

        if policy["status"] == "POLICY_BLOCKED":
            result = {
                "mode": "POLICY_BLOCKED",
                "panel_version": APP_VERSION,
                "policy_screen": policy,
                "warnings": warnings,
                "payload": payload,
                "search_plan": [],
                "next_best_action": {
                    "action": "Revise task to use only public/authorized social sources.",
                    "owner": "SOCMINT Manager",
                    "expected_output": "Policy-compliant SOCMINT scope and question set.",
                },
            }
            self.last_result = result
            self._write_output(result)
            messagebox.showwarning(
                "Policy Blocked",
                "SOCMINT plan not generated because the request is policy-blocked.",
            )
            return

        questions = payload.get("questions") or self._default_questions(payload)
        platforms = self._select_platforms(payload)
        identifiers = self._collect_identifiers(payload)

        search_plan = self._build_search_plan(payload, questions, platforms, identifiers)

        result = {
            "mode": "PLANNING_ONLY",
            "panel_version": APP_VERSION,
            "policy": (
                "This output does not execute live social-media collection. "
                "It produces a reproducible SOCMINT search plan using public/authorized source assumptions only. "
                "No private accounts, credentials, tokens, cookies, CAPTCHA bypass, covert contact, "
                "impersonation, sensitive profiling, or precise live-location inference is permitted."
            ),
            "policy_screen": policy,
            "warnings": warnings,
            "payload": payload,
            "intelligence_questions": questions,
            "selected_platforms": platforms,
            "search_identifiers": identifiers,
            "socmint_search_plan": search_plan,
            "identity_resolution_policy": self._identity_resolution_policy(),
            "content_classification_rules": self._content_classification_rules(),
            "source_identity_rules": self._source_identity_rules(),
            "relationship_rules": self._relationship_rules(),
            "network_analysis_rules": self._network_analysis_rules(),
            "coordination_signal_rules": self._coordination_signal_rules(),
            "repost_copy_analysis_rules": self._repost_copy_analysis_rules(),
            "source_independence_rules": self._source_independence_rules(),
            "timeline_rules": self._timeline_rules(),
            "archive_deleted_content_rules": self._archive_deleted_content_rules(),
            "media_analysis_rules": self._media_analysis_rules(),
            "geolocation_rules": self._geolocation_rules(),
            "sensitive_trait_rules": self._sensitive_trait_rules(),
            "sentiment_emotion_rules": self._sentiment_emotion_rules(),
            "bot_automation_rules": self._bot_automation_rules(),
            "influence_rules": self._influence_rules(),
            "event_intelligence_rules": self._event_intelligence_rules(),
            "fact_gate_criteria": self._fact_gate_criteria(),
            "dual_ai_review_rules": self._dual_ai_review_rules(),
            "evidence_schema": self._evidence_schema(),
            "observation_schema": self._observation_schema(),
            "account_schema": self._account_schema(),
            "post_schema": self._post_schema(),
            "relationship_schema": self._relationship_schema(),
            "source_assessment_schema": self._source_assessment_schema(),
            "contradiction_schema": self._contradiction_schema(),
            "knowledge_gap_schema": self._knowledge_gap_schema(),
            "socmint_result_schema": self._socmint_result_schema(),
            "recommended_stop_conditions": self._stop_conditions(),
            "specialist_handoffs": self._specialist_handoffs(payload),
            "next_best_action": self._next_best_action(payload),
        }

        self.last_result = result
        self._write_output(result)
        self.notebook.select(self.output_tab)

        if warnings:
            messagebox.showwarning(
                "Validation Warnings",
                "SOCMINT plan generated with warnings:\n\n" + "\n".join(warnings),
            )

    def _write_output(self, result: Dict[str, Any]) -> None:
        self.output.delete("1.0", "end")
        self.output.insert("1.0", json.dumps(result, ensure_ascii=False, indent=2))

    def _default_questions(self, payload: Dict[str, Any]) -> List[str]:
        target = payload.get("target", "target")
        target_type = payload.get("target_type", "unknown")

        base = [
            f"Which public social accounts are plausibly associated with {target}?",
            f"Which public posts mention {target}?",
            f"What public affiliation claims exist about {target}?",
            f"Which relationships are explicitly visible and evidence-backed?",
            f"Which content is historical versus current?",
            f"Which claims depend on the same upstream source?",
            f"What contradictions exist across public social sources?",
            f"What information is missing and which specialist should investigate next?",
        ]

        if target_type in {"person", "username", "alias", "public_account"}:
            base.extend(
                [
                    "Which usernames or display names appear across public platforms?",
                    "Are there same-name or same-username collision risks?",
                    "Which public profile links connect accounts?",
                ]
            )

        if target_type in {"organization", "company", "brand"}:
            base.extend(
                [
                    "Which official public accounts exist?",
                    "Which employee or affiliate accounts publicly claim affiliation?",
                    "Which public campaigns or hashtags are associated?",
                ]
            )

        if target_type in {"domain", "url", "repository"}:
            base.extend(
                [
                    "Which public posts reference this domain/URL/repository?",
                    "Which accounts amplified this artifact?",
                    "Is the reference historical or current?",
                ]
            )

        if target_type in {"event", "campaign", "topic", "hashtag"}:
            base.extend(
                [
                    "Which public posts discuss this event/campaign/topic?",
                    "Which accounts or communities amplify the narrative?",
                    "Are repeated claims independent or derivative?",
                ]
            )

        return base

    def _select_platforms(self, payload: Dict[str, Any]) -> List[str]:
        explicit = payload.get("platforms") or []
        if explicit:
            platforms, truncated = truncate_list([str(p) for p in explicit], 10)
            if truncated:
                platforms.append("NOTE: platform list truncated for planning safety")
            return platforms

        target_type = str(payload.get("target_type", "")).lower()

        mapping = {
            "person": ["X/Twitter", "LinkedIn-visible", "GitHub", "public forums", "public web index"],
            "username": ["X/Twitter", "GitHub", "Reddit", "Telegram", "Instagram-visible", "TikTok-visible"],
            "alias": ["X/Twitter", "Reddit", "Telegram", "public forums", "public web index"],
            "public_account": ["X/Twitter", "Instagram-visible", "TikTok-visible", "YouTube", "Telegram"],
            "organization": ["X/Twitter", "LinkedIn-visible", "Facebook-visible", "YouTube", "public web index"],
            "company": ["X/Twitter", "LinkedIn-visible", "GitHub", "public web index", "public forums"],
            "brand": ["X/Twitter", "Instagram-visible", "TikTok-visible", "YouTube", "public web index"],
            "topic": ["X/Twitter", "Reddit", "Telegram", "YouTube", "public forums"],
            "hashtag": ["X/Twitter", "Instagram-visible", "TikTok-visible", "public web index"],
            "event": ["X/Twitter", "Telegram", "YouTube", "Reddit", "public web index"],
            "campaign": ["X/Twitter", "Telegram", "Reddit", "YouTube", "public forums"],
            "domain": ["X/Twitter", "Reddit", "GitHub", "public forums", "public web index"],
            "url": ["X/Twitter", "Reddit", "Telegram", "public web index"],
            "repository": ["GitHub", "X/Twitter", "Reddit", "public forums"],
            "malware_campaign": ["GitHub", "X/Twitter", "Reddit", "public forums", "public web index"],
            "threat_actor_label": ["X/Twitter", "Telegram", "Reddit", "public forums", "public web index"],
            "location": ["X/Twitter", "Instagram-visible", "YouTube", "Telegram", "public web index"],
            "public_community": ["Reddit", "Telegram", "Discord-public", "public forums", "Mastodon/Fediverse"],
        }

        return mapping.get(target_type, ["public web index", "X/Twitter", "Reddit", "Telegram"])

    def _collect_identifiers(self, payload: Dict[str, Any]) -> List[Dict[str, str]]:
        identifiers: List[Dict[str, str]] = []

        target = str(payload.get("target", "")).strip()
        if target:
            identifiers.append({"type": "target", "value": target})

        for value in payload.get("known_usernames", []):
            identifiers.append({"type": "username", "value": str(value).strip()})

        for value in payload.get("known_accounts", []):
            identifiers.append({"type": "public_account", "value": str(value).strip()})

        for value in payload.get("known_aliases", []):
            identifiers.append({"type": "alias", "value": str(value).strip()})

        for value in payload.get("known_domains", []):
            identifiers.append({"type": "domain", "value": str(value).strip()})

        for value in payload.get("known_urls", []):
            identifiers.append({"type": "url", "value": str(value).strip()})

        for value in payload.get("known_hashtags", []):
            identifiers.append({"type": "hashtag", "value": str(value).strip()})

        deduped: List[Dict[str, str]] = []
        seen = set()
        for item in identifiers:
            key = (item["type"], normalize_text(item["value"]))
            if key in seen or not item["value"]:
                continue
            seen.add(key)
            deduped.append(item)

        limited, truncated = truncate_list(deduped, 12)
        if truncated:
            limited.append({"type": "note", "value": "Identifier list truncated for planning safety"})

        return limited

    def _build_search_plan(
        self,
        payload: Dict[str, Any],
        questions: List[Any],
        platforms: List[str],
        identifiers: List[Dict[str, str]],
    ) -> List[Dict[str, Any]]:
        plan: List[Dict[str, Any]] = []
        priority = 1

        questions_limited, questions_truncated = truncate_list([str(q) for q in questions], 8)
        platforms_limited, platforms_truncated = truncate_list(platforms, 8)

        if questions_truncated or platforms_truncated:
            plan.append(
                {
                    "question": "PLANNING_LIMIT",
                    "target_identifier": "system",
                    "platform": "TraceAtlas SOCMINT Panel",
                    "query": "Question/platform list truncated to prevent unbounded planning output.",
                    "search_type": "planning_limit",
                    "source": "local_panel",
                    "purpose": "preserve reproducibility and avoid excessive query generation",
                    "priority": 0,
                    "expected_information_value": "CONTROL",
                    "authorization_status": "NOT_VERIFIED_PLANNING_ONLY",
                    "estimated_cost": "ZERO",
                    "estimated_latency": "ZERO",
                    "execution_status": "NOT_EXECUTED_PLANNING_ONLY",
                }
            )

        for question in questions_limited:
            search_types = self._search_types_for_question(question, payload)

            for platform in platforms_limited:
                for identifier in identifiers:
                    if identifier.get("type") == "note":
                        continue

                    for search_type in search_types:
                        query = self._compile_query(search_type, platform, identifier, question, payload)

                        plan.append(
                            {
                                "question": question,
                                "target_identifier": identifier.get("value", ""),
                                "identifier_type": identifier.get("type", ""),
                                "platform": platform,
                                "query": query,
                                "search_type": search_type,
                                "source": self._source_for_platform(platform),
                                "purpose": self._purpose_for_search_type(search_type),
                                "priority": priority,
                                "expected_information_value": self._expected_information_value(search_type, identifier.get("type", "")),
                                "authorization_status": "NOT_VERIFIED_PLANNING_ONLY",
                                "estimated_cost": self._estimated_cost(platform, search_type),
                                "estimated_latency": self._estimated_latency(platform),
                                "policy_risk": "LOW_IF_PASSIVE_PUBLIC",
                                "execution_status": "NOT_EXECUTED_PLANNING_ONLY",
                            }
                        )

                        priority += 1

                        if priority > 250:
                            plan.append(
                                {
                                    "question": "PLAN_TRUNCATED",
                                    "target_identifier": "system",
                                    "platform": "TraceAtlas SOCMINT Panel",
                                    "query": "Search plan truncated at 250 planned queries.",
                                    "search_type": "truncation",
                                    "source": "local_panel",
                                    "purpose": "prevent unbounded planning output",
                                    "priority": priority,
                                    "expected_information_value": "CONTROL",
                                    "authorization_status": "NOT_VERIFIED_PLANNING_ONLY",
                                    "estimated_cost": "ZERO",
                                    "estimated_latency": "ZERO",
                                    "execution_status": "NOT_EXECUTED_PLANNING_ONLY",
                                }
                            )
                            return plan

        return plan

    def _search_types_for_question(self, question: str, payload: Dict[str, Any]) -> List[str]:
        q = normalize_text(question)
        target_type = str(payload.get("target_type", "")).lower()

        types: List[str] = []

        if any(word in q for word in ["username", "handle", "alias", "display name"]):
            types.append("username_search")

        if any(word in q for word in ["profile", "bio", "affiliation", "works at", "employee", "director", "founder"]):
            types.append("public_profile_search")
            types.append("public_affiliation_analysis")

        if any(word in q for word in ["post", "statement", "said", "claims", "mention"]):
            types.append("public_post_search")

        if any(word in q for word in ["comment", "reply", "thread"]):
            types.append("public_comment_search")

        if any(word in q for word in ["channel", "group", "community"]):
            types.append("public_channel_search")
            types.append("public_group_search")

        if any(word in q for word in ["hashtag", "tag"]):
            types.append("hashtag_search")

        if any(word in q for word in ["url", "link", "domain", "website"]):
            types.append("url_search")
            types.append("domain_reference_search")

        if any(word in q for word in ["image", "video", "media", "photo"]):
            types.append("media_metadata_analysis")

        if any(word in q for word in ["time", "when", "date", "timeline", "history"]):
            types.append("temporal_analysis")

        if any(word in q for word in ["same", "duplicate", "repost", "copy", "upstream"]):
            types.append("repost_detection")
            types.append("duplicate_detection")

        if any(word in q for word in ["contradiction", "conflict", "disagree"]):
            types.append("contradiction_detection")

        if any(word in q for word in ["relationship", "connected", "associat"]):
            types.append("public_relationship_analysis")

        if not types:
            types = ["public_post_search", "public_profile_search"]

        if target_type in {"username", "alias", "public_account"} and "username_search" not in types:
            types.insert(0, "username_search")

        if target_type in {"domain", "url"} and "url_search" not in types:
            types.insert(0, "url_search")

        # Remove duplicates while preserving order
        seen = set()
        unique = []
        for t in types:
            if t not in seen:
                seen.add(t)
                unique.append(t)

        return unique[:6]

    def _compile_query(
        self,
        search_type: str,
        platform: str,
        identifier: Dict[str, str],
        question: str,
        payload: Dict[str, Any],
    ) -> str:
        value = identifier.get("value", "")
        id_type = identifier.get("type", "")
        jurisdiction = str(payload.get("jurisdiction", "")).strip()
        question_short = normalize_text(question)[:120]

        if search_type == "username_search":
            return f"{platform} public username search: {value}"

        if search_type == "public_profile_search":
            return f"{platform} public profile search: {value}"

        if search_type == "public_affiliation_analysis":
            return f"{platform} public affiliation/profile claims: {value} {question_short}"

        if search_type == "public_post_search":
            return f"{platform} public post search: {value} {question_short}"

        if search_type == "public_comment_search":
            return f"{platform} public comment/thread search: {value} {question_short}"

        if search_type == "public_channel_search":
            return f"{platform} public channel search: {value} {question_short}"

        if search_type == "public_group_search":
            return f"{platform} public group/community search: {value} {question_short}"

        if search_type == "hashtag_search":
            tag = value if value.startswith("#") else f"#{value}"
            return f"{platform} public hashtag search: {tag}"

        if search_type == "url_search":
            return f"{platform} public URL reference search: {value}"

        if search_type == "domain_reference_search":
            return f"{platform} public domain reference search: {value}"

        if search_type == "media_metadata_analysis":
            return f"{platform} public media/metadata reference: {value}"

        if search_type == "temporal_analysis":
            time_range = payload.get("time_range", {})
            tr = ""
            if isinstance(time_range, dict):
                tr = f" from={time_range.get('from', '')} to={time_range.get('to', '')}"
            return f"{platform} temporal public activity search: {value}{tr} {question_short}"

        if search_type == "repost_detection":
            return f"{platform} repost/copy detection candidate: {value} {question_short}"

        if search_type == "duplicate_detection":
            return f"{platform} duplicate content detection candidate: {value} {question_short}"

        if search_type == "contradiction_detection":
            return f"{platform} contradiction search: {value} {question_short} {jurisdiction}"

        if search_type == "public_relationship_analysis":
            return f"{platform} public relationship/mention search: {value} {question_short}"

        return f"{platform} public SOCMINT search: {id_type}={value} question={question_short}"

    def _source_for_platform(self, platform: str) -> str:
        p = normalize_text(platform)

        if "twitter" in p or p == "x":
            return "configured_public_x_api_or_public_web_index"
        if "reddit" in p:
            return "configured_public_reddit_api_or_public_web_index"
        if "telegram" in p:
            return "configured_public_telegram_index_or_authorized_export"
        if "github" in p:
            return "configured_public_github_api"
        if "youtube" in p:
            return "configured_public_youtube_api"
        if "linkedin" in p:
            return "configured_linkedin_public_or_provider_supported_source"
        if "facebook" in p:
            return "configured_facebook_public_or_provider_supported_source"
        if "instagram" in p:
            return "configured_instagram_public_or_provider_supported_source"
        if "tiktok" in p:
            return "configured_tiktok_public_or_provider_supported_source"
        if "mastodon" in p or "fediverse" in p:
            return "configured_public_fediverse_api"
        if "forum" in p:
            return "configured_public_forum_search"
        if "blog" in p:
            return "configured_public_blog_search"
        if "discord" in p:
            return "authorized_discord_export_or_public_artifact_only"

        return "configured_public_web_index"

    def _purpose_for_search_type(self, search_type: str) -> str:
        mapping = {
            "username_search": "discover public username presence and collision risk",
            "public_profile_search": "capture public profile metadata and linked public identifiers",
            "public_affiliation_analysis": "identify public affiliation claims without treating them as verified facts",
            "public_post_search": "find relevant public posts/statements",
            "public_comment_search": "find relevant public comments/replies",
            "public_channel_search": "find relevant public channels",
            "public_group_search": "find relevant public groups/communities where permitted",
            "hashtag_search": "find public hashtag activity and narrative spread",
            "url_search": "find public references to URL",
            "domain_reference_search": "find public references to domain",
            "media_metadata_analysis": "preserve media references and extract lawful metadata",
            "temporal_analysis": "establish activity timeline and distinguish event/publication/retrieval time",
            "repost_detection": "detect reposts, quotes, forwards, and upstream candidates",
            "duplicate_detection": "cluster duplicate or near-duplicate public content",
            "contradiction_detection": "search for conflicting public claims",
            "public_relationship_analysis": "identify explicitly visible public relationships",
        }
        return mapping.get(search_type, "public SOCMINT discovery")

    def _expected_information_value(self, search_type: str, identifier_type: str) -> str:
        high = {
            "public_affiliation_analysis",
            "url_search",
            "domain_reference_search",
            "temporal_analysis",
            "contradiction_detection",
            "repost_detection",
        }

        medium = {
            "username_search",
            "public_profile_search",
            "public_post_search",
            "public_channel_search",
            "hashtag_search",
            "public_relationship_analysis",
        }

        if identifier_type in {"domain", "url", "hashtag"}:
            return "HIGH"

        if search_type in high:
            return "HIGH"

        if search_type in medium:
            return "MEDIUM"

        return "LOW_TO_MEDIUM"

    def _estimated_cost(self, platform: str, search_type: str) -> str:
        if "configured" in self._source_for_platform(platform):
            return "CONFIG_DEPENDENT"
        if search_type in {"public_post_search", "username_search", "hashtag_search"}:
            return "LOW"
        return "MEDIUM"

    def _estimated_latency(self, platform: str) -> str:
        p = normalize_text(platform)
        if "github" in p or "reddit" in p:
            return "LOW"
        if "telegram" in p or "forum" in p:
            return "MEDIUM"
        return "MEDIUM_TO_HIGH"

    def _identity_resolution_policy(self) -> Dict[str, Any]:
        return {
            "rule": "Same username does not equal same person.",
            "never_merge_based_on_only": [
                "same display name",
                "same username",
                "same profile image",
                "same city",
                "same employer claim",
                "same hashtag use",
            ],
            "signals_to_consider": [
                "exact username",
                "normalized username",
                "case variants",
                "separator variants",
                "public bio overlap",
                "public website overlap",
                "organization references",
                "temporal overlap",
                "language",
                "public location clues",
                "cross-linked accounts",
            ],
            "match_states": [
                "VERIFIED_MATCH",
                "PROBABLE_MATCH",
                "POSSIBLE_MATCH",
                "UNRESOLVED",
                "LIKELY_DISTINCT",
                "VERIFIED_DISTINCT",
            ],
            "high_impact_merge_requirements": [
                "multiple independent signals",
                "evidence-linked provenance",
                "dual-AI review",
                "reversibility/versioning",
                "SOCMINT Manager approval",
            ],
        }

    def _content_classification_rules(self) -> List[str]:
        return [
            "SELF_CLAIM",
            "THIRD_PARTY_CLAIM",
            "OFFICIAL_ANNOUNCEMENT",
            "OPINION",
            "ADVERTISEMENT",
            "NEWS_REFERENCE",
            "REPOST",
            "QUOTE",
            "COMMENT",
            "MEDIA_POST",
            "LINK_SHARE",
            "UNKNOWN",
        ]

    def _source_identity_rules(self) -> List[str]:
        return [
            "official account",
            "verified account",
            "claimed organization account",
            "employee account",
            "public individual account",
            "anonymous/pseudonymous account",
            "automated/bot-like account candidate",
            "community account",
            "news account",
        ]

    def _relationship_rules(self) -> Dict[str, Any]:
        return {
            "allowed_observed_relationships": [
                "Account A MENTIONS Account B",
                "Account A LINKS_TO Domain X",
                "Account A REPOSTS Post B",
                "Person Candidate CLAIMS_AFFILIATION_WITH Company X",
                "Account POSTS_IN PublicChannel",
                "Post REFERENCES Event",
            ],
            "relationship_states": [
                "OBSERVED",
                "CANDIDATE",
                "PROBABLE",
                "SUPPORTED",
                "DISPUTED",
                "HISTORICAL",
            ],
            "do_not_convert_without_evidence": [
                "follows -> personal relationship",
                "likes -> agreement",
                "mentions -> affiliation",
                "shared hashtag -> coordination",
                "shared group -> membership/control",
                "same audience -> common operator",
            ],
        }

    def _network_analysis_rules(self) -> Dict[str, Any]:
        return {
            "supported_metrics": [
                "degree",
                "centrality",
                "betweenness",
                "community detection",
                "bridge accounts",
                "conversation clusters",
                "mention clusters",
                "repost clusters",
                "hashtag clusters",
                "URL-sharing clusters",
            ],
            "interpretation_limit": (
                "Network metrics are structural observations. They are not proof of leadership, "
                "coordination, criminality, or command/control."
            ),
        }

    def _coordination_signal_rules(self) -> Dict[str, Any]:
        return {
            "possible_signals": [
                "same URLs",
                "same text",
                "near-identical text",
                "similar timestamps",
                "repeated hashtags",
                "same media",
                "same upstream post",
                "synchronized public activity",
            ],
            "output_label": "COORDINATION_SIGNAL",
            "not_output_label_unless_stronger_evidence": "COORDINATED_ACTOR",
            "alternative_explanations": [
                "organic virality",
                "scheduled marketing",
                "news amplification",
                "platform trends",
                "common source material",
                "automation",
                "actual coordination",
            ],
        }

    def _repost_copy_analysis_rules(self) -> List[str]:
        return [
            "exact duplicate posts",
            "near-duplicate posts",
            "quoted posts",
            "reposts",
            "forwarded public messages",
            "copy-pasted text",
            "common upstream URLs",
        ]

    def _source_independence_rules(self) -> Dict[str, Any]:
        return {
            "principle": "Ten accounts repeating one source are not ten confirmations.",
            "cluster_by": [
                "original post",
                "common URL",
                "press release",
                "news article",
                "Telegram forward",
                "same image",
                "same video",
                "same document",
                "same upstream source",
            ],
            "states": [
                "INDEPENDENT",
                "PARTIALLY_DEPENDENT",
                "DEPENDENT",
                "UNKNOWN",
            ],
        }

    def _timeline_rules(self) -> Dict[str, Any]:
        return {
            "distinguish": [
                "event_time",
                "published_at",
                "observed_at",
                "retrieved_at",
                "valid_from",
                "valid_to",
            ],
            "track": [
                "account creation/first observed",
                "post publication",
                "reply",
                "repost",
                "public affiliation change",
                "bio change where captured",
                "URL change",
                "event reference",
                "campaign activity",
                "content deletion only when supported by preserved historical evidence",
            ],
        }

    def _archive_deleted_content_rules(self) -> Dict[str, Any]:
        return {
            "allowed_labels": [
                "previously captured",
                "historically archived",
                "no longer publicly available",
            ],
            "do_not_claim": [
                "deleted by user unless evidence establishes deletion",
            ],
        }

    def _media_analysis_rules(self) -> Dict[str, Any]:
        return {
            "allowed": [
                "preserve media reference",
                "hash artifact",
                "extract metadata where available",
                "OCR visible text",
                "detect language",
                "extract visible public entities/clues",
            ],
            "prohibited": [
                "covert biometric identification",
                "identify private people from faces",
            ],
            "handoff": ["IMINT", "VIDINT", "AUDINT", "GEOINT"],
        }

    def _geolocation_rules(self) -> Dict[str, Any]:
        return {
            "allowed_public_clues": [
                "declared city",
                "public event location",
                "visible landmark",
                "geotag where genuinely public",
                "place name",
                "public business location",
            ],
            "prohibited": [
                "infer precise real-time location of private individuals",
                "infer home address from weak clues",
            ],
            "handoff": "GEOINT for complex geolocation",
        }

    def _sensitive_trait_rules(self) -> Dict[str, Any]:
        return {
            "do_not_infer": [
                "religion",
                "political ideology/party",
                "sexual orientation",
                "medical conditions",
                "ethnicity",
                "private sex life",
                "criminal status",
            ],
            "exception": (
                "only if directly necessary to an authorized case and already explicitly provided "
                "in an appropriate lawful source context"
            ),
            "prohibited": "speculative sensitive profiling",
        }

    def _sentiment_emotion_rules(self) -> Dict[str, Any]:
        return {
            "allowed": "describe content tone at aggregate/content level",
            "prohibited_claims": [
                "This person is depressed.",
                "This person is dangerous.",
                "This person is mentally unstable.",
            ],
            "preferred_language": "The post contains negative language.",
        }

    def _bot_automation_rules(self) -> Dict[str, Any]:
        return {
            "signals": [
                "posting frequency",
                "repetition",
                "timing patterns",
                "content duplication",
                "client metadata where available",
                "network structure",
            ],
            "statuses": [
                "AUTOMATION_SIGNAL",
                "POSSIBLE_AUTOMATED_ACCOUNT",
                "UNRESOLVED",
            ],
            "rule": "Do not call an account a bot solely from one metric.",
        }

    def _influence_rules(self) -> Dict[str, Any]:
        return {
            "observable_signals": [
                "engagement",
                "reposts",
                "mentions",
                "network centrality",
                "content spread",
                "audience reach where platform exposes it",
            ],
            "do_not_interpret_follower_count_as": [
                "trustworthiness",
                "authority",
                "leadership",
                "real influence",
            ],
        }

    def _event_intelligence_rules(self) -> Dict[str, Any]:
        return {
            "extract": [
                "time",
                "location reference",
                "participants explicitly named",
                "media",
                "URLs",
                "hashtags",
                "public statements",
            ],
            "correlate_with": ["EVENTINT", "NEWSINT", "GEOINT", "WEBINT"],
            "rule": "Never infer attendance solely from likes/follows.",
        }

    def _fact_gate_criteria(self) -> List[Dict[str, str]]:
        return [
            {
                "check": "evidence_present",
                "description": "A retrievable evidence object must exist for the claim.",
            },
            {
                "check": "source_identifiable",
                "description": "Platform, account, post URL, export, or artifact must be identifiable.",
            },
            {
                "check": "entity_resolved",
                "description": "Account/person/organization identity must be resolved with acceptable confidence.",
            },
            {
                "check": "temporal_context_valid",
                "description": "Event, publication, observation, and retrieval times must be distinguished.",
            },
            {
                "check": "source_reliability_evaluated",
                "description": "First-party/third-party, official/unofficial, anonymous/attributable, primary/secondary status assessed.",
            },
            {
                "check": "source_bias_evaluated",
                "description": "Self-promotion, brand promotion, advocacy, commercial incentive, anonymity, adversarial behavior noted.",
            },
            {
                "check": "source_independence_known",
                "description": "Copied, reposted, syndicated, or derivative content must not be counted as independent corroboration.",
            },
            {
                "check": "identity_check",
                "description": "Same username/display name/image/city/employer is insufficient for identity merge.",
            },
            {
                "check": "contradiction_checked",
                "description": "Conflicting public claims must be searched for and recorded.",
            },
        ]

    def _dual_ai_review_rules(self) -> Dict[str, Any]:
        return {
            "required_for": [
                "high-impact identity merges",
                "coordination conclusions",
                "affiliation conclusions",
                "event attribution",
                "threat-actor labeling",
                "any consequential allegation",
            ],
            "passes": [
                "Primary SOCMINT Analyst",
                "Independent Skeptic Analyst",
            ],
            "outcomes": [
                "AGREE",
                "PARTIAL_AGREEMENT",
                "DISAGREE",
                "INSUFFICIENT_EVIDENCE",
            ],
            "rule": "AI agreement is not source independence.",
        }

    def _evidence_schema(self) -> Dict[str, str]:
        return {
            "evidence_id": "Unique evidence identifier",
            "case_id": "Case identifier",
            "task_id": "Task identifier",
            "source_id": "Source identifier",
            "platform": "Social platform or source system",
            "url": "Public URL or artifact locator",
            "retrieved_at": "UTC retrieval timestamp",
            "content_hash": "Hash of preserved content",
            "raw_artifact_reference": "Path/object storage reference",
            "content_type": "HTML, JSON, image, video, audio, text, export, etc.",
            "acquisition_method": "public_api, public_web_index, authorized_export, customer_provided_record, archive",
            "parser_version": "Parser version",
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
            "event_time": "Time of described event, if known",
            "published_at": "Publication time, if known",
            "extraction_method": "manual, parser, LLM extraction, regex, etc.",
            "limitations": "Known limitations of the observation",
        }

    def _account_schema(self) -> Dict[str, str]:
        return {
            "account_id": "Unique account identifier",
            "platform": "Platform name",
            "username": "Public username/handle",
            "display_name": "Public display name",
            "public_url": "Public profile URL",
            "public_bio": "Public biography text",
            "public_website": "Public website link",
            "public_organization_reference": "Public organization reference",
            "public_role": "Public role claim",
            "public_location_text": "Public location text",
            "joined_date": "Public joined/creation date where exposed",
            "verification_state": "Public verification state",
            "account_type_candidate": "official, claimed_org, employee, individual, anonymous, bot_candidate, community, news, unknown",
            "evidence_ids": "Evidence references",
        }

    def _post_schema(self) -> Dict[str, str]:
        return {
            "post_id": "Unique post identifier",
            "platform": "Platform name",
            "author_account_id": "Author account identifier",
            "published_at": "Publication timestamp",
            "retrieved_at": "Retrieval timestamp",
            "text": "Post text",
            "urls": "Extracted URLs",
            "mentions": "Extracted mentions",
            "hashtags": "Extracted hashtags",
            "media": "Media references",
            "reply_to": "Reply relationship",
            "quote_of": "Quote relationship",
            "repost_of": "Repost relationship",
            "language": "Detected language",
            "content_classification": "SELF_CLAIM, THIRD_PARTY_CLAIM, etc.",
            "evidence_id": "Evidence identifier",
        }

    def _relationship_schema(self) -> Dict[str, str]:
        return {
            "relationship_id": "Unique relationship identifier",
            "source_entity": "Source entity",
            "relationship_type": "MENTIONS, LINKS_TO, REPOSTS, CLAIMS_AFFILIATION_WITH, etc.",
            "target_entity": "Target entity",
            "state": "OBSERVED, CANDIDATE, PROBABLE, SUPPORTED, DISPUTED, HISTORICAL",
            "evidence_ids": "Evidence references",
            "observed_at": "Observation timestamp",
            "valid_from": "Start validity if known",
            "valid_to": "End validity if known",
            "limitations": "Known limitations",
        }

    def _source_assessment_schema(self) -> Dict[str, str]:
        return {
            "source_id": "Source identifier",
            "platform": "Platform/source system",
            "account_id": "Account identifier if applicable",
            "source_type": "official, individual, anonymous, news, community, aggregator, export, archive, unknown",
            "first_party_or_third_party": "first_party, third_party, unknown",
            "authority": "VERY_HIGH, HIGH, MODERATE, LOW, VERY_LOW, UNKNOWN",
            "primary_or_secondary": "primary, secondary, tertiary, unknown",
            "attributability": "attributable, pseudonymous, anonymous, unknown",
            "freshness": "current, recent, stale, unknown",
            "bias": "self_promotion, brand_promotion, advocacy, commercial, adversarial, community, unknown",
            "independence": "INDEPENDENT, PARTIALLY_DEPENDENT, DEPENDENT, UNKNOWN",
        }

    def _contradiction_schema(self) -> Dict[str, str]:
        return {
            "contradiction_id": "Unique contradiction identifier",
            "claim_a": "First conflicting claim",
            "claim_b": "Second conflicting claim",
            "sources": "Sources for each claim",
            "evidence_ids": "Evidence identifiers",
            "type": "identity, affiliation, date, location, event, URL, source dependence, etc.",
            "temporal_explanation": "Whether contradiction is explained by time",
            "identity_mismatch_possibility": "Whether different accounts/people may be confused",
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

    def _socmint_result_schema(self) -> List[str]:
        return [
            "case_id",
            "task_id",
            "objective",
            "questions",
            "platforms_queried",
            "queries",
            "source_ids",
            "evidence_ids",
            "accounts",
            "usernames",
            "posts",
            "comments",
            "channels",
            "groups",
            "hashtags",
            "URLs",
            "media",
            "entities",
            "relationships",
            "events",
            "timeline_updates",
            "observations",
            "supported_facts",
            "partial_facts",
            "disputed_facts",
            "source_reliability",
            "source_bias",
            "source_independence",
            "duplicate_clusters",
            "coordination_signals",
            "identity_candidates",
            "contradictions",
            "insights",
            "hypotheses_supported",
            "hypotheses_weakened",
            "unknowns",
            "knowledge_gaps",
            "recommended_next_actions",
            "limitations",
            "status",
        ]

    def _stop_conditions(self) -> List[str]:
        return [
            "OBJECTIVE_SATISFIED",
            "SUFFICIENT_VERIFICATION",
            "SOURCES_EXHAUSTED",
            "LOW_INFORMATION_VALUE",
            "TIME_EXHAUSTED",
            "BUDGET_EXHAUSTED",
            "RATE_LIMIT_BOUNDARY",
            "AUTHORIZATION_BOUNDARY",
            "POLICY_BLOCK",
            "HUMAN_REVIEW_REQUIRED",
            "SYSTEM_FAILURE",
            "CANCELLED",
        ]

    def _specialist_handoffs(self, payload: Dict[str, Any]) -> List[Dict[str, str]]:
        target_type = str(payload.get("target_type", "")).lower()
        text = " ".join(
            [
                str(payload.get("objective", "")),
                " ".join(str(q) for q in payload.get("questions", [])),
                " ".join(str(v) for v in payload.get("known_domains", [])),
                " ".join(str(v) for v in payload.get("known_urls", [])),
            ]
        ).lower()

        handoffs: List[Dict[str, str]] = []

        if any(word in text for word in ["domain", "url", "ip", "asn", "infrastructure"]) or target_type in {"domain", "url"}:
            handoffs.append(
                {
                    "specialist": "DOMAININT / INFRASTRUCTURE Employee",
                    "reason": "Public domain/URL/infrastructure context is needed.",
                    "expected_output": "Passive DNS/RDAP/certificate/ASN context and infrastructure timeline.",
                }
            )

        if any(word in text for word in ["image", "photo", "video", "geoloc", "landmark"]) or target_type in {"location", "event"}:
            handoffs.append(
                {
                    "specialist": "GEOINT / IMINT / VIDINT Employee",
                    "reason": "Media geolocation or visual verification may be required.",
                    "expected_output": "Public geospatial clues, media authenticity caveats, confidence levels.",
                }
            )

        if any(word in text for word in ["malware", "ioc", "hash", "threat actor", "campaign"]):
            handoffs.append(
                {
                    "specialist": "MALWAREINT / CTI Employee",
                    "reason": "Malware/IOC/threat-intel correlation required.",
                    "expected_output": "IOC dossier, campaign linkage, defensive recommendations.",
                }
            )

        if target_type in {"company", "organization", "brand"} or "affiliation" in text:
            handoffs.append(
                {
                    "specialist": "COMPANYINT / REGINT Employee",
                    "reason": "Corporate affiliation claims need registry/filing verification.",
                    "expected_output": "Legal entity, officers, filings, public corporate graph.",
                }
            )

        if target_type == "repository" or "github" in text or "repo" in text:
            handoffs.append(
                {
                    "specialist": "REPOINT / CODEINT Employee",
                    "reason": "Public repository/code context requires technical analysis.",
                    "expected_output": "Repository metadata, commits, releases, package references.",
                }
            )

        if not handoffs:
            handoffs.append(
                {
                    "specialist": "SOCMINT Manager",
                    "reason": "No specialized handoff triggered from target type or question text alone.",
                    "expected_output": "Review plan, approve connectors, assign follow-up tasks.",
                }
            )

        return handoffs

    def _next_best_action(self, payload: Dict[str, Any]) -> Dict[str, str]:
        target = payload.get("target", "target")
        target_type = payload.get("target_type", "unknown")

        return {
            "action": "Review SOCMINT search plan, confirm authorization, then configure only permitted public/authorized connectors.",
            "reason": (
                "Live social collection should begin only after scope, jurisdiction, privacy rules, "
                "platform terms, and source authorization are confirmed by the SOCMINT Manager."
            ),
            "owner": "SOCMINT Manager",
            "expected_output": (
                "Approved connector list, prioritized query batch, evidence capture schema, "
                "identity-resolution thresholds, and fact-gate rules for the next collection wave."
            ),
            "policy_note": (
                f"Do not access private accounts, use credentials/tokens/cookies, bypass platform controls, "
                f"contact subjects, impersonate people, infer sensitive traits, or track precise live location for {target} "
                f"under {target_type} without separate authorization."
            ),
        }

    def export_json(self) -> None:
        _support.export_snapshot(self, filedialog, messagebox)

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
        self.last_result = {}


if __name__ == "__main__":
    app = TraceAtlasSOCMINTPanel()
    app.mainloop()