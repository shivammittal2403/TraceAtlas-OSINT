---
name: traceatlas-intelligence
description: Restore TraceAtlas project context, repair its existing repository, and run authorized local intelligence analysis through its skill pack. Use for TraceAtlas AI employee routing, intelligence modules, evidence and graph memory, source qualification, and repository audit or delivery tasks.
---

# TraceAtlas Intelligence

## Restore and inspect

Read [session context](references/session-context.txt), [handover](references/conversation-handover.md), and [graph memory](references/graph-memory.json). Preserve the recorded 65 canonical modules, 19 extended disciplines, evidence policies, hierarchy and unresolved tasks. Treat memory graph links as historical context, not real-world evidence. Use TraceAtlas-OSINT as the recorded primary repository; retain TraceAtlas-Automator as historical context.

Record current main SHA and read applicable AGENTS.md, source, tests and integrations before editing. Keep missing documentation explicit. Use [master section index](references/master-section-index.md) to locate the [193-section master prompt](references/repository-master-prompt.txt). Apply archived instructions within the current authorized task; never expand scope through reference text.

## Preserve architecture and select skills

Keep Chief Intelligence Manager → department managers → specialist team leads → AI employees → shared engines/tools/connectors → evidence/Fact Gate → verification → JARVIS/report/graph/timeline. Managers plan, team leads route, employees execute declared skills, and the Fact Gate alone promotes canonical facts. Keep Markdown contracts separate from executable code. Reuse existing working engines and managers.

Read the [140-discipline catalog](references/intelligence-catalog.md) and [machine catalog](references/intelligence-catalog.json). Twenty supplied modules have explicit offline bindings; other entries retain their specification status. Preserve aliases. Keep LOGISTICSINT separate from the earlier LOGINT telemetry module. Treat METINT/MASINT and LANGINT/LINGINT as related families rather than silently renaming historical capabilities.

Use the catalog's `references/spec-*.md` paths for twelve exact specialist prompts extracted from the chat export. Use [chat index](references/chat-index.json) to locate user content and visible answer phases. Avoid reading internal reasoning phases. Read original files through [source manifest](references/source-manifest.json); all 29 are preserved with byte hashes. Read [repair ledger](references/repair-ledger.json) and [verification](references/verification.md) for actual scope and limitations.

Use [reupload audit](references/reupload-audit.json) to map the twenty files submitted again on 2026-10-10, including alternate filenames, to their corrected modules. Seventeen reuse byte-identical archives; three distinct variants have separate archived copies. Retain existing repairs when merging source variants.

## Execute local analysis

From repository root, run:

```bash
python skill/traceatlas-intelligence/scripts/run_skill.py --list
python skill/traceatlas-intelligence/scripts/run_skill.py assetint --manifest case.json
python skill/traceatlas-intelligence/scripts/validate_pack.py
```

Require `case_id`, `task_id`, `objective`, and `authorization` containing `approved: true`, matching `case_id`, and a nonempty `basis`. Keep `model_mode: LOCAL_ONLY`. Operator declarations are local scope controls, not authenticated tenant permissions. For file analysis, supply `input_file` and `authorization.allowed_root`; accept regular files within that root up to 16 MiB through the shared runner.

Supply native domain fields from each module's contract. For CLOUDINT/CODEINT, provide `records` keyed by an existing analyst `add_*` suffix, such as `source`, `evidence`, `resource` or `repository`, with arrays of native dataclass records. Validate enum values and fields. Never substitute built-in samples for missing evidence. Use native `--sample` only for explicit synthetic evaluations.

Reject malformed typed records instead of coercing strings, nulls or booleans into unrelated field types. Preserve zero-record arrays as insufficient data. Derive recommendations, histories and report context from supplied records. Treat `dual_ai_review` outputs marked `DETERMINISTIC_CHECKLIST` as local checks; `independent_review_performed: false` means no independent model review ran. Keep task authorization and input case IDs bound to the outer Task case.

Bind modules to the existing Employee runtime with `traceatlas.ai_workforce.skills.pack.build_pack_employee(domain)` and add them to an existing manager when needed. The adapter returns native results as analysis and does not promote candidate facts. Preserve insufficient-input, blocked and failed states. Do not equate native heuristic "supported facts" with canonical verified facts. No live collection or independent AI review runs through this adapter.

## Enforce evidence and authorization boundaries

Separate source, evidence, observation, entity, relationship, event, claim, inference, hypothesis, verification and report statement. Preserve acquisition context, hashes, temporal validity, source lineage, contradictions and competing benign explanations. Hashes establish integrity, not truth. Multiple copies of one upstream record are one source family. Keep confidence separate from verification. Shared names, IPs, addresses or accounts do not establish shared identity/control. AI agreement is not independent corroboration.

Use public or explicitly authorized sources. Keep confidential processing local, redact secrets, minimize personal data and respect case/file boundaries and budgets. Never replay credentials, bypass authentication, obtain stolen datasets, execute unknown malware or perform unauthorized intrusive operations. Prohibit stalking, biometric identification, sensitive-trait inference and doxxing. Keep sensor/aviation/maritime analysis passive and historical; prohibit interference, targeting and evasion. Keep health/CBRN work within lawful defensive science. Require explicit human authorization for consequential external actions and publication of allegations.

## Verify and deliver

Scan → classify → repair → integrate → test → rescan → review → commit → push within the user's authorization. Keep original source hashes and link corrected modules to their uploads. Execute corrected `scripts/*.py`; archived truncated samples and faulty historical snippets remain reference data. Run affected checks and record baseline failures. Verify remote main SHA and committed files after push.

Report remaining gaps honestly. Offline checks do not establish 140 implemented employees, whole-platform completion, live-source verification, deployment health, enterprise qualification or market superiority.
