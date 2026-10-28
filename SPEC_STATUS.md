# PatchTrace specification status

Date: 2026-10-28. Base commit: `e093ade` (origin/main, after PR #97). The working branch `claude/patchtrace-haiku-agent-motpbx` (PR #102, draft, not merged) adds SPEC-26 A registry tooltips, SPEC-52 WIN-1 (version resource and icon), the CI restructure and exact dev pins; rows below say "branch" where that matters. Method: every spec file under `docs/specs/` (103 files; INDEX.md and REGISTRY.md excluded; the file set at `e093ade` is identical to the working tree) was matched to its canonical ID and status in `docs/specs/REGISTRY.md`, and to its own Status line. Each was then checked against code at `e093ade` with `git ls-tree` and `git grep`, using slice tags in `docs/modules.md` and items in `tasks/todo.md`. GitHub was read over REST only (default branch, PR state). Paths in the Spec column are under `docs/specs/`; paths in Evidence are repository-relative. While this status was being compiled, the working tree gained uncommitted edits by another worker (`tools/build_windows.py`, `pyproject.toml`, `src/patchtrace/__main__.py`, and new untracked icon and version-info files for SPEC-52 WIN-1). They are not on main and were not counted; the working tree was clean when the run started.

Legend.
- DONE: functional scope on main; nothing open.
- PARTIAL: some functional scope built on main, some open.
- MISSING: approved or draft with no functional code on main. "(draft, not approved)" marks a draft or proposal, not a defect.
- EXTERNAL: code built; only external acceptance (native Windows run, live tool, manual GUI) or an owner decision or ratification is open.
- N/A: index, audit, review log, ledger or research output with no build scope. The four status words do not fit these.
- "(draft)" after a status: the spec's own status is draft or proposal.
- "tracker": an item from `tasks/todo.md` that was not re-checked against code. "unverified": not confirmed.
- Program E plans (`program-e/`) are unregistered; they are included here.

Summary: DONE 4 | PARTIAL 61 | EXTERNAL 13 | MISSING 18 (9 draft or proposal not approved; 7 approved with no code; 2 plan or deferred) | N/A 7 | total 103.

| Spec (under docs/specs/) | ID | Status | Evidence (key files) | Open items |
|---|---|---|---|---|
| architecture.md | SPEC-01 | DONE | src/patchtrace/ingestion.py, backend.py, jobs.py, persistence.py, service.py, models.py | None recorded (registry: built); unverified beyond file existence. |
| accessibility-baseline.md | SPEC-45 (proposed) | PARTIAL (draft) | 82 setAccessibleName occurrences under src/patchtrace (mostly ui*.py); tooltips.py | AX-M1 to AX-M6 owner and Windows gates; the 54-control gap from 2026-10-14 not re-counted (unverified). |
| acquisition.md | SPEC-08 | EXTERNAL | src/patchtrace/acquisition/ (contracts, winbindex, transport, quarantine, delta, workflow); ui.py AcquisitionDialog | Windows msdelta run; live Winbindex and msdl fetch (tracker: proxy 403). |
| ai-provider-interpretation.md | SPEC-41 (draft) | PARTIAL (draft) | src/patchtrace/providers.py:70-79 refuses IPv4-mapped IPv6 literals (fix verified); interpretation.py; evidence.py | R12, R15, R25, R26, R35 to R37, R29 severity part, G11, G13 to G16, G18 to G20; live provider acceptance. |
| anchor-fabric.md | SPEC-48 | PARTIAL | src/patchtrace/fabric/ (11 files); cli_commands/fabric.py (FAB-5 verbs); pilot/origins.py imports ..fabric (FAB-3); tests/test_fabric_*.py | FAB-6 related panel, blocked on the GUI panel registry; Windows CI and 20,000-anchor timing gate; spec sections 5 and 6 still list FAB-3 and FAB-5 as unbuilt. |
| app-settings.md | SPEC-43 (requested) | EXTERNAL (draft) | src/patchtrace/ui.py, ui_evidence.py, ui_series.py, ui_engine_setup.py; enrichment/profiles.py; tests/network_guard.py | Section 8 proposals await owner approval (owner decision). |
| bindiff-adapter.md | SPEC-10 | EXTERNAL | src/patchtrace/secondary/bindiff.py, bindiff_probe.py, bindiff_inputs.py, bindiff_run.py, evidence_view.py; src/patchtrace/ui_engine_setup.py | Live BinDiff 8 run and human goldens only (registry and tracker). |
| bindiff-execution.md | SPEC-29 | EXTERNAL | secondary/bindiff_probe.py, bindiff_inputs.py (AcceptedBinExportLike Protocol), bindiff_run.py, cli_bindiff.py; tools/provision_bindiff.py; tools/bindiff_pin.json | P6 live Linux and Windows run; real Ghidra or IDA BinExport pair; live-bindiff promotion (tracker). |
| binexport-producer-ghidra-host.md | SPEC-49 (draft ADR) | EXTERNAL (draft) | src/patchtrace/unified/extract/ (S1 extractor); secondary/binexport*.py | Owner sign-off on who produces BinExport2 (ADR pending). |
| binexport2-support.md | SPEC-10b | EXTERNAL | secondary/binexport*.py; secondary/cli_binexport.py; tools/fuzz_binexport.py; tools/qa_binexport_memcap.py | Nightly fuzz evidence; Windows memory-cap run; human Ghidra and IDA goldens (C3-7). |
| byte-representations.md | SPEC-26-B | PARTIAL | src/patchtrace/representations/ (6 files); raw_view.py; artifact_bytes.py | Verified function extents; async paging; persisted results (registry; spec has no Status line). |
| calibration-corpus-and-model.md | SPEC-39 (proposed; was SPEC-28 C9) | PARTIAL (draft) | src/patchtrace/calibration/ (9 files, ships); tools/calibration/ (dev only) | C9-0 ratification; C9-3 Tier R recipes; labelling blocked on owner decisions O1, O2, O4; GUI C9-12 gated by locked test (tracker). |
| cli-umbrella.md | SPEC-44 (proposed) | PARTIAL (draft) | src/patchtrace/cli.py (COMMANDS tuple); backend_cli.py; cli_commands/ | doctor, export and show not found in cli.py (grep); spec defers import and project; owner ratification. |
| completeness-audit.md | none (audit) | N/A (audit) | none | Per-row statuses stale (registry handoff note B4); cite by path only. |
| csaf-cve-interpretation-engine.md | SPEC-35 (was SPEC-28 title) | PARTIAL | src/patchtrace/intelligence/ (anchors, explain, hypotheses, lexicon, reports, storage, cli); intelligence/csaf/ | Tests 6.1.11 (CWE catalogue), 6.1.12, 6.1.13 not implemented; live Microsoft metadata, documents, .sha256 and consented fetch (external). |
| diaphora-optional-engine.md | SPEC-DA-01 | MISSING (approved) | none; unified/read_model.py:348 only renders a 'diaphora' source row | Adapter and its two named tests (tracker); draft PR #100 carries Mode A import, not on main. |
| enrichment-hardening-backlog.md | SPEC-07h | EXTERNAL | src/patchtrace/enrichment/cache.py, storage.py, intelligence.py, cve.py; verified_backup.py; raw_cleanup.py; tools/live_nvd_probe.py | First live run; H7 default flip after Windows CI (registry, tracker). |
| enrichment.md | SPEC-07 | PARTIAL | src/patchtrace/enrichment/ (13 files: cache, ranking, signals, views, pipeline, storage) | 500 ms cache-hit objective not met: 1.31 s best-of-3 (2026-10-28, 4 vCPU); the spec-required re-validation alone is about 0.65-0.8 s, so meeting it needs a persisted ranking stage (contract change) or an owner relaxation; 10k-pair UI gate unmeasured; handoff-package validation (package not supplied). |
| ghidriff-launcher-symbols.md | SPEC-53 (draft) | MISSING (draft, not approved) | none on main; no launcher in src/patchtrace/backend.py | PatchTrace-owned Ghidriff launcher and local-only symbol policy (tracker); draft PR #100 titled "SPEC-53 local symbol mode + launcher" is not on main. |
| gui-framework.md | SPEC-54 | PARTIAL | src/patchtrace/gui/ (registry.py PanelSpec at line 133, anchors, projection, capabilities, ports); gui/qt/ (host, tasks, theme, table, codediff, docks); panel.py in nway/, pilot/, unified/ | a11y_audit has 0 references in src; spec line 5 "Not built" list stale; manual gates M19 to M28 (external); F7 theme submenu and reduced motion (tracker). |
| gui-preflight-inspection.md | SPEC-26 (parent; parts A, C, E) | PARTIAL | src/patchtrace/ui.py, tooltips.py, ui_inspection.py, preflight.py, artifact_inspection.py; branch (PR #102): swap-orientation confirm and critical error box use registry tips | SPEC-26 A per-row plain_tip templates and both-theme and display-scaling tooltip tests (branch, PR #102 draft); part E multi-engine panel (tracker). |
| kb-cve/31-A-contracts-identity.md | KBC-A (SPEC-34) | PARTIAL | src/patchtrace/kbcorrelation/contracts.py, ids.py, products.py (K0 tag) | Per-section gaps unverified; registry "design only" is stale. |
| kb-cve/31-B-msrc-reverse-index.md | KBC-B (SPEC-34) | PARTIAL | kbcorrelation/index.py, sources/cvrf.py, sources/cvrf_fetch.py, sources/importer.py (K1, K6 tags) | Live MSRC provider metadata and directory layout (external); provider research. |
| kb-cve/31-C-product-build-pairs.md | KBC-C (SPEC-34) | PARTIAL | kbcorrelation/products.py, pairs.py, plan.py, lineage.py, resolver.py (K5 tags) | Pair-resolution wiring into kb pairs and kb plan (tracker, unverified). |
| kb-cve/31-D-acquisition-packages.md | KBC-D (SPEC-34) | PARTIAL | kbcorrelation/acquire.py, cli_acquire.py, recovery.py, workflow.py (K7 tags) | Acquirer binding (tracker: integrator); K7 UI; live package download (external). |
| kb-cve/31-E-evidence-intent.md | KBC-E (SPEC-34) | PARTIAL | kbcorrelation/leads.py, cli_leads.py (K4a tag); pilot/ (SPEC-30 built) | Semantic mechanisms depend on SPEC-28 and SPEC-30; no KB leads UI (no ui_kb module). |
| kb-cve/31-F-workflow-ui-persistence.md | KBC-F (SPEC-34) | PARTIAL | kbcorrelation/workflow.py, store.py, recovery.py, service.py (K3 tag); cli_commands/kb.py | K3 GUI and K7 UI: no ui_kb or tooltips_kb_online module at e093ade. |
| kb-cve/31-G-components-discovery.md | KBC-G (SPEC-34) | PARTIAL | kbcorrelation/components.py, context.py | Component discovery coverage against sub-spec unverified. |
| kb-cve/31-H-tests-release.md | KBC-H (SPEC-34) | PARTIAL | 62 test files named kbc or kb_ under tests/ | Live probes (external); release gates unverified. |
| kb-cve/README.md | SPEC-34 (index) | N/A (index) | none | Index of sub-specs; their statuses are above. |
| kb-cve-correlation-and-acquisition.md | SPEC-34 (was SPEC-31 KB) | PARTIAL | src/patchtrace/kbcorrelation/ (37 files; K0 to K7 tags in docs/modules.md); cli_commands/kb.py | K3 GUI and K7 UI (none at e093ade); K8 KEV, unified and secondary adapters (tracker); live MSRC and NVD fetch (external). |
| kb-patch-search-and-pair-resolution.md | SPEC-37 (was SPEC-32) | MISSING (approved) | none: no patch_search package on e093ade | patch_search/service.py facade and all adapters not started; PR #41 closed unmerged, but its docs are on main. |
| kb-patch-search-contract-blueprint.md | KPS-E (SPEC-37) | MISSING (approved) | none (examples, not runtime code) | Implementation examples only; no runtime code. |
| kb-patch-search-pair-lifecycle.md | KPS-B (SPEC-37) | MISSING (approved) | none | Pair eligibility, session storage and crash recovery not started. |
| kb-patch-search-qa-and-fixtures.md | KPS-D (SPEC-37) | MISSING (approved) | none; draft PR #69 adds synthetic fixtures (not on main) | Test corpus, acceptance gates and failure injection not started. |
| kb-patch-search-source-adapters.md | KPS-A (SPEC-37) | MISSING (approved) | none | Microsoft patch-search source adapters not started. |
| kb-patch-search-ui-cli-contract.md | KPS-C (SPEC-37) | MISSING (approved) | none | GUI and CLI contract not started. |
| kev-exploitation-context.md | SPEC-46 (draft) | PARTIAL (draft) | src/patchtrace/kev/ (16 files: contracts, store, service, cli, kb_adapter, report, project_context); cli_commands/kev.py; tools/live_kev_probe.py | No KEV GUI (no kev UI module); CISA feed URL unverified (gate K6, external); spec still says no KEV code on main (stale). |
| known-answer-corpus.md | SPEC-32 | PARTIAL | corpus/ (catalog, ours, README); tools/calibration/tier_r (47 files); tools/unified/corpus/ | Tracker M1 catalogue (14+ projects) and M2 CVE cases unmet (unverified); tracker says M3 mutations not built, but tools/calibration/mutations/ exists. |
| multi-engine-evidence-calibration.md | SPEC-27 | PARTIAL | src/patchtrace/secondary/reconcile.py, evidence.py; src/patchtrace/calibration/ | Index not calibrated; no security-finding confidence score (spec status line); calibration gate awaits SPEC-39. |
| multi-engine-evidence-panel.md | SPEC-38 (proposed; collision) | PARTIAL | secondary/evidence_panel.py, evidence_panel_service.py, evidence_table.py, evidence_view.py; ui_evidence.py | Product decision D5 (evidence status in exported reports); C8 NVDA and DPI manual gates (external). |
| multi-engine-orchestration.md | SPEC-28 | PARTIAL | src/patchtrace/secondary/runs.py, registry.py, scheduler.py, store.py, cli_run.py | Adapters emitting alternatives; C2 live workflow (external). |
| network-egress-privacy.md | SPEC-42 (draft) | PARTIAL (draft) | acquisition/transport.py; enrichment/intelligence.py; intelligence/csaf/transport.py; providers.py; netutil.py; tests/network_guard.py | Spec section 7 gaps: network census, offline switch, F4, F5 tests; owner decision on restrict_env default. |
| non-goals.md | SPEC-55 (draft) | EXTERNAL (draft) | none (decision record) | Owner ratification of non-goals and deferred decisions. |
| nway.md | SPEC-09 | EXTERNAL | src/patchtrace/nway/ (contracts, graph, series, view_model, pair_access, panel) | Native three-build CI acceptance only (registry). |
| offline-backend-installer.md | SPEC-06 | PARTIAL | src/patchtrace/offline_bundle.py, backend_bundle.py, ui_bundle_setup.py; tools/build_backend_bundle.py; .github/workflows/backend-bundle.yml | Real relocatable Python, Ghidriff, Ghidra and JDK payload not assembled; clean Windows disk, path and AV smoke (tracker). |
| patch-intent-localization-engine.md | SPEC-30 (draft, deferred) | PARTIAL (draft) | src/patchtrace/pilot/ (34 files: service.py localize, fusion, tiers, ranking, why, report, store, panel.py, sources/) | Calibration gate; plan s10 owner amendments; live Ghidriff labels and capa, FLOSS and DiE deltas (blocked live); Windows CI. |
| pe-overview.md | SPEC-26-D | PARTIAL | src/patchtrace/pe_overview/ (24 files: authenticode, version_info, manifest, resources, exports_table, build_facts, panel) | Signed and trusted Windows acceptance (external); persistence keyed by hash (registry); spec "Not done" still lists version info (stale). |
| pe-version-authenticode.md | SPEC-51 (SPEC-26 D2) (draft) | PARTIAL (draft) | pe_overview/resources.py, version_info.py, manifest.py, authenticode.py; tests/test_pe_resources.py; tests/test_pe_version_info.py | DER and embedded-signature digest; catalog check; compare rows; CLI and GUI tab (registry). |
| program-e/BUNDLE-integration-plan.md | unregistered (plan) | PARTIAL | src/patchtrace/offline_bundle.py, backend_bundle.py; tools/build_backend_bundle.py; .github/workflows/backend-bundle.yml; tags B1 to B8 | Publish relocatable payload; clean Windows offline smoke (tracker). |
| program-e/CAP-integration-plan.md | unregistered (plan) | PARTIAL | src/patchtrace/intelligence/tools/capa_pairs.py, capa_view.py, capa_hints.py, capa_cache.py (CAP-1 to CAP-5, CAP-7 tags) | CAP-6a Qt model (no capa view in gui/); intel-tools pairs verb; capa memory_limit option (tracker). |
| program-e/DIE-integration-plan.md | unregistered (plan) | PARTIAL | src/patchtrace/buildenv/ (14 files; D1 to D4, D6 tags); cli_commands/build_env.py | D5 card, controller, tooltips and D7 timeline (not in buildenv/); D8 live DiE golden; D9 G-DIE-1. |
| program-e/E6-test-performance-beta-plan.md | unregistered (plan) | MISSING (plan) | none (plan; no source change per its status line) | Final feature audit, bug check, scripted beta, performance and Windows smoke, all open. |
| program-e/FAB-integration-plan.md | unregistered (plan) | PARTIAL | src/patchtrace/fabric/; cli_commands/fabric.py (FAB-5); pilot/origins.py (FAB-3) | FAB-6 related panel (blocked on GUI panel registry); Windows CI and timings. |
| program-e/GDE-integration-plan.md | unregistered (plan) | MISSING (deferred) | none: no guide/ package at e093ade | Deferred by registry until the GUI panel registry and anchors land; gui/registry.py PanelSpec now exists; owner decision. |
| program-e/GUI-integration-plan.md | unregistered (plan) | PARTIAL | src/patchtrace/gui/ (registry, qt/ host, tasks, table, codediff, docks, theme); ui_unified.py; tags GUI-F1 to GUI-F9 | F7 theme submenu, theme_changed and reduced motion (tracker); manual gates M19 to M28 not run (external). |
| program-e/KB-integration-plan.md | unregistered (plan) | PARTIAL | src/patchtrace/kbcorrelation/ (tags K0 to K7); cli_commands/kb.py | K3 and K7 UI (no ui_kb module); K8 adapters (tracker). |
| program-e/KB2-source-facts.md | unregistered | N/A (research output) | none | Source facts and synthetic fixtures; no build scope. |
| program-e/KEV-integration-plan.md | unregistered (plan) | PARTIAL | src/patchtrace/kev/ (K1a, K1b, K2 cli and service, K4 kb_adapter, K5 report and project_context); tools/live_kev_probe.py (K6) | K3 GUI (absent); K6 live gate: canonical CISA URL unverified (external). |
| program-e/LBL-integration-plan.md | unregistered (plan) | PARTIAL | tools/calibration/ (tier_r; tier_w/run_local.py; mutations/); docs/modules.md tags LBL-15, LBL-17 | Tier W runner and labelling campaign (owner decisions O1, O2, O4); draft PRs #78, #79, #82, #85 (LBL-30 to LBL-32) open. |
| program-e/OUTSTANDING-specs-ledger.md | unregistered | N/A (ledger) | none | Ledger of findings F2 to F5 and F10 as of 2026-10-14; stale. |
| program-e/PIL-integration-plan.md | unregistered (plan) | PARTIAL | src/patchtrace/pilot/ (tags A1 to A3, B1, B2, C1, C2, D1, T); pilot/panel.py; cli_commands/pilot.py | Calibration gate; plan s10 owner amendments; Windows CI for pilot tests (external). |
| program-e/README.md | unregistered | N/A (index) | none | Index of Program E plans. |
| program-e/WB1-integration-plan.md | unregistered (plan) | PARTIAL | src/patchtrace/search/ (26 files; WB1-S0, S1, S2 tags); cli_commands/search.py | Slices S3 to S9 not tagged (unverified); Windows probe gate (tracker). |
| program-e/WB2-integration-plan.md | unregistered (plan) | PARTIAL | src/patchtrace/callgraph/ (29 files; G0 to G5, G7 tags); cli_commands/graph.py | G6 and later not tagged (unverified); live Ghidriff matches-label gate (tracker). |
| program-e/WB3-integration-plan.md | unregistered (plan) | PARTIAL | src/patchtrace/strings/ (23 files; WB3-S0 to S7a tags); cli_commands/strings.py | Real FLOSS and Ghidriff goldens (S9, external); later slices per plan (unverified). |
| program-e/WBQ-integration-plan.md | unregistered (plan) | PARTIAL | pe_overview/resources.py, manifest.py, exports_table.py (S1, S2, S4); src/patchtrace/codetext/ (S7, S8); src/patchtrace/symbols/ (S10) | S9 highlighter attach (tracker); S11 to S13 not built (tracker); Windows LF fixture checks (external). |
| program-e/YRX-integration-plan.md | unregistered (plan) | PARTIAL | src/patchtrace/rules/ (22 files; R0 to R5 tags; engine.py imports yara_x); cli_commands/rules.py; pyproject rules extra yara-x==1.21.0 | Frozen smoke R1 and R2 checks and Windows CI (tracker); rules GUI unverified. |
| qbindiff-inspired-matching.md | SPEC-QB-01 (draft) | MISSING (draft, not approved) | none: no matching/ package | Proposed; not implemented. |
| qbindiff-modular-integration.md | SPEC-QB-02 (draft) | MISSING (draft, not approved) | none | Companion to SPEC-QB-01. |
| radiff2-inspired-comparison.md | SPEC-RD-01 (draft) | MISSING (draft, not approved) | none: no comparison/ package | Proposed; no feature implemented. |
| radiff2-modular-integration.md | SPEC-RD-02 (draft) | MISSING (draft, not approved) | none | Companion to SPEC-RD-01. |
| report-export-contract-v2.md | SPEC-50 (draft for build) | MISSING (draft, not approved) | src/patchtrace/reports.py (v1 only; grep finds no v2 contract) | Build not started; v2 opt-in; owner approval to build unverified. |
| runtime-discovery.md | SPEC-05 | DONE | src/patchtrace/runtime_discovery.py | None recorded (registry: built; read-only discovery). |
| schemas.md | SPEC-02 | DONE | src/patchtrace/models.py; tools/generate_schemas.py and 10 tools/generate_*_schemas.py | None recorded (registry: built). |
| secondary-engine.md | SPEC-11 | EXTERNAL | src/patchtrace/secondary/rzdiff.py, registry.py, engine_env.py; tools/live_rzdiff_check.py | First live rizin evidence; external acceptance (registry). |
| series-window.md | SPEC-09b | PARTIAL | src/patchtrace/nway/view_model.py, pair_access.py; ui_series.py | Open-pair live-project path (registry). |
| three-tool-evidence-adapters.md | SPEC-36 (was SPEC-29 three-tool) | PARTIAL | src/patchtrace/intelligence/tools/ (capa, capa_pairs, capa_view, capa_hints, capa_cache, floss, diec, runner, store); tools/provision_intel_tools.py | intel-tools pairs verb and capa memory-limit option (CAP-1, CAP-5); live runs and DiE value gate (external). |
| tier-w-local-corpus.md | SPEC-33 | PARTIAL | tools/calibration/tier_w/ (10 files incl. run_local.py, pairs.py, msf.py, pe_tables.py) | Exporters, labels and CLI deferred (registry); run_local.py exists, so runner status conflicts (see drift); owner decision O1. |
| ui.md | SPEC-04 | EXTERNAL | src/patchtrace/ui.py and ui_*.py (ui_evidence, ui_series, ui_leads, ui_pemeta, ui_inspection) | Clean Windows GUI acceptance; DPI and screen-reader checks (external). |
| unified-engine/00-decisions.md | SPEC-31/00 (draft) | EXTERNAL (draft) | src/patchtrace/unified/ (contracts, extract, ladder, worker) | USER decisions U-01 to U-12 open (defaults in spec section 4). |
| unified-engine/01-architecture.md | SPEC-31/01 (draft) | PARTIAL (draft) | src/patchtrace/unified/ (68 files) | Remaining slices; registry "nothing implemented" is stale. |
| unified-engine/02-data-model.md | SPEC-31/02 (draft) | PARTIAL (draft) | unified/contracts.py, keys.py, limits.py, store.py, registry.py | place_ir, find_ir and orphan result-dir sweep deferred (tracker). |
| unified-engine/03-extraction.md | SPEC-31/03 (draft) | EXTERNAL (draft) | unified/extract/ (decomp.py, ghidra_script.py, retain.py, runner.py); unified/sources/ghidriff.py | Windows live-unified run and MSVC-built IR (blocked, tracker); G-U5 on frozen EXE (external). |
| unified-engine/04-matching-pipeline.md | SPEC-31/04 (draft) | PARTIAL (draft) | unified/ladder/ (blocking.py, residual.py, assign.py, passes.py) | P16 to P19 and LAP (tracker; blocking.py and residual.py exist, passes unverified); G-U3 parity blocked (external). |
| unified-engine/05-fusion-and-noise.md | SPEC-31/05 (draft) | PARTIAL (draft) | unified/fusion/, unified/facts/ (S0b and S3 tags) | G-U1 and G-U2 recall on Windows and MSVC-built IR (tracker, external); other IR gates unverified. |
| unified-engine/06-adapters.md | SPEC-31/06 (draft) | PARTIAL (draft) | unified/sources/ghidriff.py, manual.py, secondary.py | Diaphora adapter (SPEC-DA-01, not built); real BinDiff and rz-diff inputs (tracker). |
| unified-engine/07-ui-and-cli.md | SPEC-31/07 (draft) | PARTIAL (draft) | src/patchtrace/ui_unified.py (778 lines, UE-S4b tag); unified/panel.py, cli.py, read_model.py | Tooltips and accessibility items (tracker S4); Windows manual gates (external). |
| unified-engine/08-evaluation.md | SPEC-31/08 (draft) | PARTIAL (draft) | tools/unified/ (corpus, bench.py; S6a tag) | S6b evaluators G-U1, G-U2, G-U4, G-U6, G-U7; G-U3 parity needs real BinDiff (blocked live). |
| unified-engine/09-licensing.md | SPEC-31/09 (draft) | PARTIAL (draft) | docs/notices.md; docs/reuse-matrix.md (both present) | Tracker A-24 notice and reuse-matrix rows (integration owner); per-source notice check unverified. |
| unified-engine/10-amendments.md | SPEC-31/10 (draft) | PARTIAL (draft) | none (amendments are edits to other specs, applied per slice) | Amendment rows A-15 and A-24 open (tracker). |
| unified-engine/11-review-log.md | SPEC-31/11 | N/A (review log) | none | Review log, not a spec. |
| unified-engine/12-features2-proposal.md | SPEC-31/12 (proposal) | MISSING (proposal, not approved) | none | features/2 proposal only; owner decision on the C9 track. |
| unified-engine/README.md | SPEC-31 (draft) | PARTIAL | src/patchtrace/unified/ (68 files; S0a to S6a tags); ui_unified.py; tools/unified/ | Remaining slices (S6b, parity); USER decisions U-01 to U-12 (owner); live Windows evidence (external). |
| verification.md | SPEC-03 | DONE | tests/ (697 paths); docs/qa.md | None recorded (requirements and audit record). |
| windows-acceptance-and-milestone-builds.md | SPEC-40 (proposed) | PARTIAL (draft) | tools/build_windows.py, build_linux.py, frozen_smoke.py, milestone_notes.py; .github/workflows/qa-windows.yml | native A6 run unverified (only A6s-style checks matched); A7, A8, A11, A12 not found in tools/frozen_smoke.py; hard-coded release name at qa-windows.yml:216. |
| windows-release-signing-policy.md | SPEC-52 (draft) | PARTIAL (draft) | branch (PR #102): tools/windows_version_info.py, tools/windows_icon.py, tools/check_windows_exe.py, src/patchtrace/app_icon.py, tools/build_windows.py, .github/workflows/qa-windows.yml | WIN-1 built without the manifest (fallback); WIN-4 in part (tag-named release, split Windows jobs); WIN-2 SHA256SUMS, WIN-3 policy check, WIN-5 signing (owner decision), WIN-6 About dialog open. |
| workbench/01-search-fts5-rapidfuzz.md | PT-WB-01 | PARTIAL | src/patchtrace/search/ (26 files; WB1-S0 to S2 tags); cli_commands/search.py; pyproject search extra rapidfuzz==3.14.6 | Slices after S2 not tagged (unverified); Windows probe (tracker); spec status line "not implemented" is stale. |
| workbench/02-networkx-callgraph.md | PT-WB-02 | PARTIAL | src/patchtrace/callgraph/ (29 files; G0 to G5, G7 tags); cli_commands/graph.py; networkx is a dev-only oracle | G6 not tagged (unverified); live Ghidriff matches-label gate and windows-latest probe (tracker, external). |
| workbench/03-floss-strings.md | PT-WB-03 | PARTIAL | src/patchtrace/strings/ (23 files; WB3-S0 to S7a tags); intelligence/tools/floss.py; cli_commands/strings.py | Real FLOSS and Ghidriff goldens (external); later slices per spec (unverified). |
| workbench/04-quickwins.md | PT-WB-04 (draft) | MISSING (draft, not approved) | none for PT-WB-QW; built quick wins sit under WBQ (pe_overview/resources.py, codetext/, symbols/) | Ranked proposals only; owner to choose which to adopt. |
| workbench/README.md | PT-WB (index) | N/A (index) | none | Index for PT-WB-01 to PT-WB-04. |
| yara-x-rule-workflow.md | SPEC-47 (draft) | PARTIAL (draft) | src/patchtrace/rules/ (22 files; R0 to R5 tags; engine.py imports yara_x); cli_commands/rules.py; pyproject rules extra yara-x==1.21.0 | Frozen smoke R1 and R2 checks and Windows CI (tracker); spec status line "no rules package" is stale. |

## This run (2026-10-28, PR #102)

Built on the branch: SPEC-26 A swap/critical box tooltips; SPEC-52 WIN-1 (no manifest) and part of WIN-4; report export backup (architecture.md "Reports"); parser boundary hardening (SECURITY_REVIEW.md F1, F3, F4, F6, F7, F8). Measured and left open with evidence: SPEC-07 500 ms objective (1.31 s), Ghidriff import memory (F5). Release evidence: docs/qa.md WIN-ALPHA.

## Registry drift

Registry (`docs/specs/REGISTRY.md`) against code at `e093ade`:
- SPEC-47 yara-x (Table A): "planned rules/; no src/patchtrace/rules/ package". Code: `src/patchtrace/rules/` (22 files), `engine.py` imports `yara_x`, `docs/modules.md` tags R0 to R5.
- SPEC-46 kev (Table A): "planned enrichment/kev; nothing implemented". Code: `src/patchtrace/kev/` (16 files), `cli_commands/kev.py`, tags K1a, K1b, K2, K4, K5.
- PT-WB-01 (Table B): "none (planned search index)". Code: `src/patchtrace/search/`, tags WB1-S0 to S2, `cli_commands/search.py`.
- PT-WB-02 (Table B): "none (planned)". Code: `src/patchtrace/callgraph/`, tags G0 to G5 and G7, `cli_commands/graph.py`.
- PT-WB-03 (Table B): "planned intelligence/tools/floss.py". Code: `src/patchtrace/strings/`, tags WB3-S0 to S7a.
- SPEC-54 gui-framework (Table A): "Qt host layer, panels and accessibility audit not built". Code: `src/patchtrace/gui/qt/` (host.py, tasks.py, theme.py), `PanelSpec` at `gui/registry.py:133`, `panel.py` in nway/, pilot/, unified/. The accessibility-audit part holds (`a11y_audit`: 0 references).
- SPEC-31/07 (Table A, unified-engine/07): "ui_unified.py not built". Code: `src/patchtrace/ui_unified.py` (778 lines), tag UE-S4b.
- SPEC-34 kb-cve (Table B): "K0 to K2 built; open acquisition packages, UI, workflow"; 31-A "design only". Code: `kbcorrelation/` has tags K3 to K7 (`acquire.py`, `cli_acquire.py`, `cli_leads.py`, `cli_online.py`); `contracts.py` is K0. UI open (no ui_kb module).
- SPEC-48 anchor-fabric (Table A): "open: FAB-3 PIL adoption, FAB-5 CLI". Code: `pilot/origins.py:14-16` imports `..fabric`; `cli_commands/fabric.py` implements the FAB-5 verbs. Only FAB-6 remains.
- SPEC-30 PIL (Table A): "open: GUI, calibration gate, reports". Code: `pilot/report.py`, `pilot/panel.py`, `cli_commands/pilot.py` exist (C1, C2 tags). Remaining: calibration gate.
- SPEC-26-D pe-overview (Table A): open "version info". Code: `pe_overview/version_info.py`, `resources.py`, `manifest.py` (SPEC-51 D2-1, D2-2).
- SPEC-41 ai-provider (Table A basis): open finding "loopback check differs on CPython 3.12 vs 3.13". Code: `providers.py:70-79` refuses IPv4-mapped IPv6 literals before the loopback check. Verified fixed.
- SPEC-33 tier-w (Table B): "runner deferred". Code: `tools/calibration/tier_w/run_local.py` exists.
- SPEC-36 three-tool (Table B owner list): omits `intelligence/tools/capa_pairs.py`, `capa_view.py`, `capa_hints.py`, `capa_cache.py` (CAP slices).
- Open PRs (Table B and snapshot): REGISTRY lists #40, #41, #43 open and #42 draft. REST on 2026-10-28: #40, #41, #43 closed unmerged; #42 merged (67e5a6c); #95, #97, #99 merged. The spec files from #40, #41 and #43 are on main at `e093ade`; how they landed is unverified. The registry snapshot "main = 1560531" is stale (main = `e093ade`).
- SPEC-56 collision: REGISTRY says SPEC-56 is the next free number. Open PR #61 (`codex/agent-skills-spec56-20261014`, not draft) uses SPEC-56 for agent skills.
- Open PRs not in the registry: #100 (draft; SPEC-53 launcher and SPEC-DA-01 Mode A import), #102 (draft; SPEC-26 A, the working branch), #78, #79, #82, #85 (LBL-30 to LBL-32), #69 (KB patch-search fixtures), #86, #83, #88 (UE-R3, UE-R7).
- `docs/specs/INDEX.md` lists `program-e/RPT2-report-export-contract-v2.md`; the file is absent (promoted to `docs/specs/report-export-contract-v2.md`).
- Spec status lines stale against code: `kev-exploitation-context.md` ("no KEV code on main"); `yara-x-rule-workflow.md` ("no rules package"); `workbench/01` ("not implemented"); `workbench/02` ("unimplemented"); `gui-framework.md` (line 5 "Not built" list); `anchor-fabric.md` section 5.

Tracker (`tasks/todo.md`) against code:
- Line 9: "Verify PR #95 on Windows CI, merge only after all release gates pass". PR #95 is merged as `08f6a5f` (REST). Release publish state is unverified.
- Line 133: M3 planted mutations "not built (tools/calibration/mutations/)". The directory exists at `e093ade` (6 files).
- Line 118: `intelligence/reports.py` and `intelligence/cli.py` deferred. Both exist.
- Line 174: "intelligence explain (not built yet)". `intelligence/explain.py` exists.
- Lines 110 and 563: `ui_unified.py` open. The file exists (778 lines).
- Line 363: "GUI F1 to F9 not started". `gui/qt/` exists and `docs/modules.md` has GUI-F tags.
- Lines 352, 451 to 455, 577 to 578: KB K2 and KEV K2 "not built". `kbcorrelation/service.py`, `store.py`, `kev/cli.py`, `kev/service.py` exist.
- Line 294: WB3 anchor join "not built (S6)". Tag WB3-S6:anchors-export-cli is in `docs/modules.md` (code not re-verified).
- Line 183: S5 P16 to P19 and LAP "not started". `unified/ladder/blocking.py` and `residual.py` exist (passes unverified).

Classification moves (not code disagreements): registry "partial" rows whose only open items are external acceptance are shown as EXTERNAL here: SPEC-10, SPEC-29, SPEC-11, SPEC-07h, SPEC-08, unified-engine/03.

## Blockers

- `gh pr list` (GraphQL) is refused in this session (HTTP 403); PR state was read via REST `pulls` and `pulls/{n}`.
- Open-PR check status (CI) was not read.
- Windows-only claims, live provider and BinDiff runs, and manual GUI gates are external and not verified.
- `tests/test_spec_registry.py` was not run. All 103 non-program-e spec files are cited in REGISTRY.md (checked by grep).
- The SPEC-52 WIN-1 working-tree changes seen during the first pass belong to this same branch (PR #102); the row above was updated after they were committed.
