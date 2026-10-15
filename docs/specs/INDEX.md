# Spec index

Listing of every file under `docs/specs/`, 2026-10-14. SPEC number and status come from `docs/specs/REGISTRY.md`, which is the authority and wins on any conflict. "unregistered" marks Program E plans under `program-e/`, which the registry test excludes; their status is the first words of their own Status line. Update by hand when a spec is added.

| File | SPEC | Status | Title |
|---|---|---|---|
| [REGISTRY.md](REGISTRY.md) | REGISTRY | n/a | Spec registry |
| [accessibility-baseline.md](accessibility-baseline.md) | SPEC-45 | draft | Accessibility, keyboard, DPI and localization baseline (SPEC-45) |
| [acquisition.md](acquisition.md) | SPEC-08 | partial | SPEC-08: Binary acquisition (Phase 3a) |
| [ai-provider-interpretation.md](ai-provider-interpretation.md) | SPEC-41 | draft | AI provider and interpretation contract (SPEC-41) |
| [app-settings.md](app-settings.md) | SPEC-43 | draft | App settings and persistence contract (SPEC-43) |
| [architecture.md](architecture.md) | SPEC-01 | built | PatchTrace beta architecture (SPEC-01, schema v1) |
| [bindiff-adapter.md](bindiff-adapter.md) | SPEC-10 | partial | SPEC-10: BinExport / BinDiff adapter (Phase 3c) |
| [bindiff-execution.md](bindiff-execution.md) | SPEC-29 | partial | SPEC-29: Real BinDiff execution (Phase C, step C4) |
| [binexport2-support.md](binexport2-support.md) | SPEC-10b | partial | SPEC-10b: BinExport2 support (Phase C, step C3) |
| [byte-representations.md](byte-representations.md) | SPEC-26-B | partial | Raw byte representations (SPEC-26 requirement B, Hex / Binary / Base64) |
| [calibration-corpus-and-model.md](calibration-corpus-and-model.md) | SPEC-39 (proposed; collision) | draft | SPEC-28 (proposed number): Calibration corpus, model pipeline and numeric-confidence gate (plan step C9) |
| [cli-umbrella.md](cli-umbrella.md) | SPEC-44 | draft | CLI umbrella contract (SPEC-44) |
| [completeness-audit.md](completeness-audit.md) | none (audit; cite by path) | n/a | Specification and implementation completeness audit |
| [csaf-cve-interpretation-engine.md](csaf-cve-interpretation-engine.md) | SPEC-35 (renamed) | draft | Microsoft CSAF CVE Interpretation Engine (SPEC-28) |
| [diaphora-optional-engine.md](diaphora-optional-engine.md) | SPEC-DA-01 | approved | SPEC-DA-01: Optional Diaphora comparison technique for PatchTrace |
| [enrichment-hardening-backlog.md](enrichment-hardening-backlog.md) | SPEC-07h | partial | SPEC-07h: Enrichment hardening backlog (P1 items of the 2026-10-14 audit) |
| [enrichment.md](enrichment.md) | SPEC-07 | partial | SPEC-07: Phase 2 enrichment — change signals, ranking, WIL, CVE context, cache |
| [ghidriff-launcher-symbols.md](ghidriff-launcher-symbols.md) | SPEC-53 | draft | PatchTrace-owned Ghidriff launcher and symbol policy (SPEC-53) |
| [gui-framework.md](gui-framework.md) | SPEC-54 | partial | GUI framework: panel registry, projection, anchors, theme, tooltips and CLI extensions (SPEC-54) |
| [gui-preflight-inspection.md](gui-preflight-inspection.md) | SPEC-26 (parent; parts A, C, E) | partial | Immediate next-build GUI and preliminary PE inspection requirements (SPEC-26 proposal) |
| [kb-cve/31-A-contracts-identity.md](kb-cve/31-A-contracts-identity.md) | KBC-A (SPEC-34) | approved | SPEC-31-A: Canonical Contracts, Identity, Provenance and Compatibility |
| [kb-cve/31-B-msrc-reverse-index.md](kb-cve/31-B-msrc-reverse-index.md) | KBC-B (SPEC-34) | approved | SPEC-31-B: MSRC Sources, KB Reverse Index, Coverage and Product-Scoped Remediation |
| [kb-cve/31-C-product-build-pairs.md](kb-cve/31-C-product-build-pairs.md) | KBC-C (SPEC-34) | approved | SPEC-31-C: Product/Build Lineage, Supersedence and Pair Resolution |
| [kb-cve/31-D-acquisition-packages.md](kb-cve/31-D-acquisition-packages.md) | KBC-D (SPEC-34) | approved | SPEC-31-D: Verified Acquisition, Delta Recovery and Offline Package Safety |
| [kb-cve/31-E-evidence-intent.md](kb-cve/31-E-evidence-intent.md) | KBC-E (SPEC-34) | approved | SPEC-31-E: Correlation Evidence Graph, Patch-Intent Rules, Confounders and Calibration |
| [kb-cve/31-F-workflow-ui-persistence.md](kb-cve/31-F-workflow-ui-persistence.md) | KBC-F (SPEC-34) | approved | SPEC-31-F: Transactional Workflow, Desktop/CLI Integration, Recovery and Migrations |
| [kb-cve/31-G-components-discovery.md](kb-cve/31-G-components-discovery.md) | KBC-G (SPEC-34) | approved | SPEC-31-G: Component Identification, Filename Evidence and Discovery Without Guesswork |
| [kb-cve/31-H-tests-release.md](kb-cve/31-H-tests-release.md) | KBC-H (SPEC-34) | approved | SPEC-31-H: Test Corpus, Quality Gates, PR Ownership and Failure Reproduction |
| [kb-cve/README.md](kb-cve/README.md) | SPEC-34 (index) | approved | SPEC-31 Implementation Addenda: Developer Handoff Index |
| [kb-cve-correlation-and-acquisition.md](kb-cve-correlation-and-acquisition.md) | SPEC-34 | approved | SPEC-31: Microsoft KB ↔ CVE Correlation, Verified Binary Pair Resolution, and Patch Investigation |
| [kb-patch-search-and-pair-resolution.md](kb-patch-search-and-pair-resolution.md) | SPEC-37 | approved | SPEC-32: KB Patch Search, CVE Resolution, and Verified Binary Pair Selection |
| [kb-patch-search-contract-blueprint.md](kb-patch-search-contract-blueprint.md) | KPS-E (SPEC-37) | approved | SPEC-32E: Python Contract Blueprint, Result Shapes, and Integration Examples |
| [kb-patch-search-pair-lifecycle.md](kb-patch-search-pair-lifecycle.md) | KPS-B (SPEC-37) | approved | SPEC-32B: Verified Binary Pair Eligibility, Session Storage, and Crash Recovery |
| [kb-patch-search-qa-and-fixtures.md](kb-patch-search-qa-and-fixtures.md) | KPS-D (SPEC-37) | approved | SPEC-32D: Test Corpus, Acceptance Gates, and Failure-Injection Protocol |
| [kb-patch-search-source-adapters.md](kb-patch-search-source-adapters.md) | KPS-A (SPEC-37) | approved | SPEC-32A: Microsoft Patch Search Data Sources and Correlation Contracts |
| [kb-patch-search-ui-cli-contract.md](kb-patch-search-ui-cli-contract.md) | KPS-C (SPEC-37) | approved | SPEC-32C: Patch Search GUI, CLI and Public Interface Contract |
| [known-answer-corpus.md](known-answer-corpus.md) | SPEC-32 | partial | SPEC-32: Known-answer corpus factory (Tier R, dev-only) |
| [multi-engine-evidence-calibration.md](multi-engine-evidence-calibration.md) | SPEC-27 | partial | SPEC-27: Cross-engine evidence fusion and calibration |
| [multi-engine-evidence-panel.md](multi-engine-evidence-panel.md) | SPEC-38 (proposed; collision) | partial | SPEC-28: Multi-engine evidence panel (Phase C, step C6) |
| [multi-engine-orchestration.md](multi-engine-orchestration.md) | SPEC-28 | partial | SPEC-28: Multi-engine orchestration (Phase C: C0, C1, C2, C5) |
| [network-egress-privacy.md](network-egress-privacy.md) | SPEC-42 | draft | Network egress, consent and privacy statement (SPEC-42) |
| [nway.md](nway.md) | SPEC-09 | built | SPEC-09: N-way build comparison (Phase 3b) |
| [offline-backend-installer.md](offline-backend-installer.md) | SPEC-06 | partial | SPEC-06: Verified offline backend bundle and installer |
| [patch-intent-localization-engine.md](patch-intent-localization-engine.md) | SPEC-30 | draft | Patch Intent Localization and Triage Engine (SPEC-30) |
| [pe-overview.md](pe-overview.md) | SPEC-26-D | partial | PE overview (SPEC-26 requirement D, backend stream) |
| [pe-version-authenticode.md](pe-version-authenticode.md) | SPEC-51 | partial | PE version resource, manifest and Authenticode verification without execution (SPEC-51; SPEC-26 D2) |
| [program-e/BUNDLE-integration-plan.md](program-e/BUNDLE-integration-plan.md) | unregistered | plan for build | BUNDLE: one-download full build (app + private Python/JDK/Ghidra/Ghidriff payload) |
| [program-e/CAP-integration-plan.md](program-e/CAP-integration-plan.md) | unregistered | Program E phase E-1 research plan | CAP integration plan: capa capability deltas on matched function pairs |
| [program-e/DIE-integration-plan.md](program-e/DIE-integration-plan.md) | unregistered | Program E E-1 research plan | DIE integration plan: build-environment fingerprint, delta and noise attribution (Detect It Easy `diec` 3.21 p |
| [program-e/E6-test-performance-beta-plan.md](program-e/E6-test-performance-beta-plan.md) | unregistered | plan | E-6 plan: final feature audit, bug check, scripted beta, performance, Windows smoke |
| [program-e/FAB-integration-plan.md](program-e/FAB-integration-plan.md) | unregistered | research plan and FAB-0 card | FAB integration plan: anchor fabric for cross-feature links (Program E, track FAB) |
| [program-e/GDE-integration-plan.md](program-e/GDE-integration-plan.md) | unregistered | - | GDE integration plan: deterministic guided-RE teacher (`guide/`, contract `guide-lesson/1`) |
| [program-e/GUI-integration-plan.md](program-e/GUI-integration-plan.md) | unregistered | research plan | GUI integration plan: panel registry, shared widgets and threading for the single main window (Program E, trac |
| [program-e/KB-integration-plan.md](program-e/KB-integration-plan.md) | unregistered | Program E research plan | KB integration plan: one KB -> CVE -> product -> binaries workflow (track KB) |
| [program-e/KB2-source-facts.md](program-e/KB2-source-facts.md) | unregistered | research output | KB2: external source facts and synthetic fixtures for the KB workflow |
| [program-e/KEV-integration-plan.md](program-e/KEV-integration-plan.md) | unregistered | 2026-10-14: slices K0 | KEV integration plan: CISA Known Exploited Vulnerabilities as an explained exploitation-context channel |
| [program-e/LBL-integration-plan.md](program-e/LBL-integration-plan.md) | unregistered | - | LBL integration plan: label training (Tier R completion, evaluation harness, training run, honest scope, Tier  |
| [program-e/OUTSTANDING-specs-ledger.md](program-e/OUTSTANDING-specs-ledger.md) | unregistered | 2026-10-14 | Outstanding specs ledger (program E) |
| [program-e/PIL-integration-plan.md](program-e/PIL-integration-plan.md) | unregistered | - | PIL integration plan: patch-intent localization (SPEC-30 a-d), CSAF remainders and the Leads panel |
| [program-e/README.md](program-e/README.md) | unregistered | - | Program E integration plans |
| [program-e/RPT2-report-export-contract-v2.md](program-e/RPT2-report-export-contract-v2.md) | unregistered | draft for build | RPT2: Report and export contract v2 |
| [program-e/WB1-integration-plan.md](program-e/WB1-integration-plan.md) | unregistered | - | WB1 integration plan: unified indexed search ("find anything": SQLite FTS5 + RapidFuzz + QCompleter) |
| [program-e/WB2-integration-plan.md](program-e/WB2-integration-plan.md) | unregistered | - | WB2 integration plan: call graph / XREF explorer (research output, 2026-10-14; plan only, no code) |
| [program-e/WB3-integration-plan.md](program-e/WB3-integration-plan.md) | unregistered | E-1 research plan | WB3 integration plan: pair-aware strings on the built FLOSS adapter |
| [program-e/WBQ-integration-plan.md](program-e/WBQ-integration-plan.md) | unregistered | research plan plus built slices | WBQ integration plan: quick wins (code colours and token marks, PE build facts, symbol names) |
| [program-e/YRX-integration-plan.md](program-e/YRX-integration-plan.md) | unregistered | E-1 research plan | YRX integration plan: analyst-reviewed discoveries to tested YARA-X rules |
| [qbindiff-inspired-matching.md](qbindiff-inspired-matching.md) | SPEC-QB-01 | draft | SPEC-QB-01: Configurable graph-aware function matching |
| [qbindiff-modular-integration.md](qbindiff-modular-integration.md) | SPEC-QB-02 | draft | SPEC-QB-02: Build-safe modular integration and release gates |
| [radiff2-inspired-comparison.md](radiff2-inspired-comparison.md) | SPEC-RD-01 | draft | SPEC-RD-01 — radiff2-inspired multi-layer binary comparison |
| [radiff2-modular-integration.md](radiff2-modular-integration.md) | SPEC-RD-02 | draft | SPEC-RD-02 — radiff2 build-safe integration, dependency and CI contract |
| [runtime-discovery.md](runtime-discovery.md) | SPEC-05 | built | Local runtime discovery (SPEC-05) |
| [schemas.md](schemas.md) | SPEC-02 | built | Normalized schemas (SPEC-02) |
| [secondary-engine.md](secondary-engine.md) | SPEC-11 | partial | SPEC-11: Secondary engine — Rizin rz-diff (Phase 3d) |
| [series-window.md](series-window.md) | SPEC-09b | partial | SPEC-09b: N-way Series window and per-hop ranking (Phase C, item C7) |
| [three-tool-evidence-adapters.md](three-tool-evidence-adapters.md) | SPEC-36 (renamed) | approved | SPEC-29 — Three-tool patch investigation adapters |
| [tier-w-local-corpus.md](tier-w-local-corpus.md) | SPEC-33 | partial | SPEC-33: Tier W local-only Windows calibration corpus (Winbindex pairs, public-PDB labels) |
| [ui.md](ui.md) | SPEC-04 | built | Desktop workflow (SPEC-04) |
| [unified-engine/00-decisions.md](unified-engine/00-decisions.md) | SPEC-31/00 | draft | SPEC-31 / 00 Decisions, conflicts and open USER questions (unified binary-diff engine) |
| [unified-engine/01-architecture.md](unified-engine/01-architecture.md) | SPEC-31/01 | draft | SPEC-31 / 01 Architecture: layers, modules, import DAG, processes, data flow |
| [unified-engine/02-data-model.md](unified-engine/02-data-model.md) | SPEC-31/02 | draft | SPEC-31 / 02 Data model: contracts, storage, keys, limits (contract freeze) |
| [unified-engine/03-extraction.md](unified-engine/03-extraction.md) | SPEC-31/03 | draft | SPEC-31 / 03 Extraction: ProgramIR from Ghidra (GZF reuse first), ingest, PE tables |
| [unified-engine/04-matching-pipeline.md](unified-engine/04-matching-pipeline.md) | SPEC-31/04 | draft | SPEC-31 / 04 L1 matching pipeline: pass ladder, propagation, residual alignment |
| [unified-engine/05-fusion-and-noise.md](unified-engine/05-fusion-and-noise.md) | SPEC-31/05 | draft | SPEC-31 / 05 Fusion (independence components, evidence classes, decisions) and L2 noise control (proof tiers) |
| [unified-engine/06-adapters.md](unified-engine/06-adapters.md) | SPEC-31/06 | draft | SPEC-31 / 06 Adapters: external engines and stored outputs as evidence sources |
| [unified-engine/07-ui-and-cli.md](unified-engine/07-ui-and-cli.md) | SPEC-31/07 | draft | SPEC-31 / 07 UI (one comparison window) and CLI |
| [unified-engine/08-evaluation.md](unified-engine/08-evaluation.md) | SPEC-31/08 | draft | SPEC-31 / 08 Evaluation: gates, corpora, parity harness, tests, performance |
| [unified-engine/09-licensing.md](unified-engine/09-licensing.md) | SPEC-31/09 | draft | SPEC-31 / 09 Licensing: per technique source, licence, reuse method, notices |
| [unified-engine/10-amendments.md](unified-engine/10-amendments.md) | SPEC-31/10 | draft | SPEC-31 / 10 Amendments to existing specs (so none is left contradicted) |
| [unified-engine/11-review-log.md](unified-engine/11-review-log.md) | SPEC-31/11 | n/a | SPEC-31 / 11 Independent review log (2026-10-14) |
| [unified-engine/12-features2-proposal.md](unified-engine/12-features2-proposal.md) | SPEC-31/12 | proposal | SPEC-31 / 12 Proposal: `features/2` with families U and F (amendment A-07, proposal only) |
| [unified-engine/README.md](unified-engine/README.md) | SPEC-31 | draft | SPEC-31: Unified binary-diff engine (derived, one window) |
| [verification.md](verification.md) | SPEC-03 | built | Requirements, acceptance and audit (SPEC-03) |
| [windows-acceptance-and-milestone-builds.md](windows-acceptance-and-milestone-builds.md) | SPEC-40 (proposed; unnumbered) | draft | Windows acceptance and milestone builds |
| [windows-release-signing-policy.md](windows-release-signing-policy.md) | SPEC-52 | draft | Windows release and code-signing policy (SPEC-52) |
| [workbench/01-search-fts5-rapidfuzz.md](workbench/01-search-fts5-rapidfuzz.md) | PT-WB-01 | approved | PT-WB-01: Advanced Investigation Search (SQLite FTS5 + optional RapidFuzz) |
| [workbench/02-networkx-callgraph.md](workbench/02-networkx-callgraph.md) | PT-WB-02 | approved | PT-WB-02: Interactive Call Graph and Cross-Reference Explorer (NetworkX) |
| [workbench/03-floss-strings.md](workbench/03-floss-strings.md) | PT-WB-03 | approved | PT-WB-03: FLOSS Versioned String Extraction and Side-by-Side Investigation |
| [workbench/04-quickwins.md](workbench/04-quickwins.md) | PT-WB-04 | draft | PT-WB-QW: Additional Very-Low-Effort, High-Value Integrations |
| [workbench/README.md](workbench/README.md) | PT-WB (index) | approved | PatchTrace Workbench: Three Reusable Integrations and Easy-Win Addenda |
