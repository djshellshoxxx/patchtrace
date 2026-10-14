# SPEC-QB-02: Build-safe modular integration and release gates
Status: proposed, companion to SPEC-QB-01.

## Guiding rules
Keep existing Ghidriff comparison as the sole default execution path. Do not replace the normalizer, comparison job machinery, project persistence, decompiler/assembly pane implementation or packaging pipeline. No new package is a mandatory runtime dependency until proven on clean Windows. Preserve Python 3.12 compatibility, pinned PySide6/Pydantic versions and offline behavior.

## Build and module boundaries
Use pure Python modules for contracts, distance scoring, anchors, feature calculators and explanation generation. Optional scipy/numpy/networkx or compiled solvers must be extras in an isolated child runtime, not in the PyInstaller desktop unless a measured need and Windows wheel compatibility are proven. Import optional engines lazily, only after selecting their feature. Avoid the temptation to import the QBinDiff package merely to use its implementation: compatibility, licensing, dependency and binary-wheel behavior require separate validation.

Adapters accept a versioned JSON graph manifest, keyed by original SHA-256 and addresses. All schemas validate schema_version, source tool, architecture, source artifact hash, exact graph limits, finite numeric values and deterministic node IDs. Ghidriff importer remains unchanged; separate adapter can derive only facts *actually present* in the imported artifact. For missing graph details, return 'unsupported capability' and leave refinement disabled rather than inventing features.

## Proposed stable interfaces
- `GraphProvider.describe_capabilities()->Capabilities`
- `GraphProvider.load(artifact,analysis_result)->ProgramGraph`
- `FeatureExtractor.extract(node,ctx)->FeatureValue|Missing`
- `SimilarityEngine.score(old,new,profile)->PairEvidence`
- `RefinementPass.apply(candidate_graph,ctx)->candidate_graph`
- `AlignmentEngine.match(candidate_graph,constraints,budget,cancel)->MatchProposal[]`
- `ProposalRepository.save_validated(run,proposals)->id`
- `MatchingService.propose(...)->ProposalRun`
Implement protocols in a pure package and make UI, CLI, persistence, exports depend on service contracts rather than solver internals.

## Database migrations
Add tables with new names only (e.g. matching_proposal_runs, matching_proposals, matching_feature_evidence); no destructive schema changes. Each run records schema/profile hash, tool versions, input digests, method, status and diagnostics. Foreign keys include project and analysis run IDs. Perform migrations transactionally and idempotently with backups and rollback tests. Never use a candidate as an authoritative match until an analyst commits a correction through existing review actions.

## CI and dependency control
Phase 1: pure unit tests + Ruff; run on baseline Python 3.12 Linux and Windows.
Phase 2: adapter contract fixture + persistence migration/rollback tests, UI offscreen smoke.
Phase 3: opt-in solver command; timeout, memory and cancellation tests, adversarial malformed input.
Phase 4: reproducible Windows native fixture (same PE pair, pinned Ghidra/Ghidriff/JDK) comparing old-vs-new behavior, verifying code/metadata views and exports unchanged.
Phase 5: frozen Windows ZIP smoke including 'no optional engine installed', 'optional engine installed', air-gapped use, missing MSVC runtime if compiled dependencies added, and bundled notices/license audit.
Use a dependency lock or pinned constraints for the analysis extra; hash-based reproducibility preferred. No background network fetch, no auto-install in GUI.

## PR sequencing
PR1 research/contracts/tests; PR2 extractors/capability adapters; PR3 sparse matcher/anchors; PR4 explainability/storage; PR5 optional UI/report integration; PR6 experimental solver; PR7 Windows build/benchmark hardening. Each PR small, must pass tests before merging. Separate workers must modify disjoint paths; one integration owner merges frequently and checks conflicts. Do not simultaneously change existing backend normalizer and UI during early phases. Record before/after build checks, feature toggles and a one-command rollback procedure.

## Failure containment
Timeout/cancel cannot commit proposals. Solver exceptions never corrupt the previous comparison or stored analyst notes. Reject schema incompatibility explicitly, preserve prior projects, and do not modify global PATH/Java/Python configuration. Telemetry stays local and excludes proprietary bytes, paths and customer data unless explicitly included in a local report. No workflow that executes analyzed binaries.

## Ready-to-merge checklist
- `python -m pytest`, `ruff check .`, Qt offscreen smoke, Windows workflow checks pass.
- Baseline Ghidriff import/native run and synthetic sample unchanged.
- Migrated and non-migrated projects reopen; full export deterministic.
- Missing optional dependencies disable only that advanced feature.
- Cancellation/timeout/resource-budget failures leave databases unchanged.
- Actual Windows x64 installer/ZIP boots with no network on a clean machine.
- Every new control has tooltip and documented failure messages.
