# PLAN-DA-01: Delivering Diaphora as an optional PatchTrace engine

Date: 2026-10-14. Status: integration PLAN, not implemented. Companions: docs/research/diaphora-feature-study-20261014.md and docs/specs/diaphora-optional-engine.md.

## Executive decision
Build in stages. First make PatchTrace able to import and accurately reconcile existing .diaphora diff databases. Then enable an explicitly selected external comparison of two existing Diaphora SQLite exports. Only after those work end-to-end and on Windows should we attempt automatic IDA/Hex-Rays export and richer pseudocode/microcode or compilation-unit tooling. Never replace Ghidriff default, alter current Ghidriff run semantics or add Diaphora/IDA as mandatory requirements.

This is an optional parallel workstream behind Phase C. Draft PR #34 currently carries separate C3/C4/C6/C9 integration, including BinExport, BinDiff execution, evidence UI and calibration; avoid overlapping ownership of secondary/* and ui.py until its integration is merged. Review upstream docs/specs/three-tool-evidence-adapters.md, which defers whole-engine Diaphora integration pending Phase C. Research and read-only import prototype can proceed without displacing alpha release priorities.

## Target architecture at delivery
Existing PatchTrace project: old/new PE plus primary Ghidriff run, manual corrections, enrichment results.
Optional Diaphora imported/computed run: independently verified old/new Diaphora exports + Diaphora result database -> bounded importer -> new DiaphoraMatchSet and provenance -> versioned separate enrichment kinds -> in-memory typed reconciliation service -> UI evidence and optional candidate detector.
No imported Diaphora match mutates primary FunctionMatch. Diaphora unavailability never fails a primary comparison. A missing secondary match is UNKNOWN, not proof of disagreement.

## Delivery graph
D0 source/version research and contract freeze
  -> D1 hardened SQLite result importer
  -> D2 SHA-256 binding and address normalization
  -> D3 optional import CLI + guarded persistence + in-memory reconciliation
  -> D4 external diff-existing-exports runner
  -> D5 optional native IDA/Hex-Rays export (requires licensed validation)
D3 -> D6 UI read-only evidence and code context
D3 -> D7 independent derivative patch-candidate signals
D4,D5,D6,D7 -> D8 benchmark and acceptance
D8 -> D9 release/rollout gates
D5 is optional and may remain blocked without delaying D1-D4.

## Phase D0: architecture review (already documented; test/merge gates still open)
Owner: integration architect; small, docs-only PR.
- Re-read current main and open PRs before touching code. Lock current relevant contract/schema snapshot and primary Ghidriff golden fixtures.
- Pin upstream Diaphora 3.4.3 exact tag SHA; inspect differences from master source studied and verify Python/IDA compatibility expectations. Preserve AGPL and IDA separate-dependency boundary.
- Freeze separate Diaphora storage kind decision. Existing strict secondary/2 engine enum only supports bindiff/rz-diff. Adding diaphora to it without backward-compatibility tests could break older project readers.
- Declare resource limits, pairing trust states and score semantics from SPEC-DA-01.
Exit: signed off specs + sample fixture checklist + clean CI baseline; no software mutation.

## Phase D1: secure standalone import of Diaphora diff results
Owner: worker Import Core (only new src/patchtrace/diaphora/sqlite_guard.py, result_import.py, contracts.py and tests/diaphora/test_import*); size medium.
- Create strict Pydantic diaphora/1 contracts with versioned JSON schema. Reader accepts only known SQLite tables/columns, bounded rows/text; differentiates diff results DB and export DB.
- Read results categories best, partial, unreliable, multimatch and unmatched primary/secondary with source row and heuristic explanation. Preserve ratio exactly, including possible upstream >1.0 bonus; label any later cap.
- Copy untrusted SQLite into private immutable snapshot, use SQLite read-only/query-only and progress/size limits. Do not execute imported SQL/hooks/scripts. Keep original unchanged.
- Build corrupt, malformed, long-text, duplicate, bad category, non-finite ratio and adversarial schema tests.
- Do not add database persistence or UI yet. Pure parsing from a fixture path -> strictly validated in-memory record.
Exit: deterministic parser/serialization, wrong schema closed safely, no regressions or new mandatory dependencies.
Risk: current .diaphora schema varied by 3.4.3 and earlier releases. Need vendor-generated test fixture (fixtures from redistributable synthetic PE only) before calling it live compatible.

## Phase D2: provenance binding, export inspector, address normalization
Owner: worker Identity & Mapping (only new diaphora/provenance.py, export_import.py, address_map.py; tests); size medium-to-large.
- PatchTrace manifest records actual input binary SHA-256 pair, source export SHA pair, diff-result SHA, orientation older->newer, producer and decompiler versions, export options digest.
- Validated producer-generated provenance is trusted; manually imported without matching manifest may be explicitly user-attested but visibly unverified, never automatically correlated to a KB/CVE.
- Source export .sqlite supplies optional function RVA, VA, code, CFG, inferred compilation units and capability flags; distinguish unavailable data and parse only what is needed.
- Rebase IDA effective addresses separately using PE preferred/actual image base and section mapping via existing verified bytes/pe_overview. Reject ambiguous bases and internal/external functions that lack trustworthy module RVA; do not align by symbol alone.
- The old/new halves of the manifest and exports must correspond to the exact project and order. Reused export for other pair or reversed halves must be rejected.
Exit: address remapping golden tests for base difference, symbol stripping, relocation and wrong architecture; code left unchanged.

## Phase D3: optional Diaphora import service and reconciliation
Owner: integration owner (only new diaphora/{normalize,store,service,cli}.py, small existing CLI dispatch, planned docs/modules.md change); size medium.
- Add only new enrichment kinds diaphora-matches and diaphora-runs. No new literal variant in existing persisted secondary/2 or engine-run/1. Persist immutable evidence summary with guarded publication and pre-extension backup; no double storage of large decompiled text.
- Create a single in-memory bridge to the current reconciliation types or a neutral common projection. Annotate verified agreement, conflicting endpoints, alternatives, unmatched/unknown, and cannot-compare due to addresses.
- Add PatchTrace CLI subcommands for inspect and import, with --json stable errors. CLI import explicitly selected; default run and existing secondary CLI unchanged. Optional unverified pair must never become automatic proof or increase calibrated engine confidence.
- Include interrupted import and stale-project rollback, cache digest, project revision consistency and old-reader compatibility tests.
Exit: real database import fixture associated with real fixture PE pair, unchanged baseline snapshots, no crash when opened with previous PatchTrace, independently reproducible status. This is the first usable milestone.

## Phase D4: supervised comparison of already-exported databases
Owner: worker Engine Execution, after Phase C merge where secondary adapters/runner may change (new diaphora/{probe,profile,runner}.py + tests, zero UI.py edits); size medium.
- Version/pin external Diaphora and compatible Python; do not assume Py3.12 compatible merely because PatchTrace itself uses Py3.12 (Diaphora README last-tested Py3.11).
- User-selected, explicitly trusted local installation; build absolute argv to compare old.sqlite/new.sqlite into a private .diaphora DB. No shell, no network, cleaned env, kill-tree cancel, per-job timeout, bounded stderr/stdout and output validation. No arbitrary hooks.
- Crucial lifecycle issue: existing secondary/scheduler.py calls adapter.parse after TemporaryDirectory exits; do NOT return a file path that no longer exists. Diaphora-owned runner must validate/import before private temp destruction, or alter generic scheduler only after targeted regression tests and multi-engine owner review.
- Output tied to manifests and parser through D1-D3; cache includes input export SHA pair and tool, decompiler, Python, profile and parser versions, not just binary pair.
- Add fake executable test with script generating SQLite result, cancellation and timeout. A real live diff through actual Diaphora 3.4.3 must be recorded separately.
Exit: successful reproducible diff of paired synthetic exports on clean native Windows or a tracked blocked external acceptance. No new mandatory requirements in standard PyInstaller package.

## Phase D5: optional IDA producer, after licensing/live verification
Owner: specialized Windows/IDA integration contributor; size large, high uncertainty.
- Probe locally installed IDA headless interpreter, Diaphora plugin and optional Hex-Rays decompiler without importing vendor modules into PatchTrace.
- Verify actual 3.4.3 native IDA headless workflow; upstream historic DIAPHORA_AUTO/DIAPHORA_EXPORT_FILE and -S may have changed. Always use tested commands for pinned versions, never assume. Produce old/new export databases sequentially with separate isolated workdirs/paths and exact SHA and capability manifests.
- Decompiler pseudocode and microcode are optional and licensed; absent -> disable corresponding view with explicit reason. Export summaries-only option for large codebases.
- Subject to user-owned IDE/IDA license; no bundling vendor bits and no uncited claims of build support.
Exit: witnessed Windows fixture with verified two binary SHA/exports/diff, tool/decompiler versions, cancellation and reasonable measured resources. This phase may remain unavailable for most users without affecting earlier phases.

## Phase D6: evidence interface and code context
Owner: separate Qt worker coordinated with Phase C evidence panel owner; size medium-to-large.
- Build optional ui_diaphora.py and one narrow hook into existing evidence panel AFTER Phase C C6 changes land. A dedicated separate panel is fallback if simultaneous UI changes make merge unsafe.
- Use existing reviewed manual-match service. Present engine-specific ratio, heuristic reason, best/partial/unreliable category, provenance trust, exact old/new mapping and alternative matches. Show Not Available for missing pseudocode/microcode, never infer.
- On-demand old/new text hunks from signed/pinned export; app-owned markup/text rendering. Microcode has an explicit dialect label and is not treated as Ghidra p-code. Optional CU pane states "inferred" and lists changed members with real evidence.
- Tooltips for every functional control, model-view separation, offscreen Qt coverage, accessibility and frozen Windows smoke. Primary viewer remains default.
Exit: import experience doesn't require installed Diaphora and never blocks primary comparison.

## Phase D7: candidate patch indicators, no security-proof claims
Owner: enrichment worker (new diaphora/signals.py + adapter injection into existing enrichment, coordinated); size medium.
- Implement clean-room rule engine over VERIFIED diff code with location-specific references. Candidate detectors: added explicit bound guard/conditional, signedness branch transition with architecture-aware instruction checks, newly added error path, newly introduced/removed sensitive function call. Avoid generic unsafe-substring scanning as high-confidence criterion.
- Keep CVE/KB narrative as separate source and risk/relevance priority only. No evidence score double-count with already-present BND/INT/OVF/VAL/ERR/SIZE/SCRUB detectors. Mark correlated graph/IR/decompiler signals.
- Negative examples: harmless logging, renamed variable, recompilation, optimization, thunks, decompiler changes, code-signature-only update, PDB changed but binary code unchanged.
Exit: inspectable exact code spans, explicit candidate label, measured false-positive behavior, no increase in unverified vulnerability assertion.

## Phase D8: evidence-quality and performance evaluation
Owner: independent QA/measurement contributor; size large, not automatically solved by feature code.
- Build hand-verified function-pair labels and changed-function relevance labels across synthetic repo-owned PE fixtures and permitted real patched binaries; no Microsoft proprietary binary redistribution.
- Three cohorts minimum: standard patched vs unpatched build, compiler/options/optimization drift, rebased/stripped/split/inlined/duplicate-function distractors; hold out by product or binary family not random functions from same binary.
- Compare Ghidriff alone, Ghidriff + BinDiff/rz-diff, Ghidriff + Diaphora, and all engines. Report function identity accuracy, true patch top 5/top 20 recall, false-positive triage count, latency, RAM, offline no-code rate, and conflicts.
- Ablate pseudocode, microcode, CU, graph, and patch detectors separately. No numerical accuracy/probability claim without enough held-out ground truth and calibration protocol in SPEC-27.
- Rule for promotion to recommended-but-optional: documented measurable improvement in true patch function localization at an acceptable false-positive and resource cost, on held-out family; otherwise leave as expert import and do not market as better.
Exit: reproducible benchmark notes with exact source/hash/tool settings and known blind spots.

## Phase D9: packaging, accessibility, docs and roll back
Owner: build/integration owner; size medium.
- Frozen Windows PyInstaller ZIP starts and uses Ghidriff even with no IDA/Diaphora/Hex-Rays installed. Optional dependency detection, path with spaces/non-ASCII, AV locked files, airgapped Windows user and cancellation.
- Notices/license audit; never vendor AGPL into MIT runtime without separate licensing decision. Explicit user-installed tool instructions plus import-only fallback and help screenshots.
- Feature flag defaults off. Disable engine; all stored data remains inert and baseline functioning. No destructive DB migration. Previously stored analysis and notes preserved across failure/cancellation and uninstalling external tool.
- Record SHA/checksum and CI artifacts; do not declare live Windows passed until actually executed.
Exit: new feature shipped only once existing clean Windows alpha gates remain green.

## PR boundaries / safe parallelization
PR-DA0: these three research/spec/plan documents, only, and optional new docs/module index row; draft, no implementation.
PR-DA1: D1 contracts/reader/fixtures; owner Import Core. New files only.
PR-DA2: D2 provenance/export/address bridge; owner Identity & Mapping. New files only.
PR-DA3: D3 persistence/CLI/reconciliation and schema generation; integration owner; schedule after current Phase C merges.
PR-DA4: D4 external compare runner; owner Engine Execution, coordinate shared jobs.run_process scheduler changes. New files only.
PR-DA5: D5 IDA producer; optional separate owner, with proof-of-availability gate.
PR-DA6: D6 UI; owner UI, after C6 changes. No concurrent ownership of ui.py/tooltips.py.
PR-DA7: D7 detector and CVE/KB integration; owner enrichment, avoid touching same files as C9 calibration.
PR-DA8: D8/D9 benchmark, packaging and docs.

Every PR: spec revised before a public interface change; red test for behavior fix, green focused tests; QT_QPA_PLATFORM=offscreen python -m pytest -q; python -m ruff check src tests tools; Linux and Windows CI where applicable; full native Ghidriff fixture and frozen Windows smoke when runner/packaging touched; merge passing slices promptly, no stranded branches. Multi-worker overlap of src/patchtrace/secondary and ui.py with PR #34 is prohibited until coordinated with integration owner. Ask other workers for JSON/short outcome logs, avoid duplicated research and rework.

## Risk register and mitigations
R1 High: Diaphora AGPL combined licensing / IDA licensing. Keep separate external user-installed binary and independent parser; audit redistribution/hosting case before any bundling.
R2 High: SQLite provenance does not carry SHA-256 pair; cannot safely correlate arbitrary .diaphora with Windows KB binary just from names/config paths. Implement verified PatchTrace manifest; unverified user attestation only remains advisory.
R3 High: EA/RVA conversion under rebase/ASLR and different exports. Verify each PE section and image-base independently; abstain, no name-only fallback.
R4 High: Old project readers strict parser rejects new engine. Separate new storage kinds and versioned contracts; old-reader compatibility test before merge.
R5 High: active parallel Phase C work changes engine model and evidence GUI. Separate file ownership, rebase from new main for each coding PR, no premature duplicate scheduler or UI.
R6 High: custom IDA exporter automation and absent/paid Hex-Rays. Deliver import-first; D5 deferred and never affects standard build.
R7 Medium: temp cleanup before parse in existing scheduler. Diaphora runner owns output lifetime until validation or change generic scheduler under regression tests.
R8 Medium: heavy export/matching, SQLite resource exhaustion. Strict caps, cancellation, no cross-process unbounded parallelism, on-demand code loading and explicit unavailable status.
R9 High: misleading CVE/vulnerability results or circular corroboration. Candidate-only patch-signals, differentiated confidence from similarity, held-out benchmarking and independent-code-change location proof.
R10 Medium: Python 3.11 upstream compatibility vs PatchTrace Python 3.12. Use isolated external interpreter, probe and report unsupported; do not alter main app requirements.

## Required acceptance checklist before any code merge
- Diaphora uninstalled: default PatchTrace comparison, CLI, GUI and report are unchanged.
- Import a true Diaphora file and reject hostile/wrong-pair/reversed/corrupt inputs.
- Old project data still loads; old binary/analysis/notes unmodified.
- Correctly verify addresses against pair and preserve Diaphora native scores/buckets.
- Incomplete capability returns unknown/unavailable rather than fabricated evidence.
- A cancelled or crashed optional run never destroys previous usable results, and no child survives.
- No source leakage to network; no unreviewed vendoring, no direct IDA project mutation.
- Native clean Windows package plus optional live installed stack run recorded separately; exact package artifact checksums included.
- Benchmarks disclose real, synthetic and mock provenance and show where Diaphora helps or hurts.

## Immediate next developer action
Do not implement wide scheduler/UI changes while PR #34 is active. Use PR-DA0 for docs review, obtain actual 3.4.3 diff/export SQLite fixtures with legal redistributable synthetic PE binaries, then implement D1 safe parser in a new tightly scoped branch after checking current main and CI. This gives a useful import-only feature fastest, reduces licensing/dependency risk, and exposes actual data-contract drift before investing in licensed IDA automation.
