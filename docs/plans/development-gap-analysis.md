# PatchTrace post-consolidation development gap analysis

**Snapshot:** 2026-10-30 UTC (live GitHub assessment). **Code baseline:** main `a04f5a299a8d4afef023261e52e08d14678cf1e7` (#124). **Documentation staging baseline:** integration/controlled-consolidation-20261030 `f18687fd035b67961c1072af84f8c2b3442979e0` (11 commits ahead, documentation only). **Assessment branch:** `docs/post-consolidation-gap-analysis-20261030`. **Disposition:** assessment only; do not treat research PRs as merged or deploy/release.

## Evidence and scoring policy

This is a **provisional architecture-planning estimate**, not a measured completion percentage, performance benchmark or declared test pass rate. A complete source-level line-by-line audit, locally executed full-suite run, and exhaustive branch-content equivalence verification were not possible in this GitHub-connector session. The assessor inspected repository instructions, immutable tree, representative implementation files, live PR/issue status, consolidation review, R2/R4/R5/R6/R7/R8 reports and exact-head workflow/job results. This is enough to identify actionable integration gaps, not to certify all source paths. Assign a 0–5 evidence grade in each dimension: implementation (30%; 6 points per grade), cross-module integration (25%; 5), automated testing (20%; 4), native/real-PE acceptance (15%; 3), documentation/release (10%; 2). A grade of 5 in automated testing means substantial tests exist, **not** that 100% pass; native grade may be 0 with substantial mocked coverage. Not-merged improvements remain missing in main regardless of PR findings. Do not interpret scores as probability of completion or vulnerability confidence.

**Critical score calibration:** Native workflow passes for a selected Ghidriff, raw-cache, and rz-diff matrix do not imply representative patch-match accuracy. Unified live-gates run 41063115449: 273 pairs built, 27 child jobs failed, zero actual A/A/release outcomes; overall green advisory workflow **is not gate success**. Main QA/Qt/Linux/Windows selected jobs green at a04f5a299, but SonarCloud failed; 58 check runs have mixed conclusions. At R2's experimental head, 268 focused checks passed; the full restricted-environment Linux run saw 18,141 passed / 303 skipped / 6 xfailed / 47 failures / 9 errors, and the isolated 56 failure IDs later passed under the permitted environment. This is **not** a new green full-suite run. R8's five isolated tests and R7's 44 synthetic checks do not constitute merged/native validation. Do not sum overlapping tests.

## 20-feature evidence matrix

| Feature | I /5 | G /5 | T /5 | N /5 | D /5 | Estimated maturity | Remaining | Priority |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| PE ingestion and validation | 5 | 5 | 4 | 3 | 4 | 88% | 12% | P1 |
| Ghidriff/Ghidra integration | 5 | 4 | 4 | 4 | 4 | 86% | 14% | P0 |
| BinExport2 | 4 | 3 | 4 | 1 | 4 | 66% | 34% | P0 |
| BinDiff | 4 | 3 | 4 | 1 | 4 | 66% | 34% | P0 |
| rz-diff | 4 | 4 | 4 | 2 | 4 | 74% | 26% | P0 |
| Unified function matching | 5 | 4 | 4 | 2 | 4 | 80% | 20% | P0 |
| Multi-engine evidence fusion | 5 | 4 | 4 | 2 | 4 | 80% | 20% | P0 |
| Semantic-change classification | 4 | 3 | 4 | 1 | 3 | 64% | 36% | P0 |
| Compiler-noise suppression | 4 | 3 | 4 | 1 | 3 | 64% | 36% | P0 |
| Confidence calibration | 4 | 3 | 3 | 0 | 4 | 59% | 41% | P1 |
| CVE/KB/product/build correlation | 5 | 4 | 4 | 1 | 4 | 77% | 23% | P0 |
| Winbindex acquisition and MSDelta | 4 | 4 | 4 | 1 | 4 | 71% | 29% | P1 |
| Patch search | 4 | 4 | 4 | 1 | 4 | 71% | 29% | P0 |
| Project persistence/history | 5 | 5 | 5 | 3 | 4 | 92% | 8% | P1 |
| GUI/analyst workflow | 5 | 4 | 4 | 2 | 4 | 80% | 20% | P0 |
| AI interpretation | 4 | 4 | 4 | 0 | 4 | 68% | 32% | P2 |
| Reports and exports | 5 | 5 | 4 | 3 | 4 | 88% | 12% | P1 |
| Security and process isolation | 5 | 4 | 4 | 2 | 4 | 80% | 20% | P0 |
| Performance/scalability | 4 | 3 | 3 | 1 | 3 | 60% | 40% | P1 |
| Windows packaging/release | 4 | 4 | 4 | 2 | 3 | 72% | 28% | P0 |

Mean of 20 equally weighted feature scores: **74.3%** (descriptive **planning proxy only**; neither feature importance nor release criticality is equal). Essential-release gates below override this mean; a single blocking gate can make release NOT READY. `I/G/T/N/D` represent maturity tiers, not passing-test percentages.

## Feature-by-feature implementation and next action

### 1. PE ingestion and validation — 88% estimated / 12% remaining

- **Implementation inspected / relevant files:** `src/patchtrace/src/patchtrace/ingestion.py`; `src/patchtrace/pe_overview/inspect.py` (paths under `tools/` remain relative to repository root). These are code anchors, not an assertion that every function in the package was exhaustively reviewed.
- **Specific remaining gap:** PE bounds, Authenticode/catalog and malicious/OneDrive cases on clean Windows.
- **Development ticket / dependency:** GT-09. **Priority P1**, effort **M** (S 1–2d, M 3–5d, L 1–2w, XL 2–4w of one engineer; very uncertain for native licensing/corpus). **Research owner:** R8. Research must be merged only after exact-head QA. 
- **Required verification:** focused adversarial unit/integration tests, unchanged source/artifact/run identity, relevant Linux/Windows QA and a dated real/native acceptance receipt; record explicit `unknown` and `not observed` states instead of silent success.

### 2. Ghidriff/Ghidra integration — 86% estimated / 14% remaining

- **Implementation inspected / relevant files:** `src/patchtrace/backend.py`; `src/patchtrace/unified/extract/runner.py`; `src/patchtrace/ghidriff_launch/ptlaunch.py` (paths under `tools/` remain relative to repository root). These are code anchors, not an assertion that every function in the package was exhaustively reviewed.
- **Specific remaining gap:** Pinned native GZF/decomp end-to-end, user PE and failure preservation.
- **Development ticket / dependency:** GT-01,GT-09. **Priority P0**, effort **L** (S 1–2d, M 3–5d, L 1–2w, XL 2–4w of one engineer; very uncertain for native licensing/corpus). **Research owner:** R1/R2. Research must be merged only after exact-head QA. 
- **Required verification:** focused adversarial unit/integration tests, unchanged source/artifact/run identity, relevant Linux/Windows QA and a dated real/native acceptance receipt; record explicit `unknown` and `not observed` states instead of silent success.

### 3. BinExport2 — 66% estimated / 34% remaining

- **Implementation inspected / relevant files:** `src/patchtrace/secondary/binexport_run.py`; `src/patchtrace/binexport_producer.py`; `src/patchtrace/binexport_proto.py` (paths under `tools/` remain relative to repository root). These are code anchors, not an assertion that every function in the package was exhaustively reviewed.
- **Specific remaining gap:** Real exporter builds + adversarial protobuf + Windows host identity/orientation.
- **Development ticket / dependency:** GT-03. **Priority P0**, effort **L** (S 1–2d, M 3–5d, L 1–2w, XL 2–4w of one engineer; very uncertain for native licensing/corpus). **Research owner:** R2. Research must be merged only after exact-head QA. 
- **Required verification:** focused adversarial unit/integration tests, unchanged source/artifact/run identity, relevant Linux/Windows QA and a dated real/native acceptance receipt; record explicit `unknown` and `not observed` states instead of silent success.

### 4. BinDiff — 66% estimated / 34% remaining

- **Implementation inspected / relevant files:** `src/patchtrace/secondary/bindiff_run.py`; `src/patchtrace/bindiff.py`; `src/patchtrace/bindiff_inputs.py` (paths under `tools/` remain relative to repository root). These are code anchors, not an assertion that every function in the package was exhaustively reviewed.
- **Specific remaining gap:** Verified licensed binary pin, native oracle and one-comparison persistence.
- **Development ticket / dependency:** GT-03. **Priority P0**, effort **L** (S 1–2d, M 3–5d, L 1–2w, XL 2–4w of one engineer; very uncertain for native licensing/corpus). **Research owner:** R2. Research must be merged only after exact-head QA. 
- **Required verification:** focused adversarial unit/integration tests, unchanged source/artifact/run identity, relevant Linux/Windows QA and a dated real/native acceptance receipt; record explicit `unknown` and `not observed` states instead of silent success.

### 5. rz-diff — 74% estimated / 26% remaining

- **Implementation inspected / relevant files:** `src/patchtrace/secondary/rzdiff.py`; `src/patchtrace/secondary/registry.py`; `src/patchtrace/secondary/cli_run.py` (paths under `tools/` remain relative to repository root). These are code anchors, not an assertion that every function in the package was exhaustively reviewed.
- **Specific remaining gap:** Strict parser does not accept most R2 native probes; validate side orientation per version.
- **Development ticket / dependency:** GT-03. **Priority P0**, effort **M** (S 1–2d, M 3–5d, L 1–2w, XL 2–4w of one engineer; very uncertain for native licensing/corpus). **Research owner:** R2. Research must be merged only after exact-head QA. 
- **Required verification:** focused adversarial unit/integration tests, unchanged source/artifact/run identity, relevant Linux/Windows QA and a dated real/native acceptance receipt; record explicit `unknown` and `not observed` states instead of silent success.

### 6. Unified function matching — 80% estimated / 20% remaining

- **Implementation inspected / relevant files:** `src/patchtrace/unified/pipeline.py`; `src/patchtrace/unified/ladder/`; `src/patchtrace/unified/facts/` (paths under `tools/` remain relative to repository root). These are code anchors, not an assertion that every function in the package was exhaustively reviewed.
- **Specific remaining gap:** Merge/test R2 witnesses, unmatched IR-only functions and bounded regression; native held-out accuracy.
- **Development ticket / dependency:** GT-01,GT-02. **Priority P0**, effort **L** (S 1–2d, M 3–5d, L 1–2w, XL 2–4w of one engineer; very uncertain for native licensing/corpus). **Research owner:** R1/R2. Research must be merged only after exact-head QA. 
- **Required verification:** focused adversarial unit/integration tests, unchanged source/artifact/run identity, relevant Linux/Windows QA and a dated real/native acceptance receipt; record explicit `unknown` and `not observed` states instead of silent success.

### 7. Multi-engine evidence fusion — 80% estimated / 20% remaining

- **Implementation inspected / relevant files:** `src/patchtrace/unified/compute.py`; `src/patchtrace/unified/exchange.py`; `src/patchtrace/secondary/reconcile.py` (paths under `tools/` remain relative to repository root). These are code anchors, not an assertion that every function in the package was exhaustively reviewed.
- **Specific remaining gap:** Preserve opposing evidence, missingness, provenance; integrate live secondary into unified run.
- **Development ticket / dependency:** GT-02,GT-03. **Priority P0**, effort **L** (S 1–2d, M 3–5d, L 1–2w, XL 2–4w of one engineer; very uncertain for native licensing/corpus). **Research owner:** R2. Research must be merged only after exact-head QA. 
- **Required verification:** focused adversarial unit/integration tests, unchanged source/artifact/run identity, relevant Linux/Windows QA and a dated real/native acceptance receipt; record explicit `unknown` and `not observed` states instead of silent success.

### 8. Semantic-change classification — 64% estimated / 36% remaining

- **Implementation inspected / relevant files:** `src/patchtrace/unified/facts/pseudo.py`; `src/patchtrace/unified/facts/channels.py`; `src/patchtrace/unified/compute.py` (paths under `tools/` remain relative to repository root). These are code anchors, not an assertion that every function in the package was exhaustively reviewed.
- **Specific remaining gap:** R3/R8 proof counterexamples, typed literals, EH unknown, native false-benign controls.
- **Development ticket / dependency:** GT-04. **Priority P0**, effort **L** (S 1–2d, M 3–5d, L 1–2w, XL 2–4w of one engineer; very uncertain for native licensing/corpus). **Research owner:** R3/R8. Research must be merged only after exact-head QA. 
- **Required verification:** focused adversarial unit/integration tests, unchanged source/artifact/run identity, relevant Linux/Windows QA and a dated real/native acceptance receipt; record explicit `unknown` and `not observed` states instead of silent success.

### 9. Compiler-noise suppression — 64% estimated / 36% remaining

- **Implementation inspected / relevant files:** `src/patchtrace/unified/facts/layout.py`; `src/patchtrace/unified/facts/pseudo.py`; `src/patchtrace/buildenv/noise_map.py` (paths under `tools/` remain relative to repository root). These are code anchors, not an assertion that every function in the package was exhaustively reviewed.
- **Specific remaining gap:** Locked A/A and cross-toolchain negatives, opt/ICF provenance, non-equivalence safeguards.
- **Development ticket / dependency:** GT-04,GT-05. **Priority P0**, effort **L** (S 1–2d, M 3–5d, L 1–2w, XL 2–4w of one engineer; very uncertain for native licensing/corpus). **Research owner:** R3/R8. Research must be merged only after exact-head QA. 
- **Required verification:** focused adversarial unit/integration tests, unchanged source/artifact/run identity, relevant Linux/Windows QA and a dated real/native acceptance receipt; record explicit `unknown` and `not observed` states instead of silent success.

### 10. Confidence calibration — 59% estimated / 41% remaining

- **Implementation inspected / relevant files:** `src/patchtrace/calibration/predict.py`; `src/patchtrace/calibration/ood.py`; `src/patchtrace/tools/calibration/` (paths under `tools/` remain relative to repository root). These are code anchors, not an assertion that every function in the package was exhaustively reviewed.
- **Specific remaining gap:** Lineage-held-out Tier W labels, locked preregistration, trustworthy metrics and promotion gate.
- **Development ticket / dependency:** GT-05. **Priority P1**, effort **XL** (S 1–2d, M 3–5d, L 1–2w, XL 2–4w of one engineer; very uncertain for native licensing/corpus). **Research owner:** R1/R5. Research must be merged only after exact-head QA. 
- **Required verification:** focused adversarial unit/integration tests, unchanged source/artifact/run identity, relevant Linux/Windows QA and a dated real/native acceptance receipt; record explicit `unknown` and `not observed` states instead of silent success.

### 11. CVE/KB/product/build correlation — 77% estimated / 23% remaining

- **Implementation inspected / relevant files:** `src/patchtrace/kbcorrelation/workflow.py`; `src/patchtrace/sources/cvrf.py`; `src/patchtrace/intelligence/csaf/` (paths under `tools/` remain relative to repository root). These are code anchors, not an assertion that every function in the package was exhaustively reviewed.
- **Specific remaining gap:** Real MSRC dialect/source lineage, product/update scopes and non-causal wording.
- **Development ticket / dependency:** GT-06. **Priority P0**, effort **XL** (S 1–2d, M 3–5d, L 1–2w, XL 2–4w of one engineer; very uncertain for native licensing/corpus). **Research owner:** R4. Research must be merged only after exact-head QA. 
- **Required verification:** focused adversarial unit/integration tests, unchanged source/artifact/run identity, relevant Linux/Windows QA and a dated real/native acceptance receipt; record explicit `unknown` and `not observed` states instead of silent success.

### 12. Winbindex acquisition and MSDelta — 71% estimated / 29% remaining

- **Implementation inspected / relevant files:** `src/patchtrace/acquisition/winbindex.py`; `src/patchtrace/acquisition/delta.py`; `src/patchtrace/acquisition/workflow.py` (paths under `tools/` remain relative to repository root). These are code anchors, not an assertion that every function in the package was exhaustively reviewed.
- **Specific remaining gap:** Native MSDelta and verified provenance/Authenticode, corpus/live transport cases.
- **Development ticket / dependency:** GT-07. **Priority P1**, effort **L** (S 1–2d, M 3–5d, L 1–2w, XL 2–4w of one engineer; very uncertain for native licensing/corpus). **Research owner:** R4. Research must be merged only after exact-head QA. 
- **Required verification:** focused adversarial unit/integration tests, unchanged source/artifact/run identity, relevant Linux/Windows QA and a dated real/native acceptance receipt; record explicit `unknown` and `not observed` states instead of silent success.

### 13. Patch search — 71% estimated / 29% remaining

- **Implementation inspected / relevant files:** `src/patchtrace/kbcorrelation/adapters/search.py`; `src/patchtrace/search/service.py`; `src/patchtrace/kbcorrelation/pairs.py` (paths under `tools/` remain relative to repository root). These are code anchors, not an assertion that every function in the package was exhaustively reviewed.
- **Specific remaining gap:** End-to-end CVE→KB→pair→project and stale/ambiguous/negative lineage controls.
- **Development ticket / dependency:** GT-06,GT-07. **Priority P0**, effort **L** (S 1–2d, M 3–5d, L 1–2w, XL 2–4w of one engineer; very uncertain for native licensing/corpus). **Research owner:** R4. Research must be merged only after exact-head QA. 
- **Required verification:** focused adversarial unit/integration tests, unchanged source/artifact/run identity, relevant Linux/Windows QA and a dated real/native acceptance receipt; record explicit `unknown` and `not observed` states instead of silent success.

### 14. Project persistence/history — 92% estimated / 8% remaining

- **Implementation inspected / relevant files:** `src/patchtrace/persistence.py`; `src/patchtrace/verified_backup.py`; `src/patchtrace/unified/store.py` (paths under `tools/` remain relative to repository root). These are code anchors, not an assertion that every function in the package was exhaustively reviewed.
- **Specific remaining gap:** OneDrive/locks crash recovery, version/migration/old result preservation on real Windows.
- **Development ticket / dependency:** GT-09. **Priority P1**, effort **M** (S 1–2d, M 3–5d, L 1–2w, XL 2–4w of one engineer; very uncertain for native licensing/corpus). **Research owner:** R6. Research must be merged only after exact-head QA. 
- **Required verification:** focused adversarial unit/integration tests, unchanged source/artifact/run identity, relevant Linux/Windows QA and a dated real/native acceptance receipt; record explicit `unknown` and `not observed` states instead of silent success.

### 15. GUI/analyst workflow — 80% estimated / 20% remaining

- **Implementation inspected / relevant files:** `src/patchtrace/ui.py`; `src/patchtrace/ui_unified.py`; `src/patchtrace/kbcorrelation/panel_qt.py`; `src/patchtrace/gui/qt/` (paths under `tools/` remain relative to repository root). These are code anchors, not an assertion that every function in the package was exhaustively reviewed.
- **Specific remaining gap:** Real end-to-end clicks, secondary and failure states, keyboard/DPI, review navigation.
- **Development ticket / dependency:** GT-08. **Priority P0**, effort **L** (S 1–2d, M 3–5d, L 1–2w, XL 2–4w of one engineer; very uncertain for native licensing/corpus). **Research owner:** R6/#126. Research must be merged only after exact-head QA. 
- **Required verification:** focused adversarial unit/integration tests, unchanged source/artifact/run identity, relevant Linux/Windows QA and a dated real/native acceptance receipt; record explicit `unknown` and `not observed` states instead of silent success.

### 16. AI interpretation — 68% estimated / 32% remaining

- **Implementation inspected / relevant files:** `src/patchtrace/interpretation.py`; `src/patchtrace/providers.py`; `src/patchtrace/evidence.py` (paths under `tools/` remain relative to repository root). These are code anchors, not an assertion that every function in the package was exhaustively reviewed.
- **Specific remaining gap:** Consent/privacy and live local/remote model acceptance; citations and hallucination QA.
- **Development ticket / dependency:** GT-11. **Priority P2**, effort **M** (S 1–2d, M 3–5d, L 1–2w, XL 2–4w of one engineer; very uncertain for native licensing/corpus). **Research owner:** R7. Research must be merged only after exact-head QA. 
- **Required verification:** focused adversarial unit/integration tests, unchanged source/artifact/run identity, relevant Linux/Windows QA and a dated real/native acceptance receipt; record explicit `unknown` and `not observed` states instead of silent success.

### 17. Reports and exports — 88% estimated / 12% remaining

- **Implementation inspected / relevant files:** `src/patchtrace/reports.py`; `src/patchtrace/intelligence/reports.py`; `src/patchtrace/kbcorrelation/export.py` (paths under `tools/` remain relative to repository root). These are code anchors, not an assertion that every function in the package was exhaustively reviewed.
- **Specific remaining gap:** Cross-feature provenance manifest, failing/partial/cancelled outputs, published ZIP smoke.
- **Development ticket / dependency:** GT-08,GT-09. **Priority P1**, effort **M** (S 1–2d, M 3–5d, L 1–2w, XL 2–4w of one engineer; very uncertain for native licensing/corpus). **Research owner:** R6. Research must be merged only after exact-head QA. 
- **Required verification:** focused adversarial unit/integration tests, unchanged source/artifact/run identity, relevant Linux/Windows QA and a dated real/native acceptance receipt; record explicit `unknown` and `not observed` states instead of silent success.

### 18. Security and process isolation — 80% estimated / 20% remaining

- **Implementation inspected / relevant files:** `src/patchtrace/jobs.py`; `src/patchtrace/backend.py`; `src/patchtrace/acquisition/transport.py`; `src/patchtrace/persistence.py` (paths under `tools/` remain relative to repository root). These are code anchors, not an assertion that every function in the package was exhaustively reviewed.
- **Specific remaining gap:** OS network isolation cannot be inferred; hostile input, env leakage, descendant and temp cleanup acceptance.
- **Development ticket / dependency:** GT-10. **Priority P0**, effort **L** (S 1–2d, M 3–5d, L 1–2w, XL 2–4w of one engineer; very uncertain for native licensing/corpus). **Research owner:** R8. Research must be merged only after exact-head QA. 
- **Required verification:** focused adversarial unit/integration tests, unchanged source/artifact/run identity, relevant Linux/Windows QA and a dated real/native acceptance receipt; record explicit `unknown` and `not observed` states instead of silent success.

### 19. Performance/scalability — 60% estimated / 40% remaining

- **Implementation inspected / relevant files:** `src/patchtrace/unified/ladder/`; `src/patchtrace/tools/unified/bench.py`; `src/patchtrace/tools/bench_enrichment.py` (paths under `tools/` remain relative to repository root). These are code anchors, not an assertion that every function in the package was exhaustively reviewed.
- **Specific remaining gap:** Native 100k and real large PE, Windows RSS/time and GUI first paint/scroll deadlines.
- **Development ticket / dependency:** GT-05,GT-12. **Priority P1**, effort **L** (S 1–2d, M 3–5d, L 1–2w, XL 2–4w of one engineer; very uncertain for native licensing/corpus). **Research owner:** R2/R5. Research must be merged only after exact-head QA. 
- **Required verification:** focused adversarial unit/integration tests, unchanged source/artifact/run identity, relevant Linux/Windows QA and a dated real/native acceptance receipt; record explicit `unknown` and `not observed` states instead of silent success.

### 20. Windows packaging/release — 72% estimated / 28% remaining

- **Implementation inspected / relevant files:** `src/patchtrace/tools/build_windows.py`; `src/patchtrace/tools/package_windows_installer.py`; `src/patchtrace/tools/release_gate.py` (paths under `tools/` remain relative to repository root). These are code anchors, not an assertion that every function in the package was exhaustively reviewed.
- **Specific remaining gap:** Exact-head verified assets, clean Win11, signed/trusted policy, air-gapped runtime bundle optional.
- **Development ticket / dependency:** GT-09,GT-13. **Priority P0**, effort **L** (S 1–2d, M 3–5d, L 1–2w, XL 2–4w of one engineer; very uncertain for native licensing/corpus). **Research owner:** R6. Research must be merged only after exact-head QA. 
- **Required verification:** focused adversarial unit/integration tests, unchanged source/artifact/run identity, relevant Linux/Windows QA and a dated real/native acceptance receipt; record explicit `unknown` and `not observed` states instead of silent success.

## Cross-cutting architectural deficits (highest leverage)

1. **Unified end-to-end acceptance is broken:** main's G-U advisory runner did not produce measured pair outcomes. Diagnose the first failed child command and transport errors, then rebuild the matrix and publish numerator/denominator; do not tune the matching ladder against a zero-observation gate.
2. **Secondary adapter boundary:** BinExport accepted snapshots and supervised BinDiff execution exist, but verified real BinExport host/pin/licensing and a native successful Ghidra→BinExport→BinDiff→reconcile→unified→GUI route remain incomplete. R2 rz-diff tests show strict parser failures and occasional side reversal; do not globally swap orientations.
3. **Function truth / semantic truth:** ordinal structural matching, model confidence, materiality, change attribution and CVE causality are separate contracts. R2 witness loss/unmatched functions and R8 type-erasure proofs show counterexamples. Reject blanket benign/cosmetic verdicts when EH, type, provenance or control dependence is unknown.
4. **Vendor source dialect:** `kbcorrelation/sources/cvrf.py` labels CVRF dialects synthetic; MSRC live compatibility and cumulative Windows servicing context need authority-bound adapter receipts.
5. **Calibration trust:** `calibration/predict.py` exists, but Tier W held-out, lineage-separated statistics, preregistration and guarded promotion are missing. Do not advertise numeric calibrated probability.
6. **Desktop completion:** Qt screens and most workflow plumbing are present; no single current release-candidate clean Windows manual walkthrough demonstrates CVE→KB→verified binary pair→native compare→unified/secondary→analyst report.
7. **Secure execution boundary:** launcher, bounded subprocess/worker, consent, immutability and data-path guards exist. Ghidra no-symbol mode is **configuration**, not proof of OS air-gap. Need trusted process inheritance/Job Object/network tests.
8. **Documentation ownership:** PR #126 owns shared tracker updates; #128–#135 actively own research. Do not replace these with new unrelated engines or duplicate tickets. This assessment's QA/tracker delta is additive pending coordinator integration.
9. **Branch ancestry is not content equivalence:** prior inventory includes 126 refs/29 open PRs; preserve unmatched history. #136 carries 24 unique fixture/test paths based on #69, targeting integration. #72 KB/KEV specs, #102 resource/CI assets and calibration PRs #78/#79/#82/#85 require explicit selective disposition before deletion.
10. **Publishing ≠ acceptance:** v0.1.0-beta.543 was released with Windows ZIP/Setup assets, but it predates #124 consolidation and cannot certify current main or the assessment/integration head.

## Research consolidation disposition

- **R1 #128:** ground truth, data admission and verified native pilot; live head changed during this assessment; preserve ownership.
- **R2 #131:** measured matching/fusion fixes (witnesses, deterministic ordering, IR-only leftovers and dominator complexity) **not on main**; compare content and approve only after exact-head gates.
- **R3 #129:** semantic falsification and EH/proof guards; coordinate overlapping `canon` change with R8.
- **R4 #130:** MSRC/CSAF/KB/product/build/source-lineage provenance and live adapter acceptance.
- **R5 #132:** statistical protocol, OOD/held-out label procedures, no accepted numeric probability.
- **R6 #133:** release and integration dossier; its 27-failed-child-gate discovery remains critical.
- **R7 #134:** research-only bounded P-code slicing synthetic prototype; no production/CWE claim.
- **R8 #135:** type-sensitive canonicalization and ICF alias adversarial proof; no merged/native false-benign measurement.
- **#136/#69:** staged KB fixtures and parser tests, pending current dialect checks and two-platform CI; avoid reintegrating original obsolete parent stack.
- **#126:** shared milestone ledger and `docs/qa.md`, `tasks/todo.md` review owner. 

## Audit methodology / reproducibility

Read `AGENTS.md`, `CLAUDE.md`, `docs/audits/20261030-consolidation-review.md`, `docs/plans/essential-integration-20261029.md`, source modules above, the live branch/PR collections, and CI jobs at exact SHA. Representative source inspection confirmed pure PE ingestion, verified GZF extraction, immutable unified job model, strict BinExport worker, isolated BinDiff run, strict rz-diff parser, immutable KB reducer, acquisition consent boundary, SQLite history, Qt GUI thread model, optional AI provider strict responses, atomic report export and Windows package builder. Native workflows and research reports are referenced as **existing records**; no local checkout, native executable, or test suite was executed by the author of this document. Unread modules, active branches' uncommitted files, and unpublished test runs must be marked **unknown**.

**Sources:** [main](https://github.com/djshellshoxxx/patchtrace/commit/a04f5a299a8d4afef023261e52e08d14678cf1e7), [consolidation](https://github.com/djshellshoxxx/patchtrace/blob/main/docs/audits/20261030-consolidation-review.md), [R2 #131](https://github.com/djshellshoxxx/patchtrace/pull/131), [R4 #130](https://github.com/djshellshoxxx/patchtrace/pull/130), [R5 #132](https://github.com/djshellshoxxx/patchtrace/pull/132), [R6 #133](https://github.com/djshellshoxxx/patchtrace/pull/133), [R7 #134](https://github.com/djshellshoxxx/patchtrace/pull/134), [R8 #135](https://github.com/djshellshoxxx/patchtrace/pull/135), [unified live gates](https://github.com/djshellshoxxx/patchtrace/actions/runs/41063115449), [beta assets](https://github.com/djshellshoxxx/patchtrace/releases/tag/v0.1.0-beta.543).

