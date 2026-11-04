# PatchTrace development dependency map and issue-ready backlog

**Assessment:** 2026-10-30; source SHA `a04f5a299a8d4afef023261e52e08d14678cf1e7`; assessment parent `f18687fd035b67961c1072af84f8c2b3442979e0`. Read [gap analysis](development-gap-analysis.md), [parallel plan](parallel-development-plan.md), [release blockers](release-blockers.md). **No items below certify merged code or newly run tests.**

## Critical path

```mermaid
flowchart TD
 B[GT-00 reconcile PR heads, ownership, specs] --> A[GT-01 repair unified live-gates evidence pipeline]
 A --> C[GT-02 merge and verify R2 matching/fusion fixes]
 A --> D[GT-03 native BinExport/BinDiff/rz-diff adapters]
 C --> E[GT-04 R3/R8 semantic proof and compiler controls]
 C --> F[GT-05 R1/R5 held-out corpus and calibration gates]
 D --> G[GT-08 complete GUI/native pair walkthrough]
 E --> G
 H[GT-06 MSRC KB/CVE/build provenance] --> I[GT-07 Winbindex/MSDelta pair acquisition]
 I --> G
 G --> J[GT-09 clean Windows acceptance and packaging]
 K[GT-10 security/hostile inputs] --> J
 F --> J
 A --> J
 J --> L[GT-13 release candidate gate/attestation]
 M[GT-14 selective integration of #69/#72/#102] --> J
 ```

**Critical-path requirement:** GT-00 → GT-01 (G-U jobs must evaluate actual pairs) → GT-02 and GT-03 → GT-04 / GT-08 → GT-09 → GT-13. R1 ground-truth admission can run independently of backend triage, but no broad correctness claim without GT-05. The **first must-fix**, GT-01, unlocks verified multi-engine semantics, performance and packaging gates. CVE flow GT-06/07 must not independently declare a vulnerability even if a pair is verified.

## Ticket reference protocol

These are *prepared issue bodies*, not newly opened GitHub issues: inspect active issues [#35](https://github.com/djshellshoxxx/patchtrace/issues/35), [#36](https://github.com/djshellshoxxx/patchtrace/issues/36), [#39](https://github.com/djshellshoxxx/patchtrace/issues/39), [#104](https://github.com/djshellshoxxx/patchtrace/issues/104), [#105](https://github.com/djshellshoxxx/patchtrace/issues/105), [#116](https://github.com/djshellshoxxx/patchtrace/issues/116), [#118](https://github.com/djshellshoxxx/patchtrace/issues/118), [#120](https://github.com/djshellshoxxx/patchtrace/issues/120), [#121](https://github.com/djshellshoxxx/patchtrace/issues/121) and active PRs before issue creation. Avoid duplicate issues; append acceptance criteria to the canonical issue when equivalent. S=1–2 engineer days, M=3–5 days, L=1–2 engineer weeks, XL=2–4 weeks. Estimates exclude external licenses, private datasets and unbounded native debugging. Each implementer must honor AGENTS.md; tests below are required additions/targets, not claimed current test passes.

### GT-00 — Integrator: baseline and ownership gate (P0, S)

- **Objective:** Refresh main/integration/29 PRs/reviews/CI at exact head; compare unmerged source blobs and active worktrees with contributor consent; maintain per-file ownership; preserve all branches.
- **Spec:** `docs/audits/20261030-consolidation-review.md`, `AGENTS.md`, `docs/branch-pr-inventory-2026-10-30.md`.
- **Code today / missing:** consolidated main at a04f5a; integration adds 11 documentation commits; GitHub cannot inspect remote worker dirty files or prove active sessions; R1–R8 and #136 moving.
- **Likely files:** `docs/branch-pr-inventory-2026-10-30.md`, integration ledger; **owner only**, no product code.
- **Acceptance:** immutable head/sha, reviewer and CI table for each contender; unknown-owner stop; explicit adopted/superseded/deferred disposition with unique-file hash evidence. **Tests:** git compare, hash/tree comparisons; do not equate cherry-pick ancestry with content loss. **Owner:** coordinator only. **Depends:** none. **Existing:** #126/#136; avoid their edits.

### GT-01 — Repair real unified gate execution and its reporting (P0, L)

- **Objective:** Make real native G-U1–G-U8 matrix execute and emit evaluated A/A/release and mutant outcomes, including explicit failure reasons; never mark advisory green as semantic PASS.
- **Spec:** `docs/specs/unified-engine/08-evaluation.md`, `13-remaining-work-plan.md`, `docs/specs/known-answer-corpus.md`.
- **Current:** `.github/workflows/unified-live-gates.yml`, `tools/live_unified_check.py`, `tools/unified/live_pairs.py`; run 41063115449 built 273 pairs but 27 child jobs failed, 0 counted outcomes.
- **Likely files:** those workflows/harnesses, `tools/unified/corpus/`, focused `tests/test_unified_live_*.py`; do not alter R1 owned fixtures.
- **Acceptance:** find first failing command from job logs; add red fixture to reproduce, preserve original receipt; exact-head Windows/Linux pair outcomes >0 with complete denominator, negative controls, six/eight gate verdicts and provenance; G-U8 frozen smoke attestation not hardcoded. **Tests:** run tests of failure path/status propagation; live CI matrix, Ruff. **Owner:** integrator + QA (workstream G), coordinating R1 #128. **Depends:** GT-00.

### GT-02 — Reconcile R2 matching/fusion evidence fixes (P0, L)

- **Objective:** Integrate tested matching witness/cap preservation, one-sided IR leftovers, determinism and iterative CFG tree queries without conflicting source edits; preserve analyst correction precedence.
- **Spec:** `docs/specs/unified-engine/{04-matching-pipeline,05-fusion-and-noise,08-evaluation}.md`.
- **Current:** `src/patchtrace/unified/{pipeline.py,compute.py,exchange.py}`, `unified/ladder/`, `unified/facts/`; draft [#131](https://github.com/djshellshoxxx/patchtrace/pull/131) has separately measured fixes, **not main**.
- **Missing:** exact-head cross-platform full QA and representative held-out proof; P02 export not wired; N:M automatic relations remain absent.
- **Files:** targeted diff from #131 plus `tests/test_unified_{fusion,ladder_*,ir_*}.py`.
- **Acceptance:** B+B acceptance keeps two independent retained evidence classes under cap; conflicting evidence survives; IR-only one-sided rows remain UNKNOWN; deterministic serial output across input order; 10k/100k scaling measured without regression. **Tests:** seeded properties, native IR replay, Linux+Windows full QA. **Owner:** R2 #131; new worker must not edit until R2 yields changes. **Depends:** GT-00, GT-01 for final acceptance.

### GT-03 — Native secondary evidence chain (P0, L; external-license blocker)

- **Objective:** Verify Ghidra→BinExport2→BinDiff import plus rz-diff via one comparison and evidence panel; retain exact orientation, immutable input SHAs and native limitations.
- **Spec:** `docs/specs/{binexport2-support,bindiff-execution,multi-engine-orchestration}.md` and `docs/specs/unified-engine/06-adapters.md`.
- **Current:** `src/patchtrace/secondary/{binexport_run.py,binexport_producer.py,bindiff_run.py,rzdiff.py,scheduler.py,reconcile.py}`.
- **Missing:** licensed/verified BinDiff binary/tool pin and native CI; rz-diff 0.9.1 produced strict empty-output parsing failures in 20/22 R2 synthetic attempts and conditional side reversal; no generic swap rule.
- **Files:** secondary adapter/probe/parser/worker contracts, live acceptance scripts and tests. **Acceptance:** accepted snapshots are re-hashed; tool invocation isolated and bounded; real BinDiff and rz-diff output imported or explicit failed/unsupported; one-sided orientation invariants and cancelled-result preservation; provenance visible in unified/Qt/export. **Tests:** malformed protobuf, version/orientation permutations, Job Object cancellation, native Ghidra/Windows and Linux. **Owner:** secondary worker B, coordinate #39/#120 and R2. **Depends:** GT-00; native final gate joins GT-01/02. License/tool availability explicit.

### GT-04 — No false-benign semantic and compiler-noise verdict (P0, L)

- **Objective:** Reconcile R3 proof constraints and R8 typed-literal/ICF counterexamples, version canonicalization, preserve uncertainty of EH, decompiler and control-dependence artifacts.
- **Spec:** `docs/specs/unified-engine/05-fusion-and-noise.md`, `docs/specs/patch-intent-localization-engine.md`.
- **Current:** `src/patchtrace/unified/facts/{pseudo.py,channels.py}`, `unified/compute.py`, `buildenv/noise_map.py`; active #129/#135.
- **Missing:** compiled PE native fixtures proving end-to-end verdict outcomes; independent equivalence and negative controls. **Files:** canonicalizer and channel registry only with R3/R8 coordinated patch owner; tests for unsigned/hex/float suffixes, octal, ICF alias, EH absence, opt and non-isomorphic CFG.
- **Acceptance:** type-sensitive expressions never suppressed without proof; `canon` key version changes invalidate derived caches; no material-to-benign collapse when required evidence unavailable; compare before/after dual compiler matrices with stated denominator. **Owner:** R3 and R8 existing authors; integrator resolves conflict. **Depends:** GT-02 and native GT-01.

### GT-05 — Corpus truth, performance and optional numeric calibration (P1, XL)

- **Objective:** Freeze independent provenance/lineage-guarded labels, execute Tier W holdout, evaluate real native false-match/false-benign accuracy and resource ceilings; numerical calibration remains disabled until pass.
- **Spec:** `docs/specs/{known-answer-corpus,calibration-corpus-and-model,tier-w-local-corpus}.md`, C9 prereg.
- **Current:** `tools/calibration/{tier_r,tier_w,train.py,run_locked_test.py}`, `src/patchtrace/calibration/`, `tools/unified/bench.py`; R1 #128, R5 #132, legacy #78/#79/#82/#85.
- **Missing:** independent reviewers/labels, no-leak partitions, true held-out Tier W, measured Windows metrics/RSS and exact calibration promotion. **Files:** owned corpus manifests/runner and calibration-only modules; never alter old locked evaluation in place.
- **Acceptance:** identical sample hashes, labelled denominators, strict train/test lineage split, preregistration hash, Brier/ECE/PR at fixed thresholds with CIs and OOD/abstention, negative-control precision; measured Windows 10k/100k bounds, first paint and native G-U5. **Owner:** R1/R5; E worker on independent harness only. **Depends:** GT-00, GT-01, GT-02; numeric probabilities optional for alpha, corpus accuracy essential for quality claim.

### GT-06 — Real vulnerability provenance and patch-search source lineage (P0, XL)

- **Objective:** Make vendor KB/CVE/product/build assertions ingest as verifiable scoped evidence rather than unqualified CVE-to-function mapping.
- **Spec:** `docs/specs/kb-cve/31-A..H`, `docs/specs/kb/vendor-feeds-and-source-matrix-spec.md`, `docs/specs/kb-patch-search-and-pair-resolution.md`.
- **Current:** `src/patchtrace/kbcorrelation/{sources/cvrf.py,source*,workflow.py,products.py,adapters/search.py}`, `intelligence/csaf/`; R4 #130.
- **Missing:** live MSRC CVRF dialect (code explicitly synthetic placeholder), real source revocations/revisions and Windows cumulative update applicability with negative controls. **Files:** provider adapter/normalizer, source digests, index, provenance/crosswalk tests; avoid touching active #130.
- **Acceptance:** real pinned provider fixtures with auth/license/response digests and published/retrieved dates; exact CVE→advisory→product→KB provenance; contradictory/incomplete source labels; unknown/negative tests; no causal function claim. **Tests:** stale, Unicode, hostile JSON/XML/CSAF, response shape drift, nontrivial Windows servicing. **Owner:** R4 #130 and C worker later. **Depends:** GT-00; GT-07 follows.

### GT-07 — Acquisition, MSDelta and verified pairing (P1, L)

- **Objective:** Complete Winbindex/download/metadata identity and native Windows MSDelta reconstruction, preserving licensed and consented provenance.
- **Spec:** `docs/specs/{acquisition,kb-cve-correlation-and-acquisition}.md`.
- **Current:** `src/patchtrace/acquisition/{winbindex.py,delta.py,transport.py,workflow.py}`.
- **Missing:** current real vendor captures; native MSDelta, signer/checksum/certificate trust and paired original/new file hashes. **Acceptance:** never execute downloaded PE; exact URL/bytes consent, size/rate quotas, SHA recheck, decompression bounds, reproducible predecessor/successor selection or explicit ambiguity; cancellation leaves no installed partially verified pair. **Tests:** hostile metadata, corrupt deltas, Windows MSDelta and live consented capture. **Owner:** C worker with R4. **Depends:** GT-06.

### GT-08 — Analyst GUI and report end-to-end path (P0, L)

- **Objective:** Make the visible Qt investigation workflow complete and unambiguous from scope search through verified pair, engine evidence, manual correction and export.
- **Spec:** `docs/specs/{ui,multi-engine-evidence-panel,report-export-contract-v2}.md`.
- **Current:** `src/patchtrace/{ui.py,ui_unified.py,ui_persistence.py,reports.py}`, `kbcorrelation/panel_qt.py`, `secondary/evidence_panel.py`.
- **Missing:** native connected walkthrough, partial/unknown/retry states, shared model interaction and keyboard/DPI. **Acceptance:** same artifact/run/KB provenance in UI, SQLite and report, correction persists after restart; no mistaken empty state on failed engine; all network actions preceded by exact preview; accessibility tests and screenshot/manual Win11 receipts. **Tests:** offscreen Qt, GUI state transitions and report goldens plus clean desktop. **Owner:** D worker, coordinate #126 and GUI contributor. **Depends:** GT-02/03/06/07 for final acceptance, but can build views with immutable fixtures independently.

### GT-09 — Clean Windows installer and project acceptance (P0, L)

- **Objective:** Validate candidate frozen ZIP + Setup against current exact SHA with working native backend and persistent/OneDrive projects.
- **Spec:** `docs/specs/{windows-acceptance-and-milestone-builds,offline-backend-installer,windows-release-signing-policy}.md`.
- **Current:** `tools/{build_windows.py,package_windows_installer.py,test_windows_installer.ps1,test_windows_portable.ps1}`, `.github/workflows/qa-windows.yml`, v0.1.0-beta.543 assets predate #124.
- **Missing:** new current-SHA published artifact, clean Win11 user path/lock/OneDrive tests; optional complete real relocatable backend bundle and true disconnected validation, signing decision. **Acceptance:** independent ZIP/Setup hash + commit provenance, real native known-patch CLI/GUI, reopen project, backup recovery, uninstall preserving data, expected absent-backend UX; explicitly label optional bundle absence. **Tests:** Windows two clean profiles, frozen smoke, checksum and no-network probes. **Owner:** F worker. **Depends:** GT-01/02/03/08/10, optional GT-05 for numeric claims.

### GT-10 — Hostile-data and process-isolation regression gate (P0, L)

- **Objective:** Verify system-level isolation claims, not just Python guards: untrusted binaries/data cannot escape process, temp, network or output allowlists.
- **Spec:** `AGENTS.md`, `docs/specs/network-egress-privacy.md`, `SECURITY.md`.
- **Current:** `src/patchtrace/{jobs.py,backend.py,persistence.py,ingestion.py}`, `secondary/binexport_run.py`.
- **Missing:** real OS-enforced network block, env/secret inheritance tests, deadline/descendant cleanup, hostile tool output and result rollback on Windows. **Acceptance:** no target execution; all child process descendants killed on cancellation and oom; deny unauthorized egress in system test; no secret in logs, no path escape; old committed results survive hostile failures. **Tests:** adversarial parser fuzz, process-tree, symlink/race, file limits, Windows network block and temporary-directory cleanup. **Owner:** G worker; security fixes have integration-owner signoff. **Depends:** GT-00; continuous gate for all releases.

### GT-11 — Optional AI live interpretation acceptance (P2, M)

- **Objective:** Validate local/remote providers only with explicit consent and cited, owned artifact evidence; no model output as vulnerability proof.
- **Spec:** `docs/specs/ai-provider-interpretation.md`.
- **Current:** `src/patchtrace/{interpretation.py,providers.py,evidence.py}`.
- **Missing:** real provider reliability/quote/privacy and rejection-of-fabrication evaluation. **Acceptance:** consent preview, secrets session-only, negative citation and changed-model tests, invalid references fail closed; report distinguishes hypothesis. **Owner:** A/G after critical path; no active expansion. **Depends:** GT-08 and GT-10; optional release.

### GT-12 — Native real-binary performance budget (P1, L)

- **Objective:** Verify 10k/100k function data and largest known acceptable PE on Windows against bounded memory, CPU, cancellation, sort and Qt first-paint budgets.
- **Spec:** `docs/specs/unified-engine/08-evaluation.md`, `docs/specs/program-e/E6-test-performance-beta-plan.md`.
- **Current:** `tools/{unified/bench.py,bench_enrichment.py}`, `unified/ladder/`; prior 100k synthetic results are shape-specific, not end-to-end.
- **Missing:** measured true native large PE and exact release-budget comparison. **Acceptance:** stage-specific factual timing/RSS and fixture digests, repeated runs and slow-host tolerance, no unbounded quadratic fallback, explicit fail/pass. **Owner:** E worker. **Depends:** GT-01, GT-02, GT-03.

### GT-13 — Release attestation and immutable provenance (P0, M)

- **Objective:** One strict release decision for exact commit, checks, external native acceptance and final assets; don't allow advisory aggregated green to mask child failure.
- **Spec:** `docs/specs/windows-acceptance-and-milestone-builds.md`, `docs/release-process.md`.
- **Current:** `tools/release_gate.py`, `.github/workflows/qa-windows.yml`, `unified-live-gates.yml`; last published beta .543 predates main #124.
- **Missing:** U gate readiness attestation, checked assets tied to head with no unexamined failures, release signing/no-sign policy.
- **Acceptance:** machine-readable release manifest: commit/tree, exact native workflow IDs + failure counts, SHA256 assets, smoke evidence, release branch and signature decision; fail closed on 0 evaluated pairs, absent native execution and incomplete checks. **Owner:** integration owner + F/G. **Depends:** GT-01, GT-08, GT-09, GT-10, GT-12 if performance release gate essential.

### GT-14 — Selective document/fixture integration without stale parent history (P1, M)

- **Objective:** Reconcile #69→#136 24 unique fixture paths, #72 KB/KEV specs, #102 icon/version + CI policy and #78/#79/#82/#85 calibration artifacts against exact current contracts.
- **Current:** `docs/branch-pr-inventory-2026-10-30.md` disposition and PR #136 staged target. **Missing:** exact-head Linux/Windows KB tests, fixture shape, license and cross-PR ownership review.
- **Acceptance:** independent file inventory, hash/content comparison, adoption/supersession table and green exact-target PR check; no GUI parent history reintroduced, no Windows QA disabled, no original source deleted. **Owner:** integration owner; source owners retain heads. **Depends:** GT-00, GT-06 for KB contracts.

## Shared-file conflict ledger

| File(s) / surface | Conflict | Exclusive write owner |
|---|---|---|
| `docs/qa.md`, `tasks/todo.md`, `docs/modules.md` | #126 coordinator; research PR proposals | integration coordinator; assessment append only on separate branch |
| `src/patchtrace/unified/facts/pseudo.py`, channel/registry version | R3 #129 vs R8 #135 | joint R3/R8 contract owner before implementation |
| `unified/ladder/`, `unified/compute.py`, `unified/exchange.py` | R2 #131 vs matching/integration | R2 until accepted, integrator afterward |
| `kbcorrelation/sources/`, source schema and `kbcorrelation/workflow.py` | R4 #130, #136 fixture tests, GUI work | R4 for source, C for isolated acquisition, coordinator for composite |
| `src/patchtrace/ui.py`, `gui/qt/`, `ui_unified.py` | existing GUI contributor, #127 workspace spec | D only after owner check; no concurrent edits |
| `.github/workflows/unified-live-gates.yml`, `tools/unified/live_pairs.py` | R1 labels/gates vs E perf and G QA | integrator/QA, PR-based edits only |
| `.github/workflows/qa-windows.yml`, release scripts | F packaging vs G security; #102 alternate | F owns scripts, G proposes tests and reviews |
| `docs/specs/`, schemas | source-of-truth contracts | coordinator approves additive spec change first |

**Issue policy:** do not allocate the same files to two workers. The coordinator synchronizes commits on feature-branch integration with exact-head CI; no force pushes/hidden PR approvals and no merging of draft research as product functionality.
