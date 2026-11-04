# PatchTrace parallel development plan — post-consolidation

**Status:** ready for coordinator assignment, **not worker activation**. Assessment source `main a04f5a299a8d4afef023261e52e08d14678cf1e7`; integration parent `f18687fd035b67961c1072af84f8c2b3442979e0`. Research PRs #128–#135 and #136 are active/unmerged; check exact heads before assignment. Full issue bodies and acceptance criteria: [dependency map](development-dependency-map.md); maturity: [gap analysis](development-gap-analysis.md).

## Operating protocol

**Coordinator (one only):** GT-00, GT-01, GT-13, shared contracts and merge order. Before dispatch, reconcile `AGENTS.md`, `CLAUDE.md`, `docs/specs/REGISTRY.md`, all open PRs/reviews/unresolved threads, worktrees/dirty files (when an actual executor is available), branch labels, exact CI and worker ownership. Reserve `docs/qa.md`, `tasks/todo.md`, and schema/version migration decisions to coordinator. New agents get isolated branches/worktrees **only after confirming the existing owner is not editing that surface**. Research owners are not silently replaced. Workstream boundaries are authority to investigate/prep tests, not to overwrite owner PRs.

| Workstream | Exclusive proposed scope | Prepared tasks | Existing owner/PR handling | Prerequisite |
|---|---|---|---|---|
| **A. Unified matching and semantic analysis** | unified matching, semantic proof, compiler-noise tests only after existing owners handoff | GT-02, GT-04 | #131 R2, #129 R3, #135 R8 retain current ownership | GT-01 live-gate triage; coordinate type/canon |
| **B. Secondary engine integration** | secondary adapters, native BinExport2/BinDiff/rz-diff harness, per-engine receipts | GT-03 | avoid competing #39 and R2 adapter edits; assign non-overlapping test harness first | tool/legal availability; GT-00 |
| **C. Vulnerability intelligence and patch search** | KB/CVE source adapters, Winbindex, MSDelta, verified pair workflow | GT-06, GT-07, GT-14 fixture part | #130 R4 retains source contract; #136 handles #69 fixtures; #126 shared docs | source contract stable, real vendor samples |
| **D. GUI and analyst workflows** | Qt views, search/pair/panel state, evidence navigation, export preview | GT-08 | #126 ledger and #127 docking spec; check existing GUI worker before editing ui.py | immutable fixture API; native gate later |
| **E. Corpus, calibration and performance** | isolated label/corpus read tooling, evaluation runners, Windows performance harness | GT-05, GT-12 | #128 R1, #132 R5, #131 R2 retain owner code; avoid locked test changes | GT-01 evaluated outputs; real data |
| **F. Windows packaging and release acceptance** | Windows build scripts, Setup/ZIP integrity, clean-user manual runbook | GT-09, GT-13 artifacts | check #102 alternate CI before importing; no disabling Windows PR checks | can prep now; strict release at end |
| **G. Security and regression testing** | hostile fixtures, child/env/network isolation harness, CI gate investigation | GT-01, GT-10 | #121 security audit, #116 persistence audit, coordinator merges shared fixes | can prep independent tests now |

### A — proposed agent assignment

> Work on **only** assigned unowned files. First review #129/#131/#135 and request integration-owner reservation of overlapping source. Reproduce B+B evidence-cap loss, discarded unmatched IR-only observations, type erasure, CFG collision and EH unknown as standalone tests. Integrate only after owner PRs are verified. Preserve primary Ghidriff matches, analyst corrections and result schema. Success: proof-sensitive verdicts never upgrade unknown to benign, seeded deterministic evidence output, old results remain readable, CI+native G-U receipts collected. Do not retune thresholds or create a new matcher.

**Likely safe early files:** new adversarial fixture/test modules in a reserved `tests/` namespace; no source core until exclusive ownership. **Review:** workstream E for accuracy controls, G for hostile behavior. **Effort:** L for matching, L semantics; contingent R2/R3/R8 merge.

### B — proposed agent assignment

> Reconcile BinExport2 accepted-snapshot source and pins with BinDiff supervised import, then reproduce rz-diff 0.9.1 strict parser/orientation failures. Preserve SHA, source side and raw receipts; fail explicit when native tool absent. Add native Linux and Windows acceptance tests, surface evidence limitations. Do not treat mocked adapter tests or two parsed native cases as general interoperability proof. Do not adopt third-party binaries or licenses silently.

**Files:** `src/patchtrace/secondary/{binexport_run.py,bindiff_run.py,rzdiff.py,reconcile.py}`; tests and `.github/workflows/live-{bindiff,rizin}.yml` after ownership check. **External:** licensed BinDiff/pinned Ghidra exporter. **Effort:** L + procurement/acceptance unknown.

### C — proposed agent assignment

> Use #130's source-lineage contract and #136's fixtures, not an alternate KB engine. Fetch only consented, pinned official public vendor responses; validate actual MSRC/CSAF response dialect, product/build context, cumulative servicing lineage and negative claims. Preserve exact source date/revision/hash, validate downloaded PE and signed/unsigned status separately. Prove two verified files were chosen or clearly abstain; never say matched function is the CVE fix.

**Files:** `kbcorrelation/sources/`, `acquisition/`, KB tests; if R4 owner is active, work on isolated fixture/acceptance scripts only. **Effort:** XL correlation + L native MSDelta. **External:** live MSRC, Winbindex, Windows native API.

### D — proposed agent assignment

> Reconcile available Qt panel APIs with one analyst journey using stored immutable sample values first. Add state tests for offline search, scope ambiguity, downloads, cancellation, verified pair creation, Ghidriff, unified/secondary evidence and report export. All errors and missing data must be visibly distinct from zero results; preserve GUI-thread-only SQLite writes. No new framework or duplicate dock registry.

**Files:** `ui.py`, `ui_unified.py`, `ui_persistence.py`, `kbcorrelation/panel_qt.py`, `gui/qt/` and related offscreen tests; **reserve ui.py with coordinator**. **Effort:** L. **Dependencies:** B/C integration contracts for real final acceptance.

### E — proposed agent assignment

> Build an independent, provenance-checked held-out evaluation harness using existing Tier R/W tooling. Add correct sample-group splits, negative controls, preregistered locked final evaluation, resource timing/RSS and GUI latency. Do not access a locked holdout for tuning. Existing calibration source and source labels remain owned by #128/#132. Keep numeric probabilities disabled pending qualified Tier W result.

**Files:** `tools/calibration/`, `tools/unified/bench.py` and separate benchmark/test modules. **Effort:** XL corpus/calibration, L performance. **External:** licensed/native Win11 data + independent labels.

### F — proposed agent assignment

> On a fresh Windows runner, build an exact-head frozen portable ZIP and Setup EXE, inspect SHA sidecars and include source commit, test clean user/long path/OneDrive/cancel/recovery; verify real native backend and optional no-backend messaging separately. Do not claim official offline runtime bundle works unless real Ghidra+JDK+Python+Ghidriff relocation and disconnected Windows case are exercised. Capture signed/unsigned policy.

**Files:** `tools/build_windows.py`, `tools/package_windows_installer.py`, `tools/test_windows_*.ps1`, `.github/workflows/qa-windows.yml`. **Effort:** L. **Requires:** current-head gates before publication.

### G — proposed agent assignment

> Independent adversarial QA: repair the live-gate harness first without weakening any assertion, then run subprocess inheritance/timeout/kill-tree/no-network/hostile-output tests on Win11. Prove prior committed runs survive failures. File minimal reproducible tickets, coordinate source fixes through each feature owner. Do not claim no-symbol means air-gapped.

**Files:** reserved `tests/test_security_*.py`, isolated `tools/` harness and workflow diagnostic script, plus owner-reviewed fixes in `jobs.py`, `backend.py`, `persistence.py` only if free. **Effort:** L.

## Parallel work schedule and dependency cuts

| Phase | Gate | Concurrent safe work | Integrator action |
|---|---|---|---|
| P0 | source/ownership map complete | R1 labels (existing owner), B native adapter harness, F packaging runbook, G hostile test fixtures, D UI model tests | freeze head and file-owner ledger; do not duplicate #128–#135 |
| P1 | GT-01 has observed >0 real pairs | R2 fixes/review, R3/R8 semantic regressions, C source fixtures, E benchmark base | review exact-head PR checks and merge only accepted minimal slices |
| P2 | unified+secondary native contracts stable | D end-to-end workflow, C verified pair, E Tier R/W evidence, G Windows isolation | combine one subsystem at a time and rerun cross-platform CI |
| P3 | end-to-end real fixture green | F clean Windows ZIP/Setup/OneDrive tests, E locked evaluation, G final security checks | issue candidate SHA and source-controlled acceptance artifacts |
| P4 | mandatory release gates green | no feature changes; only necessary low-risk repairs | sign off exact artifacts, create release candidate; no auto-release solely from docs |

## Suggested integration order

1. Coordinator documents PR #136 disposition and R1–R8 ownership, and fixes GT-01 diagnostic/harness with G. No unverified existing research branch merged during this step.
2. Integrate independently passing R2 matching/fusion fixes (#131). No threshold changes. Re-run G-U evaluated matrix.
3. Integrate R3/R8 semantic/canonicalization consensus as one versioned additive change, with negative-control red/green proofs.
4. Integrate BinExport2/BinDiff/rz-diff native adapter acceptance independently, especially parser version + orientation.
5. Integrate R4 vendor correlation and #136 KB fixtures; native MSDelta + identity verified downstream.
6. Merge Qt presentation and report wiring after contracts freeze; preserve user annotations, existing project archives and old derived results.
7. Integrate R1/R5 evaluation artifacts only after independent label/holdout requirements, turn on numeric confidence only if separate promotion requirements are met (optional for alpha).
8. Build exact-head Windows artifact; run adversarial, Windows clean-user and release integrity gates, then strictly attest and publish. Preserve newer external PRs #102/#126/#127 until separately disposed.

## PR acceptance checklist for every worker

- Head SHA and baseline parent, base target, exact changed-file list, owner reservation, no dirty/overwritten work.
- Applicable AGENTS/CLAUDE/spec read, relevant schema modified first for contract changes, explanation of preserved data.
- Focused red→green test output and reproduction fixture/digest; full `python -m ruff check src tests tools`; Linux/Windows `QT_QPA_PLATFORM=offscreen python -m pytest -q` as CI applicable; native tests separately labelled.
- Check workflows at **new exact SHA**: no substitution of an old green head, pending/skipped is not passed.
- Evidence receipt includes native tool versions, binary hashes, platform, executed job count, positive/negative denominators, failed/cancelled/unknown reasons and performance figures when claimed.
- PR can be proposed to integration only if ownership and checks permit. Do not auto-approve, force-push, override protections or merge unreviewed draft research. The integrator is the only shared-file editor.

## Stop conditions / externally dependent work

Stop only the dependent task when a licensed tool, verified private Windows binary, actual native Win11 environment, owner-controlled branch, or permission is unavailable. Continue bounded independent tests and docs. Preserve explicit blocked status; no false completion claim. Merge reviewed non-overlapping work while leaving blocked/native-only features conditional.
