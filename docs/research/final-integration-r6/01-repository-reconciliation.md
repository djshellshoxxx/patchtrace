# 01 — Live repository, branch, R1–R5 and CI reconciliation

**Observation date:** 2026-10-30 UTC. **Authoritative reference:** [main a04f5a2](https://github.com/djshellshoxxx/patchtrace/commit/a04f5a299a8d4afef023261e52e08d14678cf1e7), following merge of PR #124. **R6 state:** documentation handoff, not a checkout-wide merge audit or native test run.

## 1. What is actually implemented in main

The following paths were verified from the main tree, not inferred from a checkbox:

| Product subsystem | Existing implementation surface | Important constraint |
|---|---|---|
| Main lifecycle | `src/patchtrace/{service,persistence,ingestion,backend,normalization,reports}.py` | Primary run/snapshot is committed evidence; derived data never overwrites it |
| Qt analyst workspace | `ui.py`, `ui_unified.py`, `ui_evidence.py`, `ui_series.py`, `ui_persistence.py`, `ui_inspection.py`, `ui_leads.py` | Existing single application window; child workers must not own the UI-thread SQLite connection |
| Unified pipeline | `unified/{pipeline,worker,compute,contracts,keys,store,read_model,registry,addressing}.py` | SPEC-31 `unified-result/1`; flag/readiness and actual native accuracy remain independent |
| ProgramIR and matching | `unified/{extract,ir,ladder,fusion,facts,sources}` | Current ladder already contains P01–P19, propagation and residual; older plans claiming “not implemented” are stale |
| Secondary engines | `secondary/{registry,scheduler,bindiff,bindiff_run,binexport*,rzdiff,reconcile,store}.py` | BinExport2 is an input/producer, BinDiff consumes verified exports, rz-diff is a separate engine; GUI support is partial |
| Security advisories | `kbcorrelation/{contracts,index,products,source*,lineage,resolver,pairs,service,cli*,panel_qt,leads}.py` | Synthetic CVRF dialect ≠ real Microsoft MSRC compatibility |
| PE acquisition | `acquisition/{transport,quarantine,winbindex,delta,workflow}.py` | Explicit network consent, hash-first identity and actual Windows native reconstruction are separate gates |
| Additional context | `enrichment/`, `intelligence/csaf/`, `kev/`, `pilot/` | Metadata or ranking must not modify original function identities |
| Statistical calibration | `src/patchtrace/calibration/`, `tools/calibration/{tier_r,tier_w,evalcore,...}` | Target A correspondence only; ordinal runtime is legitimate fallback |
| Packaging | `tools/build_windows.py`, `tools/frozen_smoke.py`, `installer/PatchTrace.nsi`, release workflows | Frozen desktop successful does not imply a bundled analysis backend or a clean-system acceptance pass |
| Existing QA | extensive `tests/test_unified_*`, `test_kbc_*`, `test_calibration_*`, `test_ui_*` | Native probes and locked tests require distinct receipts |

**Architecture interpretation:** `docs/specs/unified-engine/README.md` starts with a 2026-10-14 status stating only S0 was implemented; R2/R3 live source review confirms substantial later implementation. Read current files, recent PRs and actual tests before using any historical “planned” label. Similarly, `tasks/todo.md` has repeated historical entries for secondary/series work.

## 2. Research PR inventory and import contracts

| PR/head | Unique work to inspect | Dependencies / conflicts | Recommended disposition |
|---|---|---|---|
| [#128 R1](https://github.com/djshellshoxxx/patchtrace/pull/128) `a02a1774a1617441072f4a8770348cc22038eeac` | Deterministic ground-truth pilot, audited source/PE/PDB review, label admission, leakage, R1 build/observer tests | May edit `docs/modules.md`, `corpus/ours/`, `tools/calibration/tier_r/` and live gate workflow; conflicts with calibration PRs #78/#79/#82/#85 | Preserve R1 as ground-truth owner; merge only reviewed labeler/harness fixes with exact-image test evidence |
| [#131 R2](https://github.com/djshellshoxxx/patchtrace/pull/131) `c704a39c8ece56c3215c1d765d79e7f4780ddcbd` | Provenance-preserving fusion, safe evidence caps, deterministic atoms, truthful manual-group text, IR-only leftovers, CFG back-edge efficiency, cache identity; synthetic/native probes | Shared `docs/modules.md`, `unified/fusion/arbiter.py`, `unified/ir/cfg.py`, `sources/ladder.py` and specs; overlaps R3 proof/spec changes and active unified workers | Import narrow, independently tested commits in dependency order; do not import benchmark numbers as measured real accuracy |
| [#129 R3](https://github.com/djshellshoxxx/patchtrace/pull/129) `2698b9a04d33b2d04f49c1ab737636539c6ef6f7` | EH guard and register-only blocker for `COS-PSEUDO/1`, conservative semantic proof tests, static compiler experiment and research | `unified/facts/verdict.py`, `registry.py`, `docs/qa.md`, `tasks/todo.md`; conflicts with #86 retained text and R2 `05-fusion-and-noise.md` | Spec/proof version update, red-green tests, verify native IR; land in isolated patch without shared tracker edits |
| [#130 R4](https://github.com/djshellshoxxx/patchtrace/pull/130) `ff570bdd784d02f745e4ad21d8aa7b4f1f776344` | Detailed MSRC/Windows servicing, evidence graph, vendor source and product-scope compatibility notes; 22 adversarial fixture definitions; prioritized backlog | **Docs-only** `docs/research/vulnerability-correlation-r4/`, no runtime/MSRC parser acceptance; #126 coordinates tracker | Review and integrate as research reference. Start separate real-CVRF adapter PR after obtaining pinned official input |
| [#132 R5](https://github.com/djshellshoxxx/patchtrace/pull/132) `4d9d9051aea87319847a0b321a14d37b95cb8abd` | Calibration protocol, per-lineage statistics, promotion trust risk, native Tier W requirements, OOD and runbook, toy non-independence study | **Docs-only** `docs/research/calibration-r5/`; #78/#79/#82/#85 calibration implementation branches | Integrate as design/test requirements; do not activate numeric confidence based on this PR |
| [#126 milestone coordinator](https://github.com/djshellshoxxx/patchtrace/pull/126) `8d958f0a1950a29c1d1cef9525a114654f4c9904` when checked | Milestone ledger and code fixes in callgraph, rules, KB | Direct ownership of `docs/qa.md`, `tasks/todo.md` and integration status; changed files include production code | Coordinate shared tracker updates; do not replace this owner's work with stale R6 snapshots |
| [#127 Qt workspaces](https://github.com/djshellshoxxx/patchtrace/pull/127) | Dockable layout specification, separate UX owner | Qt UI central files may overlap upcoming R6 GUI slices | Review before any Qt structural changes; defer nonessential redesign |

Other **open historical** PRs requiring a *change-by-change* comparison with main: #68 (corpus cards), #71/#90 (fixture corrections), #78 (Tier R outputs), #79/#82 (two-sided A/A and noise), #85 (locked prereg), #86 (bounded retained decompilation), #94 (performance test timing), #100 (local symbols/Diaphora), #102 (Windows alpha and parser hardening). Their “open” state is not proof that none of the functionality is present in main; earlier squash/merge work can supersede file content. Do not merge an entire stale branch merely because it remains open.

**Branch count is volatile:** other researchers reported 117–119 branches and approximately 20–23 PRs on 2026-10-30. This directory intentionally records the relevant named owners rather than asserting a permanent exhaustive branch inventory. Obtain a fresh paginated snapshot with SHA and base/merge-base before each merge.

## 3. Exact-head CI ledger (do not flatten statuses)

The main commit's [QA and Windows standalone](https://github.com/djshellshoxxx/patchtrace/actions/runs/41060959610), [native Windows Ghidriff](https://github.com/djshellshoxxx/patchtrace/actions/runs/41060959854), [live unified extraction](https://github.com/djshellshoxxx/patchtrace/actions/runs/41060959558), [live rz-diff](https://github.com/djshellshoxxx/patchtrace/actions/runs/41060959715) and [Tier R shard](https://github.com/djshellshoxxx/patchtrace/actions/runs/41060959579) each completed with a successful *workflow*. This supports the specific exercised smoke paths, not final release acceptance.

The exact same `main` SHA also ran [advisory unified live gates 41063115449](https://github.com/djshellshoxxx/patchtrace/actions/runs/41063115449). **Observed child jobs: 27 failures, 3 successes** despite overall workflow conclusion `success` because relevant jobs are advisory/continue-on-error. The gate result was **NOT READY** with:
- Build job: 273 generated pairs, including 12 planted-mutation classes with 20 mutants/class; **build coverage only**.
- Linux A/A/release: **zero outcomes**. Harness `tools/unified/live_pairs.py` requires `run.status == 'completed'`, but byte-identical pairs return `identical`. Other pairs encountered native backend failures requiring raw log triage (do not guess their root cause).
- Linux integrity job: import/pytest prevented by missing `libEGL.so.1`; dependency issue, not an automatic semantic test failure.
- G-U1: 15 missing A/A cases; G-U2: zero evaluated cases for each of the 12 classes; G-U3: zero matched rows, precision **undefined**; G-U4: no repeat/mirror evidence; G-U5: some synthetic benchmark subreports only; G-U6/G-U7: unmeasured; G-U8: missing frozen smoke despite several passing integrity checks.
- Gate-report SHA-256: `6328006a60e94c51aec6e0cc182f84bb3dbc8bfdd76c32685d0e888e06204710`. Keep the raw report as an immutable artifact. A new report must be separately keyed and compared, not overwrite this failed baseline.

Baseline SonarCloud check had a failed code-analysis check on that SHA; isolate it from functional pytest failure, and require an owner policy choice for whether it is gating. A queued/skipped GitHub check is neither a pass nor a fail. **Every merge must re-run gates for the PR's actual head, not reuse main's green results.**

## 4. Published binary versus source: keep these separate

The newest release returned by the GitHub Releases API at inspection was [v0.1.0-beta.543](https://github.com/djshellshoxxx/patchtrace/releases/tag/v0.1.0-beta.543), published 2026-10-29 and targeting `f4063c3cc7e0c9d02d972e798699ad206628a5f1`. It predates `a04f5a2`. It includes canonical Windows ZIP, portable alias ZIP, NSIS per-user Setup.exe, Linux tarball and SHA sidecars. API asset digests returned:
- `PatchTrace-0.1.0-windows-x64.zip`: `fd95010f866de7d88b14b10dbe8410ca6eedd92688a4d75837a2c617e4533edb`.
- `PatchTrace-Windows-x64-Setup.exe`: `cef4b4e53a71ce4bf58c1ca6ed5a357a0e24cde9ca42a1140ef3bb9ac26fb8b1`.

Do not call this the R6 integration release. Record at release time: tag, peeled annotated commit, exact SHA of audited code, Actions run/job IDs, ZIP and Setup SHA/size, actual binaries downloaded and rehashed, AV/SmartScreen status, clean-profile test machine, Ghidra/Java/tool versions and results. Releasing the desktop does not retroactively validate a missing BinDiff tool or absent offline backend bundle.

## 5. Source security observations and exact-status caution

1. **Verified-backup tamper/data-durability risk — live code still warrants regression.** At the checked main, `src/patchtrace/verified_backup.py::_fingerprint` uses only `(st_size, st_mtime_ns)`. `trusted_backup` can reuse an earlier cached verdict without re-opening the backup. [Audit #121](https://github.com/djshellshoxxx/patchtrace/issues/121) describes a same-size/mtime-restored alteration before irreversible history pruning in `persistence.py`. The mechanism remains visible in main; reproduce against the current code, then fix before trusting destructive pruning. A cache-hit test must not be substituted for verification against altered bytes.
2. **Calibration sign-off trust boundary — verified live code.** `tools/calibration/fit.py::_reproduce_gates` currently constructs `cond` with four external preconditions forced to `True` (`reproducibility_check`, `owner_signoff`, `frozen_exe_smoke`, `independence_caveat_shown`) before evaluating claimed gates. This is not independent attestation of those conditions. Block model promotion until a trusted external evidence input is verified and bound to profile/prereg/report/runner.
3. **Semantic pseudo-proof — draft fix, not main.** At main, `facts/verdict.py::_pseudo_proof` permits `ev.eh == 'unavailable'` provided it is not `'differs'`, and `PSEUDO_BLOCKERS` omits `'register-only'`. R3 #129 changes both; merge only after spec, proof-version, focused tests, CI and native validation.
4. **Live Microsoft CVRF parser — verified source gap.** `kbcorrelation/sources/cvrf.py` explicitly documents `cvrf-json/0`/`cvrf-xml/0` as synthetic placeholders using an `example.invalid` namespace. No official MSRC monthly CVRF compatibility is established by fixture success.
5. **Release gating — partially repaired since older audit.** Audit #121 described release without Qt-gate dependency at an older PR SHA. **Current** `.github/workflows/qa-windows.yml` release job explicitly has `needs: [qa, qt-gate, linux-smoke, release-gate]`; do **not** repeat the stale “Qt not gated” finding as currently true. Separate native Ghidriff/Unified/BinDiff gates are still not hard dependencies of `release`; define a single verified R6 acceptance status before calling it release-ready. An automatic beta publication should not be confused with an R6-ready release.

## 6. Safe integration algorithm (execute on a real checkout)

```bash
git status --short
git branch -vv
git worktree list --porcelain
git remote -v
git fetch --prune origin
git rev-parse origin/main
gh pr list --repo djshellshoxxx/patchtrace --state open --limit 100 --json number,title,headRefName,headRefOid,baseRefName,isDraft,reviewDecision,mergeStateStatus
gh run list --repo djshellshoxxx/patchtrace --limit 40
```

- Check repository instructions and file ownership, record dirty/untracked files and private worktrees; do not modify other workers' working copies or reuse their branch names.
- For each PR, compare three things: its diff versus its original base, live main's current file semantics, and the missing tests/behavior. Calculate merge-base and patch-equivalence; a unique commit does not always equal unique functionality.
- Create one new integration worktree/branch from refreshed main; one integrator owns `contracts.py`, shared SQLite schema, `ui.py`, `docs/qa.md`, `tasks/todo.md` and release workflow. Independent workers own disjoint leaf modules/tests and can open draft PRs.
- Apply first: small nonoverlapping R1/R2/R3 correctness fixes with exact regressions; then native harness; then real MSRC and acquisition; then GUI and release. Require all upstream SHA/consent/licence and optional-tool conditions at each step.
- Run focused red→green tests, Qt-offscreen full pytest, Ruff and schema drift; review changed persisted contract/feature flags; execute Linux and Windows current-head CI and native tools; verify no original snapshot differs; merge after actual review.
- Record each completed merge and superseded branch, not merely “all work consolidated.” Never force-push or silently discard unique changes.

## 7. Evidence labels for every future task

`CODE-PRESENT`: source exists at named SHA. `TESTED-UNIT`: actual reported test with command/count/OS/SHA. `NATIVE-ACCEPTED`: real pinned executable, input/output hashes, process logs, OS and expected behavior. `E2E-ACCEPTED`: end-user workflow including persistence/UI/export and review. `PUBLISHED`: released asset SHA and target ref verified. `DRAFT`, `FAILED`, `BLOCKED`, `INSUFFICIENT-DATA` and `NOT-RUN` remain separate. A claim of 100% completion requires every applicable category, not a ready-looking class or green workflow badge.

**Handoff constraint:** This R6 documentation branch deliberately does not edit `docs/qa.md` or `tasks/todo.md` while #126 holds those shared files. See document 08 for text and matrix to reconcile under the coordinator.
