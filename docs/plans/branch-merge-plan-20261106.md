# PatchTrace branch consolidation and execution plan

Audit date: **November 5, 2026 (America/Los_Angeles)**. GitHub observations and this filename use November 6 UTC. This is a source-pinned merge plan and execution receipt, not a release-completion claim.

## Decision

Use the existing **#205 → #218 → #235** integration chain as the product consolidation path. Preserve its review boundaries. Bring the two remaining current slices, **#242 and #243**, together in one isolated, reviewed candidate targeting #235. Advance the small, independent workflow repair **#204** toward main first. Do not replay older cumulative branches just to reduce the branch count.

Do not merge #205 unchanged: its exact head has verified hosted failures. Keep its qualification owner's frozen branch intact. Before it can reach main, the owner must apply the narrowly reviewed repairs needed for its current gates; the known crash-test correction is already carried by #219/#218. The later feature waves remain separately reviewable. Do not roll all later features backward into #205 merely to make an old PR green.

The user authorized this analysis and starting consolidation. Source branch rewriting, branch deletion, scanner suppression, failing-check bypasses, and activation of overlapping paid workflows are not part of this execution.

## Execution checkpoint — 2026-11-06 UTC

The audit inventory below remains frozen. Two new task-owned branches and PRs were created after that snapshot; its 242-branch/112-PR counts are not a current repository total.

| Planned work | Work completed | Remaining boundary |
|---|---|---|
| Independent workflow repair #204 | Ready for review at unchanged `1229ca3bba6bc099d040c279ed9ebc8b91ae913e`; existing Linux, Windows, Qt, packaging and scanner successes preserved | Both Linux smoke jobs still require successful results before the planned main merge |
| Current application leaves #242/#243 | History-preserving consolidation in [#244](https://github.com/djshellshoxxx/patchtrace/pull/244), targeting #235 | Current-head hosted checks and applicable review remain required |
| Frozen #205 qualification repairs | Published [#245](https://github.com/djshellshoxxx/patchtrace/pull/245) at `4465a0492367d08f324e80b290a594791921691c`, targeting the unchanged #205 owner branch | Native Windows and applicable full-suite/scanner requirements remain open; the original #205 ref is untouched |
| Downstream recovery propagation | Staged #245 once in the isolated #244 candidate; exact resolved tree `9bebb7cc0fed5d8326f9c9d25781d3576298133f` | This preparation does not advance frozen #205, #218, #235 or main |
| #244 source-provenance review | Confirmed the Qodo finding with two failing real-store tests, implemented the bounded admission-index repair, obtained independent review and passing regressions | Normal hosted/review disposition on the resulting head remains separate |
| #183 workspace/wiki documentation | Adapted the useful draft workspace proposal; recorded seven pinned sources and six reference-only wiki dispositions | Other historical research/specification groups remain selective reconciliation work |

The combined reviewed source publication is `a502c9c241d855dba530160e19215d802ebaf90f`, tree `3e5276d6643d784e459264d6cb213082b812c8d4`. The coordinator's combined selection passed **774 tests in 37.31 seconds**, including both current leaves, the source-provenance repair, N-way/crash recovery and the documentation registry. Whole-tree Ruff passed; KBC schema generation produced no drift. Later documentation/evidence updates do not change that source. The earlier 424/54/75/294-test selections overlap this run and must not be added as unique coverage.

Detailed receipts: [consolidation validation](../qa/branch-merge-readiness-20261106.md), [recovery diagnosis](../qa/nway-windows-recovery-20261106.md), [source-admission repair](../qa/kb-source-admission-20261106.md), and [workspace documentation disposition](../research/workspace-docs-reconciliation-20261106.md). The separate full Linux run belongs to exact #245, not the newer combined #244 tree; its actual outcome is **3 failed, 19618 passed, 139 skipped, 6 xfailed, 1 warning in 2537.16s (0:42:17)**. [The full Linux receipt](../qa/pr245-linux-qualification-20261106.md) preserves the raw result and separate baseline/environment controls. This run is not green.

### Efficient propagation after qualification

Read-only simulations showed that #245's production/specification/regression changes merge cleanly into #218, #235 and #244. The crash-test keyword correction is already byte-identical in all three descendants. Only `docs/qa.md` and `tasks/todo.md` conflict: preserve each destination's complete bytes and append the corresponding #205-to-#245 receipt once. Do not replace either ledger with the older branch's whole file.

The isolated #244 merge follows that exact resolution and preserves #245 as a merge parent. Once the respective gates permit owner promotion, accept #245 into #205 and propagate the updated parent forward through #218 and #235. The already-prepared #244 history then recognizes the repair by ancestry rather than applying it again. Main promotion remains #204 first, then the reviewed #205 → #218 → updated #235 sequence.

The existing PRs are stacked: #205 targets `main`, #218 targets `integrate/swarm-qualified-20261105`, and #235 targets `integrate/swarm-wave3-20261105`. For main promotion, explicitly retarget #218 to `main` after #205 is accepted there, then retarget #235 to `main` after #218 is accepted. Refresh the comparison, mergeability and applicable current-head/base checks at each step. The base change is part of promotion; accepting a child into its current parent branch would be a different operation. Preserve the parent branches and use expected-head merge protection.

CodeRabbit explicitly skips #244/#245 because reviews are disabled for their integration base branches; those skipped checks are not completed reviews. Independent code review is recorded separately. The parent Sonar findings retain their normal disposition requirements even when a new delta's Sonar check passes. The repository currently has auto-merge disabled; no deferred merge has been scheduled.

The #218 Windows result completed at 05:58:57 UTC: **6 failed, 19,980 passed, 89 skipped, 5 xfailed**, with 19 warnings in 4,403.56 seconds. All five original #205 N-way failures recur; the additional `changed-True` recovery test also refused before its intended second-pass mutation. The relevant production/tests are byte-identical between the two old heads. This supports propagating the same reviewed repair; it is not native verification of that repair. Windows build, frozen EXE, portable ZIP and installer checks were skipped after pytest failed. [Completed Windows evidence](../qa/nway-windows-recovery-20261106.md#completed-218-windows-result).

## Frozen inventory and anchors

| Anchor | Branch | Exact head |
|---|---|---|
| main | `main` | `5d504ff5c046bfb758623182b472976003632bba` |
| #205 | `integrate/swarm-qualified-20261105` | `f33e2a0aaa3399644367f2419fee21cfe2e8702b` |
| #218 | `integrate/swarm-wave3-20261105` | `afc8a2967ba3dec6b1ac3351d20dd08c193ba9bc` |
| #235 | `integrate/independent-wave4-20261105` | `ccfe175d44a70947203c75bbd033a9a9e2633f0f` |
| #242 | `resume/kb-acquire-lifecycle-20261106` | `b8bda98452b2f742ad55064aa2e1452700658a33` |
| #243 | `resume/desktop-index-refresh-20261106` | `c9cea0671442a6051b068acfb69d17aabcf674ae` |

The fetched snapshot contains **242 remote branch names, 241 distinct branch-head SHAs, and 112 open PRs** (103 draft at inventory time). The staging branch created during this task is excluded from these counts.

| Earliest carrier containing the exact branch head | Branch names | Open PR heads |
|---|---:|---:|
| main | 26 | 0 |
| #205 | 28 | 23 |
| #218 | 8 | 5 |
| #235 | 17 | 13 |
| Outside #235 ancestry | 163 | 71 |
| Total | 242 | 112 |

Thus **79 branch heads and 41 open PR heads are already in #235's ancestry**. The 41 include #205, #218, and #235 themselves; 38 are additional source PRs. Another **12 branch names / 5 open PRs** have all unique nonmerge patches represented by stable patch IDs in #235 history. The other **151 branch names / 66 open PR heads** need content-level relevance decisions. They are not 151 independent features and are not all merge candidates.

Patch identity and ancestry are different evidence. Patch identity does not prove that merge resolutions or the current behavior agree. A clean Git merge is also not a correctness or release-acceptance result.

Complete records:

- [242-branch inventory and PR dependencies](consolidation-20261106/branch-inventory.json)
- [All 112 open PR dispositions](consolidation-20261106/open-pr-matrix.md)
- [Read-only merge simulations](consolidation-20261106/merge-simulations.json)
- [New staging verification receipt](../qa/branch-merge-readiness-20261106.md)

## Concrete execution order

### 1. Finish the independent CI repair, #204

[PR #204](https://github.com/djshellshoxxx/patchtrace/pull/204), head `1229ca3bba6bc099d040c279ed9ebc8b91ae913e`, moves the invalid standalone agent step out of `.github/workflows/` and retains its bytes under `.github/workflow-examples/`. It adds no runnable agent or schedule.

This task independently reproduced **3 failures, 48 passes, and 3 existing expected failures on main**. The unchanged PR head produced **49 passes and the same 3 expected failures**, with whole-tree Ruff passing. Its existing hosted evidence is stronger:

| Exact-head check | Observed result |
|---|---|
| Ubuntu full QA | 18,729 passed; 47 skipped; 7 xfailed |
| Windows full QA | 18,696 passed; 81 skipped; 6 xfailed |
| Five Qt gates | All successful |
| Linux package | Successful |
| SonarCloud and Snyk | Successful |
| Linux smoke on 22.04 and 24.04 | Queued at audit |
| CodeRabbit | Previously skipped because draft; now successful after readiness transition; no unresolved inline threads observed |

[Hosted QA run](https://github.com/djshellshoxxx/patchtrace/actions/runs/42112574660).

**Action already taken:** marked #204 ready for review, preserved its head, and appended the fresh evidence to its PR description. This retains the already successful expensive checks. Do not rebase, repush, or rerun those passing jobs without a concrete new reason.

**Next:** inspect both smoke results and the normal review outcome. Merge through GitHub with the expected head SHA only when applicable requirements pass. #204 is already in #235 ancestry, so no additional merge of it into that integration branch is necessary. Refresh all bases after its main merge.

### 2. Complete the current two-slice integration candidate

The isolated branch `integrate/merge-readiness-20261106` starts at #235 and incorporates #242 and #243 with history-preserving merges. It does not update either source branch or the frozen integration owners' branches.

| Slice | Intended change | Net scope relative to #235 |
|---|---|---|
| #242 | Cancellation propagation plus captured revision/source admission checks before final import | 4 files; 340 insertions, 5 deletions |
| #243 | Explicit desktop metadata preview, separate single-operation consent, refresh receipt, and saved-candidate inspection | 5 files; 410 insertions, 11 deletions |

The two file sets are disjoint. The combined source merge changes **nine files, including three production files**, with 750 insertions and 16 deletions. It adds no binary acquisition UI, new transport, schema, dependency, or target execution.

**#243's merge-base issue:** its history has two merge bases with #235: `bf3661966785a971f484b6339af81274278d1434` and `92f2ab687790909bde87031ef6557b05d9683adb`. A triple-dot diff can choose only one and show already-integrated material as new. GitHub reported the source PR as dirty; Git 2.52's `ort` merge constructed the virtual base and cleanly preserved the exact intended five-file change. Do not copy entire old files over newer integration files to resolve this condition.

The reviewed source tree is **`ea48a7e087590fccffadb54e4414bd000f16838b`**. Every changed blob matches its owning leaf. Later #235 handoff, QA, module, task, and scanner records were explicitly checked unchanged. The root ran **424 affected tests, all passing in 27.17 seconds**, whole-tree Ruff, whitespace checks, and KBC schema generation with no schema drift. An independent reviewer found no blocking standards or specification issues and ran **42 overlapping regression tests, all passing in 2.73 seconds**. These totals are not additive unique coverage.

**Execution:** the candidate is published as #244 and ready for normal review. The checkpoint above records the subsequent documentation and reviewed repair additions. Obtain hosted current-head evidence and normal review, then integrate it into #235 only after the applicable slice gates pass. Preserve #242/#243 as source records until the accepted carrier has reached main and inclusion has been rechecked.

### 3. Repair and qualify the existing product train

| Stage | Actual evidence / blocker | Required next step |
|---|---|---|
| #205 | Ubuntu: 19,701 passed, one failed; Windows: 19,660 passed, six failed; Sonar failed | Preserve its frozen owner. Apply only reviewed qualification repairs, then rerun affected failed work and finish required evidence on the new head. |
| #218 | Ubuntu: 20,022 passed, 52 skipped, 6 xfailed; completed Windows: 6 failed, 19,980 passed, 89 skipped, 5 xfailed; some Qt/corpus work unfinished; Sonar failed | Propagate the narrowly reviewed recovery prerequisite after owner qualification; require Windows QA and the skipped build/package checks on the repaired head. |
| #235 | Most hosted work queued; Sonar failed; draft review skipped | Qualify the eventual stable head after the two-slice candidate is accepted; retain the open scanner disposition. |

The exact #205 Linux failure is a stale subprocess crash-test double: `park()` rejects the new `created=` keyword. #219/#218 carry a correction. Its five additional Windows recovery failures occur in `test_nway_recovery_copy_20261105.py` and `test_nway_series_tolerance.py`; these need platform-specific evidence, not an assumption that runner delay caused them. [#205 Ubuntu job](https://github.com/djshellshoxxx/patchtrace/actions/runs/42122458590/job/127578062128), [Windows job](https://github.com/djshellshoxxx/patchtrace/actions/runs/42122458590/job/127578061546).

[#218 Ubuntu job](https://github.com/djshellshoxxx/patchtrace/actions/runs/42127592775/job/127595647592) completed successfully; [Windows job](https://github.com/djshellshoxxx/patchtrace/actions/runs/42127592775/job/127595647308) has now completed with the six recovery failures detailed above. These hosted results supersede the older handoff's incomplete local run at 94% and this audit's earlier pending Windows observation.

The main promotion order remains **#205, then #218, then updated #235**. After each accepted parent reaches main, refresh the next PR's base and compare the actual merge result, retaining only the next stage's reviewed delta. A failed stage does not become eligible because a later branch exists. No direct main push, force update, synthetic successful status, or weakening of checks is part of the plan.

For #235, the open Sonar finding is `pythonsecurity:S8707` in `tools/check_windows_package.py`, key `AaGuFuc-a2s4H-WIcBuh`. [The preserved independent triage](../qa/sonar235-package-path-20261105.md) argues that the explicit local read-only CLI path is intentional. That is supporting review material; an authorized normal scanner disposition and passing current-head result are still required. Do not suppress the rule or change the gate to force promotion.

### 4. Reconcile the historical documentation lane

Historical research was partially preserved through #231. An independent content, byte-count, and SHA-256 check confirmed all **17 receipt-listed files**: nine dossier files from #178 and eight R5 files from #183. This does not establish whole-PR equivalence.

The clearest remaining documentation source is **#183**, `ed70e6ddac449a42f843f1c60aa878416ab31727`. There are **125 source paths absent at #235**:

| Group | Missing historical paths |
|---|---:|
| R2 research / results | 10 documents and 67 result artifacts |
| R3 | 4 |
| R4 | 9 |
| R6 | 9 |
| R8 | 5 |
| Panel specifications | 9 |
| Dockable workspace specification | 1 |
| Wiki | 6 |
| Plans, dependency maps, gaps, blockers | 5 |

Import enduring documents in small source-pinned slices, with a disposition manifest. Keep historical claims and evidence dates explicit; do not overwrite current trackers or imply old recommendations remain accepted. Missing artifacts do not automatically mean missing product behavior.

The first such slice is complete: [workspace documentation reconciliation](../research/workspace-docs-reconciliation-20261106.md) adapts the dockable-workspace proposal and preserves all seven source identities. The six wiki pages remain reference-only because current guides cover their content; inaccurate old Qt boundaries and stale counts were not carried forward. The proposed workspace alias and unimplemented core-docking work remain explicitly draft.

#178 has green hosted checks but two unresolved review threads: the `_self_check` versus `self_check` naming correction and floating source references S10-S17. Resolve the substance and verify what #231 already preserves before attempting a whole-PR merge. #179 and #187 are useful historical audit references, not current ownership or acceptance evidence. #187's old QA failures are the workflow-fragment defect addressed by #204.

### 5. Preserve the separate native and automation lanes

- **Native #222 → #224:** #224 contains #222, but neither is in #235 ancestry. These branches retain real failure evidence and separately owned qualification. Their descriptions leave CLI, Windows, application-adoption, and Tier R gates open. Keep their native worktrees, source pins, quarantine, and acceptance thresholds intact. If a later evidence slice is accepted, avoid merging both cumulative tips independently.
- **Automation #167/#170/#171/#186:** these are distinct overlapping operating models. #170 introduces scheduled API-funded development; #171 introduces eight workers and four daily batches; #186 is a manual workflow repair. They are not proven duplicates and must not all be enabled as a side effect of branch consolidation. No paid agents or schedules are started by this task.
- **Partial older source #174/#176:** current carriers have selected ports, but not all historical tests, receipts, and workflows. Compare a proposed behavior against current contracts before making a small port. Do not merge the old cumulative train wholesale.
- **Older #163/#164 and producer branches:** preserve the earlier owner restrictions and history. They contain overlapping and superseded integration assumptions, not an automatic shortcut to current acceptance.

### 6. Reconcile source PRs only after main acceptance

Exact ancestry-covered open PRs are enumerated in the matrix. Five additional open PRs have no unmatched unique nonmerge patches: **#181 (9/9), #182 (4/4), #184 (4/4), #189 (5/5), #190 (1/1)**. Confirm that the accepted current tree retains their intended behavior before assigning a final superseded disposition.

After the relevant carrier is on main, re-fetch source heads, check for new unpublished or unmerged work, and link every source PR disposition to the actual accepted main commit. Keep branches recoverable. No mass deletion or mass closure occurs in this execution. The only duplicate head pair in the snapshot is `access-test-noprefix` and `claude/access-test-1791773355`, both at `726a371ab34d4589b0456d059865ade6b82fac88`; identity alone is not a reason to delete them.

## Why this order is efficient

It reuses existing work and preserves already-completed checks. #204 is a one-commit repair with successful whole Linux/Windows/Qt evidence; making it ready avoids pushing a new head and restarting that work. The current application work needs two small leaves added to one existing carrier, not 112 independent merges. The original PRs remain useful review records.

Run focused tests for a changed boundary, then required broad qualification on a stable candidate. Do not repeatedly restart the full suite for documentation-only updates or re-run successful jobs when only two smoke jobs remain queued. At audit the repository had 35 queued workflow runs and three in progress; those counts do not identify a runner-capacity limit. Keep queue management separate from changes to quality requirements.

## Gate and ownership limits

The connector could read an empty ruleset list but received HTTP 403 for branch protection. That does not establish that main is unprotected. Use the normal GitHub merge operation with an expected source head and honor any enforced requirement; never substitute a direct ref update.

This task has a fresh isolated checkout, and cannot inspect dirty work or live processes in other owners' environments. It therefore leaves their branches and logs unchanged. All new verification is local synthetic Linux behavior. Windows packaging, live providers, native compatibility, model calibration, and release acceptance remain separately evidenced gates.

The revision/source protection in #242 is an **admission check**. Holding `WorkspaceStore` holds a connection; it is not an SQLite write lock spanning download and the whole import. The specification's explicit atomicity limitation remains in force.
The subsequent #244 repair builds the index before that admission comparison and reuses it afterward. Cooperative additions before/during index construction produce stale refusal; additions after admission stay in the workspace but cannot enter the operation's saved context or sidecars. This fixes the confirmed provenance drift without claiming an enclosing transaction.
