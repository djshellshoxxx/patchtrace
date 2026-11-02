# Milestone ledger: integrated essential alpha (2026-10-30)

Working ledger for the milestone in `docs/plans/next-milestone-dev-prompt-20261030.md` (PR #125). Coordinator branch: `claude/modest-hamilton-kz2gta`. Live GitHub state beats this file; re-check before use.

## Step 0 snapshot (13:08 UTC)

- `origin/main` = `5214720716c7afb7952bacbc9afd4b8255574ae8` (#111). Unchanged since the prompt snapshot.
- `git log -8 --oneline origin/main`: 5214720 (#111), f4063c3 (#107), 94bd6a4 (#106), fbe58d8, 45fa67a, e264bd7, 241a777 (#87), e093ade (#97).
- Latest published prerelease: `v0.1.0-beta.543` (2026-10-29 05:40Z).

### #124 at head `95e09548a82202ae4cfd9380522f36513da87a66`

- Base `5214720` = current main. `mergeable_state: unstable` (non-required check failing, not `blocked`).
- Review threads: 9 of 9 resolved. CodeRabbit review skipped (rate limited). Qodo: 0 open findings.
- Checks at head (43 runs): every QA/native/packaging job success.
  - QA run [41041471026](https://github.com/djshellshoxxx/patchtrace/actions/runs/41041471026): `qa (ubuntu-latest)`, `qa (windows-latest)`, `qt-gate` Linux 1–4/4 and Windows 1/1, `linux-package`, `linux-smoke` 22.04/24.04 success; `release`/`release-gate` skipped (PR event).
  - Native Ghidriff five jobs success in runs [41041462592](https://github.com/djshellshoxxx/patchtrace/actions/runs/41041462592) and [41041471132](https://github.com/djshellshoxxx/patchtrace/actions/runs/41041471132).
  - Live rz-diff [41041471212](https://github.com/djshellshoxxx/patchtrace/actions/runs/41041471212) success on ubuntu-latest and windows-latest.
  - Live BinDiff [41041471099](https://github.com/djshellshoxxx/patchtrace/actions/runs/41041471099) job success (licence state still to read from its log; job success is not live-BinDiff evidence).
  - **SonarCloud**: quality gate failed (C security, C reliability on new code). Not a required check. Findings triaged in `docs/audits/20261030-consolidation-review.md` §"Connected SonarCloud check triage". Recorded as open, not green.

### Ownership map (remote branches, last 24 h)

| Branch | Last commit (UTC) | Owner / PR | Disposition |
|---|---|---|---|
| `claude/compassionate-goldberg-5uuqks` | 10-30 12:55 | #125 (prompt author) | docs only, leave to owner |
| `codex/deep-review-consolidation-20261030` | 10-30 10:32 | #124 | land in Phase 1 |
| `claude/awesome-ramanujan-o3pxx3-{ci,hostile,win1}` | 10-30 04:55–05:11 | owner-only | do not touch |
| `codex/pr110-ci-repairs-20261029` | 10-30 05:02 | #115 | superseded candidate |
| `claude/jolly-fermi-eghaxy` | 10-30 04:40 | #123 | superseded candidate |
| `codex/pr110-kb-arch-scope-20261029` | 10-30 04:08 | #122 | superseded candidate |
| `codex/pr110-persistence-feedback-20261029` | 10-30 04:07 | #119 | superseded candidate |
| `codex/pr111-bounded-nav-into-integration-20261029` | 10-30 04:05 | #117 | superseded candidate |
| `fix/pr110-ci-regressions-20261029` | 10-30 03:58 | #113 | superseded candidate |
| `codex/fix-pr110-ci-gates-20261029` | 10-30 03:57 | #114 | superseded candidate |
| `codex/pr110-qa-wbjson-diaphora-help-20261029` | 10-30 03:54 | #112 | superseded candidate |

No branch other than #125's was pushed in the hour before this check, so no conflicting coordinator.

## Decisions

1. **Merge #124 with SonarCloud red.** Reason: M-A defines the gate as the QA workflow legs, all green at the exact head; Sonar is not a required check; its findings are triaged with evidence and the hostile-input fixtures cannot turn green without disabling rules, which the rules forbid. Sonar stays recorded as an open gate.

## Log

| Time (UTC) | Action | SHA / link | Result |
|---|---|---|---|
| 13:10 | ledger created, draft PR | [#126](https://github.com/djshellshoxxx/patchtrace/pull/126) | — |
| 13:09 | **merged #124** (merge commit, expected head `95e0954`) | main `a04f5a299a8d4afef023261e52e08d14678cf1e7` (parents `5214720`, `95e0954`) | push QA run [41060959610](https://github.com/djshellshoxxx/patchtrace/actions/runs/41060959610) started |
| 13:25 | closed #110 #112 #113 #114 #115 #117 #119 #122 #123 as superseded by #124 | comment on each with evidence | see M-B table |

## M-B evidence (superseded PRs)

| PR | Head | Method | Result |
|---|---|---|---|
| #110 | `5ed624e` | `git merge-base --is-ancestor` vs `a04f5a2` | ancestor |
| #113 | `979ddfa` | ancestor check | ancestor (chosen repair alternative) |
| #123 | `99f8328` | ancestor check | ancestor (#124 baseline) |
| #117 | `025300f` | added lines of `c1e21ef..head` present in main tree | 35/35 present |
| #119 | `3e9cedb` | same | 73/73 present |
| #122 | `40e02da` | same | 16/16 present |
| #112 | `aba4c20` | PR test files run against main | 1 fail: asserts standalone `winbindex.strict_json` rejects lone surrogate; on main only `parse`/`parse_rows` call it and both validate per entry → contract without caller, no behaviour lost |
| #114 | `c0d1c38` | same | 1 fail: same contract via PR-only `allow_entry_surrogates` kwarg; symbol-consent tests pass |
| #115 | `bb42828` | same | all pass |

Script: line-presence check over `git diff -U0 base..head` added lines (len ≥ 6) against `git show origin/main:<file>`. Alternative-PR tests run in a detached worktree of `a04f5a2` (42 passed, 2 failed as above).

## Next executable step

Wait for push QA run 41060959610 on `a04f5a2`; record per-leg results and Windows artifacts (M-A/M-C); check release job for B1 403 (M-D).

## Owner-authorized completion continuation (2026-10-30 Pacific / October 31 UTC)

The latest owner instruction expands the stopping condition beyond essential alpha:
finish all committed requirements after essential acceptance, preserving permanent
exclusions. Earlier essential-only deferrals establish sequence, not deletion of
adopted requirements. Research proposals remain proposals unless adopted. This
section extends the original coordinator ledger above; its historical decisions
are observations, not permission to repeat a merge with new failing gates.

### Current ownership and preservation

- Canonical main: `a04f5a299a8d4afef023261e52e08d14678cf1e7` (refetched).
- Controlled integration: `f18687fd035b67961c1072af84f8c2b3442979e0`.
- Combined native/KB verification: #143, `a7f13e13ffb512f8e9621753a0ae162d78942f3b`.
- Original #126 coordinator source remains `8d958f0a1950a29c1d1cef9525a114654f4c9904`;
  its ledger is retained byte-for-byte above. Its nine commits include production
  code in callgraph, KB and rules; its docs-style title does not establish docs-only scope.
- This continuation uses isolated local worktrees and its own #144 branch,
  `codex/semantic-proof-reconciliation-20261031`. It does not overwrite #126,
  #128–#135, #140 or #143. #143 was notified in comment 6539300740.
- Local original checkout `/workspace/patchtrace` was clean on `work` at main;
  no pre-existing stashes or other local worktrees were present. Unpublished work
  on other machines remains unknown, so original author refs are preserved.
- [Content inventory](../qa/completion-inventory-20261031.json): **135 fetched
  remote branches**, each with immutable head, merge base, PR/dependencies,
  changed-path blob comparison against main and operational disposition; **100
  registry entries** with stated status/gaps and explicit unverified dimensions.
  Includes overlap map, 36 PR-head workflow snapshots and review-thread inventory.
  The new #144 is additional to that captured original PR inventory.
- 21 refs are ancestors of main; 5 have identical current content at all their
  changed paths; 109 require semantic reconciliation. These are preservation
  dispositions, not deletion authorization. A differing blob may be superseded
  by stronger current behavior and is not proof of a missing feature.

### Completion matrix and next executable actions

This table is an execution ledger, not a maturity percentage. Each row requires
implementation, GUI/CLI, meaningful tests, native acceptance, documentation and
release evidence independently. The registry inventory enumerates finer module
requirements; unreviewed dimensions are explicitly unknown. Beta.543 predates
main and supplies no current-source release acceptance for any row.

| Feature / requirement source | Implementation and GUI/CLI gaps | Tests / native acceptance | Owner, source, dependencies | Next executable action |
|---|---|---|---|---|
| Ground truth / known-answer-corpus, Tier R/W specs | R1 provenance/factory/pilot changes remain on #128; no general corpus admission from tiny authored controls | #128 QA passes, but five review threads remain open; locked held-out and full native denominators unavailable | R1 #128; GT-01/05; preserve source | Verify receipt corrections and repair still-valid publication races; run unchanged pinned native matrix |
| Ghidriff/GZF/IR / SPEC-01,31 | #143 combines native persistence, genuine identical controls, diagnostics and failure staging recovery; GUI primary route present | #143 native Windows and extraction pass; full QA still running; G-U matrix unrun | #139→#140→#141; GT-01 | Finish exact-head child jobs; dispatch native gates after CLI authentication is provisioned |
| Unified matching / SPEC-31 04 | R2 witnesses, stable native order and verified IR leftovers selectively reconciled in #144; automatic overlapping N:M groups remain limitations | 19 failures reproduced before port; 94 focused pass after; native held-out open | R2 #131; GT-02 depends final acceptance on GT-01 | Verify final combined source; retain missing group/P02-export requirements in queue |
| Multi-engine fusion / SPEC-31 05, multi-engine specs | Retain complete B+B witness/support and strongest opposition; impossible cap fails; manual groups attributed | Independent scoped review approved R2 source; synthetic regressions only | R2 #131 → #144; GT-02/03 | Exact-head Windows/Linux/native conflict and orientation acceptance |
| Semantic classification / SPEC-31 05 | R3 IR EH-unavailable and register-only blockers reconciled; S0 weak proof stays displayed | Baseline regression reproduced; focused semantic suites pass; native false-benign open | R3 #129 → #144; GT-04 | Run native EH/register/mutant controls; keep review/unknown on unsupported evidence |
| Compiler noise / SPEC-31 05 | R8 canon/2 retains suffix/radix/octal/opaque identity; added signed-L and exponent fixes; repaired sorting/display/anchor consumers | Type and consumer failures reproduced; independent review found constant/offset false anchors, now regressed | R8 #135 → #144; GT-04 | Final full suite plus native C5/C6 and A/A controls; no general equivalence claim |
| BinExport2 / SPEC-10b,49 | Existing strict acceptance/producer/worker; real exporter host/orientation path still needs acceptance | Synthetic/frozen checks do not establish native compatibility | secondary owner; GT-03; #120 | Verify pinned host/exporter and real snapshots through persisted unified/GUI route |
| BinDiff / SPEC-10,29 | Existing bounded adapter; verified licensed binary pin/oracle remains external prerequisite | Advisory job success does not prove tool actually ran | secondary owner; GT-03 | Follow bindiff-pin runbook, then record tool hash and real oriented comparison |
| rz-diff / SPEC-11,28 | Existing native adapter; R2 reports singleton orientation and empty-output dialect gaps | Scoped native passes coexist with probe failures; no universal swap accepted | R2/secondary; GT-03 | Reproduce pinned singleton/multifunction probes and fail closed on unresolved orientation |
| CVE/KB/product/build / KBC-A..H | Current CVRF parser still explicitly synthetic; R4 research not runtime implementation; servicing/provenance graph gaps | No current accepted real monthly-provider chain | R4 #130; GT-06 | Implement real documented dialect with permitted pinned captures and negative product/status controls |
| Patch search / KPS-A..E | Product/arch separation and ambiguity UI present; complete real source→pair flow unaccepted | #142 repairs synthetic corpus; 934 prior overlapping tests are not live-provider evidence | R4, GUI; #136→#142; GT-06/08 | Complete real scoped CVE/KB search and explicit pair selection with provenance |
| Acquisition / SPEC-08,34 | Existing consent/quarantine/hash/PE route; native Windows MSDelta and signer/catalog states open | Mocked transport/delta tests are not native acceptance | acquisition owner; GT-07 depends GT-06 | Measure permitted real PA30/31 input/base/output hashes and cancellation |
| Calibration / SPEC-27,39, Tier W | Runtime remains ordinal; no numeric confidence enabled. #78/#79/#82/#85 safeguards unique and unmerged | Independent lineage/locked/OOD/promotion evidence missing | R1/R5 #132; GT-05 | Reconcile persistence, A/A hard failure, pin collisions and exclusive final look before lock |
| Project lifecycle / SPEC-01,02 | Existing creation/ingestion/history; recovery/OneDrive/migration invariants need current integrated acceptance | Real Windows cancel/crash/reopen/prior-result preservation open | core/GUI; GT-09; #116/121 | Run immutable-input/history/cancel/reopen matrix on final source and package |
| GUI/workspace / SPEC-04, dockable proposal #127 | Adopted panel requirements need source-level reconciliation; #127 remains draft, not silently accepted | Offscreen Qt is automated evidence; keyboard/DPI/screen-reader human gates open | #126 GUI owner, R6 #133; GT-08 | Reconcile adopted layouts/panels, finish complete native investigation walkthrough |
| Enrichment/WIL/CVE / SPEC-07 | Existing pipeline/ranking/context; remaining committed integration/performance tasks retained after essential gate | Synthetic signal tests do not establish analyst or real provider acceptance | enrichment owner; GT-11 after essential | Execute remaining registry/todo requirements with bounded evidence and no causal promotion |
| Interpretation / provider and evidence specs | Existing cited interpretation; further committed work follows essential dependencies; R7 prototypes remain research-only | No accepted live model quality/privacy benchmark; numeric vulnerability probability excluded | R7 #134, providers; GT-11 | Verify existing exact preview/consent/citation flow, then only adopted expansion |
| Reports/exports / report-export-v2 | Existing exports; complete cross-feature provenance, partial/cancel states and released-package export open | Rule-export host marker failure reproduced separately; protection retained | core/GUI; GT-08/09 | Verify real project→export→reopen with same artifact/run/source identities |
| Security/process isolation / SECURITY, SPEC-31 G-U8 | Existing process/IO/privacy guards; OS-level no-network, descendant cleanup and Windows failure preservation need acceptance | No target binaries executed; no model commands or hidden transmission; research output TOCTOU still open | security/integrator; GT-10 | Reproduce hostile paths, child env/tree/deadline and rollback on final native OS |
| Performance/package/release / Windows and Linux specs | R2 bounded CFG correction incorporated; native large-program RSS/UI budgets, exact assets/notices/checksums and clean Windows gates open | #143 QA/packaging pending; no new accepted release | release owner, R6 #133; GT-12/13 | Finish exact-head packages and native/clean-desktop evidence; publish only per release policy |

Permanent exclusions remain: no target execution, exploit generation, autonomous
model-command execution, implicit uploads/downloads, credential persistence,
structural-match-to-CVE-causality promotion or unvalidated numeric probability.
R7 synthetic slicing, optional learned matchers and speculative corpus recipes
remain research until adopted. Existing issue #35/#36/#39 commitments must be
reconciled against current implementations after essential acceptance, not dropped.

### Source reconciliation in this continuation

- #129 production `verdict.py` and its regression retained, with proof version 2.
- #135 numeric correction retained with canon version 2, plus integration fixes:
  signed-L radix typing, complete exponent float tokens, typed-key sort/display,
  value-projected multiset subtraction for machine anchors, and field-only
  structure-offset fallback. Original R8 compiler-evidence document is copied
  unchanged; its historical native limitations remain accurate.
- #131 five production files and three dedicated regression files plus updated
  real-compute tests retained. `matching/2`, canon/2 and proof version 2 coexist.
  Original research tools/results are not claimed adopted; original source refs
  remain intact. No source research PR is closed merely because runtime files port.
- #143 already retains #139/#140/#141 and #136/#142 combined content. No component
  or source PR is accepted solely because it appears in this candidate.
- #102 source and branding/version work remain preserved; Windows PR QA is not
  disabled. Legacy calibration and proposed document branches remain preserved.

### Evidence and blocked gates

- Imported R3/R8 baseline selection: **13 failed, 31 passed** (before repair).
- Extra signed-L regression: failed on R8 proposed source, then corrected.
- Exponent C5/C6 regressions: **2 failed, 15 passed** before lexer correction.
- Real typed-literal fact/anchor consumers: **4 failed, 17 passed** before repair.
- Constant and structure-offset type-only exchange regressions each reproduced
  false `material` separately before correction; now expect `review`.
- R2 baseline selection: **19 failed, 75 passed**; ported selection **94 passed**.
- Latest reconciled R2/semantic/anchors/compute selection: **136 passed**.
  All counts overlap and must not be added. These are synthetic/recorded-input
  regression evidence, not new native accuracy measurements.
- Full baseline serial suite and full intermediate parallel suite are running.
  Repairs during an intermediate invocation disqualify it as final-head evidence;
  a final stable-source full run is required. Record actual results below.
- Entire-repository Ruff and patch hygiene passed at each repair checkpoint;
  final source still requires its own repeat and schema drift verification.
- Fresh #143 native Windows run `41167705190` and live extraction `41167705125`
  passed. Full QA `41167705216` remains in progress; Ubuntu Qt shard 2/4 passed
  at 05:06:33 UTC. Inspect every child leg and artifact before acceptance.
- Git CLI fetch and authorized push work with the supported shell network
  capability. CLI `gh auth status` reports the configured GH_TOKEN invalid;
  connected repository tools have no workflow dispatch. Owner said they will
  provision authentication; do not paste credentials into chat or borrow another
  project's identity. No native dispatch is claimed until an actual run URL exists.
- Ordinary temporary roots under `/tmp` and `/workspace` inherit sandbox-created
  read-only `.git` markers. Attempts to use the configured output mount and an
  additional `/var/tmp` root failed read-only. Keep the rule-export guard intact;
  report the affected test instead of relabelling it passing or skipping it.

### Next commands once prerequisites are available

Use the final published #144 head, not the earlier #143 head, for changed-code
acceptance. Verify dispatch head and all evaluated denominators.

```bash
gh auth status
gh workflow run unified-live-gates.yml --repo djshellshoxxx/patchtrace \
  --ref codex/semantic-proof-reconciliation-20261031 \
  --raw-field pairs=all --raw-field per_class=20
```

Do not merge or close original PRs until required exact-head acceptance and
content dispositions are established; retain refs. After a reviewed passing
merge, refetch and verify canonical main, then continue the remaining committed
registry/todo requirements and release gates.

### Independent R1 receipt-evidence repair

A separate isolated repair based on original #128 head `04bd023` preserves the
entire completed matrix in stdout's JSON error when output publication fails.
Commit `8c9eafc` on `codex/r1-receipt-publication-20261031`; original R1 source
untouched. Regression: **1 failed, 28 passed** before repair, **29 passed** after;
Ruff/diff hygiene clean; independent review approved. This addresses Qodo review
4429572900 only. Parent-replacement TOCTOU (4429572890) remains open pending a
portable directory-handle-bound writer and Windows verification. Pre-build
failures do not fabricate receipts; prior output bytes are preserved. It is not
incorporated in #144 because the broader R1 parent has separate acceptance and
review dependencies. Do not merge a passing small repair to imply parent corpus
acceptance.

### Final continuation evidence (2026-10-31 UTC)

The refreshed inventory now covers **138 remote refs / 39 PRs**, including this
continuation's three preserved repair branches. Dispositions: 21 incorporated
by ancestry, 5 with exact changed-path content, 112 retained for semantic
reconciliation. These are snapshot classifications, not permission to delete.

**Stable product source tested:** `59ff5ad1379c0a787d92f62d732686c1dd0e65b4`;
subsequent changes in this checkpoint are evidence/documentation only. Receipt:
[completion-verification-20261031.json](../qa/completion-verification-20261031.json).

| Verification | Actual result / limitation |
|---|---|
| Main baseline, full serial offscreen pytest | **18,342 passed, 1 failed, 136 skipped, 7 xfailed**, 1799.03 s |
| Reconciled source, full four-worker suite under concurrent full-suite load | **18,444 passed, 3 failed, 136 skipped, 7 xfailed**; unchanged ASM timing and 100k related-panel timing gates failed plus host Git marker |
| Those two timing gates, unchanged separate recheck | **2 passed**, 3.36 s; not represented as a new green full run |
| Reconciled source, complete suite after competing full runs finished | **18,446 passed, 1 failed, 136 skipped, 7 xfailed**, 334.80 s; both timing gates pass unchanged |
| Remaining failure on main and repaired source | `tests/test_rules_actions.py::test_the_preview_is_exactly_the_file_and_never_replaces`: sandbox's ancestor `.git`; isolated reproduction still fails. Protection/test unchanged. |
| Unified GUI, repeated five times | **285 passed**, 78.58 s; Linux offscreen only |
| Worker/GUI interpreter recheck | **94 passed**, 36.11 s; final-tree installed interpreter |
| Ruff, dependency check, schema generation, diff hygiene | pass; no generated schema drift |
| Fresh real pinned Linux backend/GZF/IR/unified smoke | **5 completed cases**: bounds `material`; signed-L, float and exponent `review`; identical `UNCH/1`. No target executed. |
| Original #143 exact-head QA | Run `41167705216`: both full suites, every repeated Qt leg, Windows frozen/portable/installer, Linux package and both Linux smoke jobs passed. PR release jobs skipped as expected. This validates #143 only. |
| #144 final-head cross-platform/native CI | Queued at snapshot; not accepted. Full G-U dispatch still awaits workflow-capable CLI authentication. |

The earlier mixed-source diagnostic run counted 18,353 passed / 8 failed and
is not acceptance: code/policy changes occurred while it ran. Result-ID mismatches
were observed, and the original editable installation also pointed at another
checkout. A separate copied interpreter installed for the final source passes
the worker/GUI recheck. All failed-node lists and log SHA-256s are retained in
the machine-readable verification receipt; no failure is silently relabelled.

Native receipt: [native-reconciliation-smoke-20261031.json](../qa/native-reconciliation-smoke-20261031.json),
with the exact executed driver beside it. Independent review rehashed **33**
source/artifact/raw/GZF items and checked stored verdicts. Explicit limits:
authored one-function cases, visible export names, no held-out/Tier R/Windows/
BinDiff/full G-U/air-gap claim. Ghidra did not retain original `L`/`f` spellings;
exponent IR content digests are equal and C6 unavailable, so its review is not a
demonstrated literal-delta detector. Backend Java version stays `unverified`;
separate configured Java 21 executable inventory is recorded without rewriting it.

Initial native setup is preserved in a separate receipt: four missing-source
setup failures plus one actual native A/A pass. The first compile retry picked
up only the source created before a cache-path error. Corrected attempt v2 wrote
all eight sources first, verified all eight successful compilations and PE files,
then ran five new complete comparisons. No setup failure was counted as native success.

### Coordinator repair and review-thread disposition

- [#146](https://github.com/djshellshoxxx/patchtrace/pull/146), head
  `798e11ef345ed7a7a65508a466eaf77ee85ef77c`, preserves #126 and fixes two
  independently reviewed rule-matrix defects: duplicate-content version/cell
  collapse, and blocking POSIX FIFO replacement before fstat. Red: 2 reproduced
  failures. Final focused suite: **157 passed** in 19.42 s; Ruff/diff clean.
  Requested version IDs, differing stored observations and ambiguous fallback
  are covered. Windows special-device race remains unverified; exact-head full
  CI is pending. An intermediate stronger fixture omitted `hits=0`; corrected
  before the final passing run, with no product validation weakened.
- R1 documentary threads `PRRT_kwDOVEPRFc6yLbej`, `...Lbev`, `...Lbew` resolved
  only after verifying committed receipt hashes/artifact fields, all five
  historical/current label-file bindings, unchanged original receipt and the
  canonical review digest in the replay. No new native run was credited for a
  persisted replay. Resolution replies are on #128; source evidence was not edited.
- R1 parent-replacement TOCTOU remains open. Evidence-loss repair #145 is still
  separate and must pass required CI/adoption before its parent thread resolves.
- No main merge, final release, source deletion, forced update, protection bypass,
  target execution or numerical-confidence promotion occurred.

Remaining work is the entire open matrix, not just release polish. Continue from
[the exact handoff](../handoff/autonomous-continuation-20261031.md), refetch heads,
finish required gates and integrate accepted repairs before the remaining
committed dependencies and optional-research adoption decisions.

Synthetic ladder/ingest benchmark at the same product source completed and its
report validates (`counts_sha256` starts `47911197`). 10k ladder 0.87 s; 60k
ladder 5.54 s / total sides+ladder 7.47 s / 507 MiB peak; 60k ingest 82.56 s /
63 MiB peak. All applicable unchanged gates pass. Facts/read-model/UI costs remain
explicitly pending; this is not real-program/native end-to-end G-U5 acceptance.
See `docs/qa/reconciliation-bench-20261031.json` and the verification receipt.


## November 1, 2026 execution checkpoint

### Read-only branch and requirement reconciliation — November 1 UTC

Canonical main remains `a04f5a299a8d4afef023261e52e08d14678cf1e7` in the full fetched checkout. The refreshed inventory covers **139 actual origin branch heads, 41 currently open PRs and all 100 prior registry rows**. It reuses 136 unchanged immutable-head records and recomputes only #144's evidence checkpoint and the new #147/#148 branches. It excludes symbolic `origin/HEAD`; the old inventory mistakenly represented that alias as a branch named `origin`.

Correct current classifications are **20 ancestors of main, 5 exact changed-path content equivalents, 114 preserved for semantic reconciliation**. This changes the historical 21-ancestor count by correcting the alias, without removing any author branch. Differing blobs do not establish missing behavior, and content equality does not establish acceptance. No PR is marked superseded, closed, merged or DONE by this reconciliation. Original ownership and unpublished activity remain unknown.

Evidence: `completion-inventory-20261101.json` contains every full head, changed-path evidence, PR association, source/reuse provenance and all 100 retained requirement rows; `branch-dispositions-20261101.md` is the compact complete branch table. Current connector PR metadata is saved separately. PR #137's six exact-head gate batches and four development plans were preserved and read; their October 30 check conclusions are historical and are not current acceptance evidence. Root's integration/check review supplies current exact-head gate conclusions.

**Adoption correction:** owner decision 12 in `docs/plans/owner-decisions-20261015.md` retains qbindiff, radiff2 and Diaphora for **v2**. All five corresponding registry rows are explicitly `adopted-v2-owner-decision-12`; stale draft labels or earlier drop recommendations cannot remove them. This retains scope rather than endorsing duplicate matching/persistence paths: remaining work must reconcile D-24/D-25/D-26 and existing unified/representation seams before contract changes. R7 prototypes and genuinely unadopted proposals remain separate from these adopted commitments.

Prioritized bounded independent work, available for coordinator reservation after confirming original-owner activity:

| Priority / accepted requirement | Bounded next task | Evidence / dependency and completion limit |
|---|---|---|
| P0 — GT-03 / SPEC-11 orientation | Reproduce #131's preserved rz-diff 0.9.1 singleton and ordinary-side captures through the current adapter; specify conservative orientation handling and add red regressions before any source change. Preserve raw output and ambiguous states. | `07-native-rizin-findings.md` records conditional reversal; `rzdiff.py` still labels `original` as older. Never globally swap fields or accept empty stdout. Coordinate original #131/#39/#120 owners. Native Linux/Windows and fixture-analysis denominators remain separate. |
| P1 — GT-12 / SPEC-31 L-35 | Extend isolated benchmark stages to facts for 5,000 changed pairs, read model at 10k/100k and exact Qt `data()` calls for paint/sort/filter. Keep prior ladder/ingest receipts intact. | `tools/unified/bench.py` still lists all three as `PENDING`; #144's receipt explicitly leaves them unmeasured. Own benchmark/tests only, no retuning thresholds or production timing gates. Windows and real-program G-U5 remain open. |
| P1 — GT-05 / legacy calibration safeguards | Reconcile #78/#79/#82/#85 against the integrated candidate with per-safeguard red/green evidence; port only demonstrably missing persistence, A/A hard-failure, recipe-collision or final-look guards. | Existing source branches and historical gate batches retained. Do not assume every differing file is missing behavior. Avoid the active receipt worker's research_build/research_pilot/helper surface. No held-out data access, locked-run rewrite or numeric confidence promotion. |
| P2 / adopted v2 — RD-F03 | Implement the bounded insertion-aware raw-offset alignment slice through the existing representations seam after a small spec-first contract amendment. | Current `representations/compare.py` compares equal logical offsets only. Test shift, repeated blocks/ambiguity, bounds and cancellation; retain original offsets and exact bytes. This is a real retained v2 gap, independent of an external radiff2 adapter decision. GUI adoption and native budgets are separate. |
| P2 / adopted v2 — SPEC-DA-01 | Prepare version-pinned export-DB schema/capability acceptance and bounded immutable fixture tests, then implement the missing export reader/context slice only against validated upstream schema. | Current `diaphora/` has Mode-A result import, no `export_import.py`/`context.py`. Real 3.4.3 fixture compatibility and licensing must remain explicit blockers; synthetic SQLite cannot establish native compatibility. Keep additive Diaphora kinds and old-reader behavior. |
| P2 / adopted v2 — SPEC-QB-01/02 | Produce a requirement-to-current-ladder acceptance map, identify residual unmet safeguards and propose one bounded slice through SPEC-31. | Owner decision 12 adopts v2 while D-25 rejects a duplicate matching path. Resolve this as an interface/scope reconciliation; do not silently delete the requirement or create a second matcher. |

Active reservations remain untouched: investigation cancellation/import transaction; research receipt publication helpers; frozen offline journey self-test; integration, native-smoke assert repair and publication. No tracked source or another worktree was edited by this audit.

**Broad completion remains unverified.** The 100 registry rows are preserved source assertions, not a fresh exhaustive implementation/GUI/native audit. Corpus truth/held-out denominators, live vendors/MSDelta, tool licensing/orientation, native G-U gates, clean Windows/recovery/accessibility, packages and release acceptance remain independently open where no exact evidence covers them. Continue all adopted requirements after essential acceptance; never infer project completion from a green subset or planning percentages.


### Issue audit continuation and next reserved repair

Full bodies and all reported comments for issues #105/#116/#118/#120/#121 are saved. `issue-dispositions-20261101.md` records source-backed per-finding dispositions, current reservations and evidence limits. All 41 original PRs have current review/thread/status/run collections saved; 79 available run first pages yielded 566 child-job summaries. Eight of #128's ten inline threads are resolved, two remain open; no resolution or closure was performed. Pagination/check-runs limitations are explicit.

Four issue #120 boundaries were directly reproduced on integrated source `f8b2bbb`: 1:1 ambiguous manual correction becomes matched/mapped; manual id/name changes collide in result identity; normalized secondary content changes collide in result identity; inconsistent engine/source/anchor alternatives are accepted. Their exact synthetic driver and source-hashed receipt are retained. Coordinator assigned isolated identity repair on `codex/unified-evidence-identity-20261101`; root will review and accept independently. Backup-byte and Diaphora query-deadline work are separately reserved. Finite KB scope/card provenance and remaining GUI/security/native gates remain open where not reproduced or accepted.


### Current executable dispositions (supersedes stale pending statements above)

| Requirement / source | State and owner/files | Current evidence / dependencies | Next executable acceptance action |
|---|---|---|---|
| Project-owned report exports / architecture, issue #116 | READY_FOR_REVIEW; isolated #149, reports/persistence/service/UI | Reproduced old GUI write path; 35 focused + 74 independent cases; source tree `4da0e0b`; exact-head CI running | Inspect full Linux/Windows/Qt/package jobs and review threads; merge only this independent slice after qualification |
| Pending-create cancellation / 31-F | READY_FOR_REVIEW; investigation controller/service, local `38c2b0d` selected into candidate | 4 original failures; 178 related cases pass; independent real Qt/service review | Run final combined CI and frozen journey; preserve already-committed paths |
| GUI-owned KB candidate panel / 31-F, #116 | READY_FOR_REVIEW; capture adapter and shared engine conversion | Lock reopening and strict-JSON defects reproduced; populated context/freshness parity passes | Final combined repeated Qt and frozen package journey |
| Constructed frozen KB journey / 31-F F8 | READY_FOR_REVIEW; gui/qt/kb_selftest, frozen_smoke | Source journey and 2x scale passed; relocation retained unchanged architecture gate (initial 2 gate failures preserved) | Actual final-head Windows ZIP/installer self-test; retain human visual/accessibility and live-tool gates separately |
| Receipt parent replacement / known-answer-corpus, #128/#145 | READY_FOR_REVIEW; #150 stacked on #145, receipt helper/build/pilot | Baseline 5 failures; 73 Linux passes and 14 Windows-only skips; independent review corrected descriptor/share-mask flaws | Execute all 14 Windows controls, inspect exact-head full suite; do not qualify unaccepted parent from child checks |
| Backup cached trust / SPEC-07h, #121 | READY_FOR_REVIEW; independent #151, verified_backup | 3 failures reproduced; fresh bytes checked before trust and publication; root 41 cases, reviewer 24 | Exact-head Windows/Linux QA; retain linear-I/O tradeoff, no arbitrary-writer locking claim |
| Diaphora row deadline / SPEC-DA-01, #121 | READY_FOR_REVIEW; independent #151, sqlite_guard | 3 failures reproduced; 65 tests, independent concurrent iterator check | Exact-head QA; independent per-query budget, whole-import memory cap still READY |
| Manual/secondary identity and ambiguity / #120 | IN_PROGRESS; identity worker, unified source refs/secondary contracts | Four reproduced defects and 24 initial failing regressions; original witness/source data preserved | Independently review complete result-key inputs and strict alternatives; regenerate schemas if changed; run combined gates |
| Sonar #144 acceptance driver | READY_FOR_REVIEW; explicit guards in recorded native driver | Assertions vanished under -O; all five replacement guards independently verified at optimize 0/1 | New-head Sonar; re-run native authored controls with exact pinned runtime |
| Sonar #147 CLI output findings | BLOCKED_EXTERNAL for detailed finding flow; source triage recorded | Two annotations visible; public Sonar detailed issue API 403; source boundary violation not demonstrated | Obtain detailed flow or concrete authority-boundary reproduction; no suppression or arbitrary CLI restriction |
| GT-01 full G-U1–G-U8 Windows/Linux matrix | BLOCKED_EXTERNAL for workflow dispatch; local preparation READY | Fresh dispatch attempt returned HTTP 401; connector exposes no dispatch; no trigger bypass | Run available local pinned smoke, retain exact scoped counts; authenticated unchanged workflow dispatch remains prerequisite for full cross-OS matrix |
| GT-02/03 rz-diff orientation and real BinDiff | READY / BLOCKED_EXTERNAL only for unavailable licensed binary | R2 conditional-orientation captures retained; no global field swap adopted | Reproduce pinned singleton/empty/ordinary outputs; validate hashes/orientation and persisted fusion; acquire only already-authorized compatible tools |
| GT-04 semantic acceptance | READY, depends on GT-01 evaluated corpus | Typed literals/machine anchors/uncertainty candidate retained; constructed tests not independent truth | Native false-benign/mutant/noise controls, truthful abstention and class denominators |
| GT-05 corpus/calibration | READY for safeguards; HUMAN_ONLY only for owner-local Tier W execution | #78/#79/#82/#85 research preserved; C9 conditional lock and Tier R budget already approved | Reconcile missing safeguards and pre-lock audit; no repeated final evaluation; keep confidence ordinal |
| GT-06 real MSRC/CSAF and acquisition chain | READY; adapter/source owners unassigned | Current CVRF remains synthetic; no live chain acceptance inferred | Implement adopted official dialect with permitted pinned captures and conservative product/status/revision/provenance tests |
| GT-07 Windows MSDelta/signatures | READY prep; BLOCKED_EXTERNAL when native host/tool access absent | No PA30/PA31 acceptance from mocks/source self-test | Permitted native base/input/output hash, signature/catalog, cancellation/quarantine tests |
| GT-08/09 project lifecycle/reporting | READY; core/GUI owners | Narrow repairs above do not cover crash/migration/disk-full/late failure/profile-switch matrix | Continue actual remaining #116/#118 issues and recovery/backup/lock/error acceptance |
| GT-10 isolation and resource bounds | READY; core/security owner | Audit still finds environment inheritance default, preparation deadlines and resource caps gaps | Reproduce each actual boundary; OS denied-egress/descendant cleanup on authorized hosts; never execute compared targets |
| GT-11 enrichment/provider/help | READY after essential dependencies | Explicit consent/citation/privacy rules retained; no live model-quality claim | Complete adopted registry/todo requirements and exact preview/provider tests with configured tools |
| GT-12 performance | READY; stable-host measurement only | Existing timing budgets unchanged; facts/read-model/Qt stages remain unmeasured | Extend benchmark for 5k facts, 10k/100k rows and UI data calls; no repeated lucky-pass acceptance |
| GT-13 packaging | IN_PROGRESS through existing PR workflows | #148 packages exist but do not qualify the new combined candidate | Build Windows on Windows; verify identity/notices/checksums/portable/installer and Linux packages at final head |
| GT-14 adopted v2 | READY after dependencies | Owner decision 12 retains five QB/RD/Diaphora registry rows | Map onto existing engines, then bounded alignment/export-reader slices; do not silently drop adopted v2 |
| Final public release and genuine desktop/accessibility sign-off | HUMAN_ONLY | Final release not authorized; human usability evidence not replaced by offscreen checks | Provide qualified candidate artifacts and exact owner checklist only after available engineering work |

This remains a restartable engineering checkpoint, not a claim that all agent work or the full project is complete. Main merge status and later exact-head results must be appended in the final handoff; the initial 139-branch inventory predates this run's new branches/PRs.


### Post-merge/source checkpoint — November 1

This entry supersedes earlier pending states only for the named slices. **#149 is DONE**, merged as `6579ed83211b7ff2039e3152728ac1cddc3e93d6` after full Linux/Windows, repeated Qt, native, Sonar, CodeRabbit and package/smoke gates. Tested and merged trees equal `4da0e0b`. Downloaded package checksums are in the dated handoff and QA records. Broader issue #116 remains open.

#150 now has **14/14 native Windows parent/junction/writer/device controls passing**, verified in downloaded JUnit, plus full QA/Qt/package checks. Sonar and parent acceptance remain open. #151 and #153 incorporate current main at `1e7eeff` / `cf6620f`; fresh exact-head checks are pending, with 48 / 379 coordinator checks passing. Independent #154 at `4aa99f7` binds recorded protocol identity before corpus access: 102 independent and 112 main-port checks passed. No final evaluation or numerical promotion occurred.

Combined code checkpoint `57d223d` includes reviewed identity, MSRC, rz-diff quarantine, GT12 and preregistration repairs. Its 428 bounded checks, Ruff, pip and schema checks passed. Later `64534b1` adds independently reviewed RD-F03 backend alignment; its page metadata finding is fixed, with UI/navigation/native performance still READY. Main-only identity repair is reviewed separately before publication after 28 meaningful baseline failures.

A separate full run at `f005c66` has two failure markers awaiting final traces; it does not cover later rz-diff, preregistration or alignment changes. Do not call it a clean full pass or qualify later source from it.

GT12 synthetic first-attempt measurements are verified: 5k facts 3.995 s; 10k/100k read model 0.947/9.330 s (informational); 100k UI paint/sort/filter 14.84/299.84/45.04 ms. All operations used 504 data calls at both sizes. Sort misses the raw 150 ms target but passes the unchanged 750 ms CI allowance. Possible brief overlap with a short test is recorded; no favorable retry. Windows/native/full G-U5 remain READY.

The rz-diff defensive repair is READY_FOR_REVIEW on combined source. Active associative consumers abstain and old unified cache identities change. The unchanged live workflow remains blocked/nonzero. A verified same-version witness remains READY research, not automatically external or human-only. GT05 normalized output persistence is IN_PROGRESS with attention schema compatibility under review.

All other accepted workstreams and retained v2 requirements remain open in the existing matrix. The dated handoff gives current refs, evidence, owners, unfinished agent work and precise access/human boundaries.

## Coordination checkpoint — 2026-11-01 14:32 UTC

This section supersedes status statements in the historical checkpoints below. Canonical main remains **6579ed83211b7ff2039e3152728ac1cddc3e93d6**; only independently qualified **#149** has merged. Original refs and research remain preserved. The current combined source is **78722316df82bd606402c9c8af3db87ab11a3e53** (tree **f53a3ccd11d2f36abcce529ddf2e4a4043220c85**); this evidence checkpoint follows it without further production changes. The published #152 PR pins the API-generated commit and verifies exact tree equality. Its preceding remote head was `953c0e9a8d0c01b475614928a0cd568c0577bb9c`.

| Requirement / slice | Disposition at this checkpoint | Evidence and next executable action |
|---|---|---|
| #149 export protection | DONE / merged | Exact main tree equals accepted source. Downloaded package checksums below apply only to this narrower merged slice. |
| #150 receipt parent replacement | READY_FOR_REVIEW / draft stacked on #145/#128 | Fourteen native Windows controls and full Linux/Windows/Qt passed; seven Sonar path findings and parent acceptance remain unresolved. No acceptance of a parent from a child result. |
| #151 storage integrity | READY_FOR_REVIEW, remote `ad63416348c122ade8419b11686164be09bb2af3` | Fresh collision defect reproduced with 2 failures; exclusive unique stage/non-replacing publication preserves prior backup and pending files. Independent and root selections each passed 39 tests. Fresh Sonar/review passed; full native/QA/Qt/package checks still running. |
| #153 real MSRC JSON | IN_PROGRESS, remote `141f8176d4dbcebe23dada481a4fe8660a332dcb` | Offline XML namespace discovery preserves 394 scalar facts, 2,684 XML memberships and 31,645 edges in the same captured-source review. Current Sonar passed. Missing-date pointer and singleton revision-warning review findings are under source review; no merge before disposition. Broader status/servicing/XML contracts remain open. |
| #154 recorded protocol identity | READY_FOR_REVIEW, remote `f27d23a80ee49573ccca54cdf036427f57eebb2a` | Visible complete digest cells, comment/code boundaries and escaped opening backticks repaired. Final combined repair independently passed 138 checks; root central selection passed 138. Earlier partial approval withdrawn. Fresh exact-head CI pending; no real corpus/final evaluation consumed. |
| #156 unified evidence identity | READY_FOR_REVIEW, remote `4eebea4a5389af16bffe32a2bf9285c406d95fb1` | Refacts uses active cancellation/deadline Budget; captured identity hashing resolves in the task worker before exact-key owner DB lookup/publication. Independent review approved; root central 159 and main-port 79 checks passed (overlapping). Existing capture I/O is not claimed eliminated. Fresh exact-head CI pending. |
| #157 normalized output replay | READY_FOR_REVIEW, remote `aff72cddc902f31a2cf44dea9c48797edabc1c30` | Actual ranking TypeError, encode-before-validation and valid failed-file adoption reproduced and repaired. Managed runs require successful report credit plus exact bytes/ownership; failed artifacts remain uncredited. Legacy loading explicitly warns or can be refused. Author 237 / independent 119 passes with native-tool skips. Integrated here; fresh CI and verified transfer remain open. |
| GT08 frozen F8 architecture | Implemented/reviewed/integrated; READY_FOR_REVIEW on combined source | One normal app event loop and owned timer continuations replace seven forbidden manual pumps; cleanup/failure/timeout controls retained. Root 31 focused checks passed. Actual combined Windows frozen/package gate remains required. |
| GT02/04 Rizin 0.9.1 | BLOCKED_EXTERNAL for debugger witness; independent research READY | Thirteen original pinned native controls reproduce conditional reversal and input refusals. Root rehashed archive, 675 runtime resources and 26 streams, replayed six ORIENTATION/two INPUT refusals. Host ptrace denied before inferior start; no bypass. Separate-core observations cannot prove same-run all-function state. Quarantine remains. |
| GT05 native LLVM controls | Scoped native build evidence complete; broader acceptance open | Verified private LLVM 18.1.3 dependencies; two real authored build/mutation/manifest/annotation controls passed in 4.69 s. No engine evaluation or independent corpus truth claimed. |
| RD-F03 | Backend integrated; UI IN_PROGRESS | Reviewed opt-in physical-window UI passed 182 author / 72 independent checks, but root preview found a clipped status label. Author is repairing layout before adoption. Original application-quit test-order failures and subprocess-isolation fix retained. No UI/native/human acceptance claimed. |
| GT04 BinExport/BinDiff | IN_PROGRESS, receipt_fix owns heavy native slot | Official pinned BinExport source built against approved Ghidra 12.0.4 + Java 21; original pinned BinDiff 8 retained. Bounded authored pair route underway. No new native acceptance claimed here; trust and orientation evidence must remain explicit. |
| GT05 verified shard transfer | IN_PROGRESS, corpus_safeguards | Fixed paths and completed report-bound credits, exact labels/output hashes, plan/shard/case ownership, successful-only transfer; no glob adoption, binary/scratch or Tier W upload. Independent review pending. |
| #105/#116/#118/#120/#121 reconciliation | IN_PROGRESS, ledger_inventory | Fresh source/comment audit; no closure from ancestry or partial fix. Every unresolved finding requires evidence/disposition. |

On this exact combined source, output/preregistration/training regression selection: **216 passed, 1 skipped, 14 warnings in 27.55 s**. The native skip is from LLVM tools absent from this command's PATH; separate native controls used verified private tools. Whole-tree Ruff, pip check, general/corpus schema regeneration and KBC check passed with zero drift. Earlier root 326, identity 159, preregistration 138 and F8 31 selections overlap; never sum them. See [machine receipt](../qa/integration-checkpoint2-20261101.json), compressed original logs and the named source/review receipts.

The original required full suite on `f005c6674e0d7e7e151668494bb9c5a299f2635b` remains **18,702 passed, 3 failed, 138 skipped, 7 xfailed**. Its two source failures are now independently repaired (F8 event-loop architecture and refused-source identity/provenance assertion); AF_UNIX remains host-denied. There is **no new full-suite claim** for this later source. Preserve that original JUnit/log archive and vanished temporary-manifest limitation. Reserve a stable isolated serial full run after current reviewed integrations and the heavy native slot is free.

The refreshed complete remote inventory records **148 branches and 48 open PRs**. Original 139 refs remain accounted for; semantic reconciliation of remaining unique work is unfinished. Closed/unmerged bot PR **#155**, head `15370a0bf690ea65f49d1f6cc67c40f73fd3d77c`, is preserved; its intended cases are superseded by the stronger #154 repair, and its prefix-comment false acceptance is explicitly rejected. Original #143–148 refs are untouched.

Active isolated owners: receipt_fix GT04 native harness; corpus_safeguards transfer and narrowly scoped corpus workflow artifact payload; frozen_journey RD UI geometry; cancel_fix GT06 source review; ledger_inventory issue audit; ci_review independent review/CI observation. Root alone owns combined integration, ledger and publication. No unobserved original owner's activity is inferred from age. Current owned worktrees and refs are preserved.

Access boundaries remain exact: authenticated unified-live workflow dispatch is unavailable (401); detailed Sonar issue endpoint returned 403; host denies AF_UNIX and ptrace; existing Windows PR workflows are available. Do not classify all native/Windows work human-only. C9 lock and Tier R budget already have conditional owner approval; verify prerequisites, do not re-ask. Owner-local Tier W data and actual human screen-reader/visual/owner-machine sign-off remain HUMAN_ONLY. The original package checksums below remain valid for #149, not this combined candidate. No final release, signing identity, gate weakening or target execution.
