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
