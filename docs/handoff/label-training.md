# Handoff: label training (Tier R to a preregistered result, then Tier W)

Written 2026-10-15 for an engineer or Claude session with no chat history. Snapshot: integration branch `origin/claude/instance-d-gui` at `b853996` (PR #64, draft), `origin/main` at `00db4c9`, LBL-15 at `origin/claude/instance-c-research` `785998a`/`393d09b` (PR #66, draft, based on main). Everything below was checked in the tree at that snapshot unless marked UNVERIFIED (register in Appendix E, 14 entries). Re-check the default-branch SHA and open PRs before starting (CLAUDE.md): `gh api repos/<owner>/<repo>/pulls` (`gh pr list` and `gh pr view` use GraphQL, which the sandbox blocks).

Companion files: `docs/handoff/label-training-glossary.md` (plain-language terms) and the new spec `docs/specs/program-e/LBL-DATA-integration-plan.md` (data path, corpus-growth admission, pre-lock checklist; slices LBL-30..LBL-34, proposed).

## 1. Purpose and current state

Purpose: produce one reproducible, leak-free, preregistered Tier R result: the pipeline (grouped nested CV, Learn-then-Test threshold, calibration gates) recovers known answers on test builds of open-source C (gate G1), and engines and lead-list variants differ measurably on those builds, or the report says plainly that they do not. Nothing here licenses a percent for Windows files (`TIER_R_CLAIM`). Tier W (real Windows binaries, owner machine only) is the only route to any display level above "order only"; its tooling is mostly unbuilt.

Current state in one paragraph: the corpus factory, evaluation core, mutation operators (25 source operators plus IR and opt layers), channel packs, MSVC profile, CI summary, preregistration tools and the LBL-26 audit fixes are on the integration branch. The training driver (`train.py`, `shift.py`) exists only in PR #66 and merges cleanly into the integration branch (tree `30c0e6d`, 83 train and audit tests pass there). No code writes the engine outputs or feature rows that `train.py` reads from real runs, so the pipeline has only ever run on synthetic worlds. No runner has built the 16 recipes in one run (R1 not done). The preregistration is a draft; no lock exists.

Commands that prove the state (run from the repository root of the integration branch; `export PYTHONPATH=src QT_QPA_PLATFORM=offscreen`):

| claim | command | observed 2026-10-15 |
|---|---|---|
| calibration test set passes except 3 known reds | `python -m pytest -q -p no:cacheprovider tests/test_calib_channels_*.py tests/test_calibration_cv.py tests/test_calibration_math.py tests/test_calibration_metrics.py tests/test_calibration_runtime.py tests/test_calibration_scope.py tests/test_calibration_tools.py tests/test_ci_summary.py tests/test_corpus_cards_audit.py tests/test_evalcore_engines.py tests/test_evalcore_report.py tests/test_evalcore_scoring.py tests/test_evalcore_synergy.py tests/test_lbl26_audit_fixes.py tests/test_mutations_*.py tests/test_prereg_*.py tests/test_tier_r_catalogue.py tests/test_tier_r_contracts.py tests/test_tier_r_shard.py tests/test_tier_r_msvc.py tests/test_tier_r_tranche.py tests/test_tier_r_eval_report.py tests/test_tier_r_eval_cli.py tests/test_tier_r_eval_corpus.py tests/test_tier_r_vendoring_cli.py` | 815 passed, 3 failed, 4 skipped, 3 xfailed (33 s). Reds: `test_ci_summary.py::test_artifacts_hold_only_labels_and_reports`, `test_tier_r_shard.py::test_workflow_structure_and_pins` (both assert the workflow job and artifact list and trip over the new `msvc-advisory` job), `test_tier_r_eval_cli.py::test_evaluate_with_imports_scores_and_exits_0` (red on the audit's base commit too; cause not diagnosed, UNVERIFIED U-4). `hypothesis` is not installed in the sandbox, so `tests/test_calibration_hardening.py` and `tests/test_evalcore_stats.py` could not be collected there; run them where it is installed |
| catalogue is consistent | `python -m tools.calibration.tier_r catalogue-check` | `{"cards": 50, "recipes": 16, "problems": [], "status": "ok"}` |
| toolchains on this host | `python -m tools.calibration.tier_r toolchain` | `mingw-gcc`, `mingw-clang`, `msvc-free` ready; `msvc` only on a Windows host; rz-diff BLOCKED (not installed) |
| LBL-15 is not on the integration branch | `git merge-base --is-ancestor 785998a HEAD; echo $?` | 1 (not an ancestor) |
| LBL-15 merges cleanly | `git merge-tree --write-tree --name-only HEAD origin/claude/instance-c-research` | prints one tree id, no conflicts. Extract with `git archive <tree> | tar -x -C <empty dir>` and run `python -m pytest -q -p no:cacheprovider tests/test_train_helpers.py tests/test_train_pipeline.py tests/test_train_report.py tests/test_train_shift.py tests/test_lbl26_audit_fixes.py` there: 83 passed |
| train driver reads files nobody writes | `grep -rn "tier-r-engine-output\|tier-r-feature-rows" tools --include=*.py` | only `train.py`, `schemas.py`, `report_schemas.py`; `tier_r/evaluate.py:engine_output_doc` builds the dict but only its SHA is kept (item T-04) |
| no lock exists | `python -m tools.calibration.prereg --qa docs/qa.md` | exit 2, "no recorded SHA ... for C9-PREREG-v1" |
| lineage count and roles today | `python <script that applies assign_roles to recipe and suite lineage ids>` (see item T-09 step 1) | 41 lineages (16 recipes + 25 suite dirs including `_template`): 24 dev, 11 locked-test, 6 shift-test. 11 < 12 needed for a locked profile |
| Tier W CLI missing | `PATCHTRACE_CALIB_ROOT=<dir> python -m tools.calibration.tier_w.run_local --corpus-id tier-w-x --dry-run` lists stages and exits 0; a real run exits 3 because `tools.calibration.tier_w.__main__` and `.cli` do not exist (`run_local.py:128`) | as stated |

Branches by name (in-flight work):
- `origin/claude/instance-d-gui` (PR #64, draft, base main): integration branch. Contains LBL-02/03/04 (recipes libdeflate, stb, c-ares), LBL-05 audit (test only), LBL-06 (nine added operators), LBL-07 (IR and opt layers), LBL-08 (MSVC profile and advisory job), LBL-11a/b/c (evalcore), LBL-13 (channel packs), LBL-14 (CI summary, nightly), LBL-prereg (P-1, P-2, vendoring scan), LBL-26 audit fixes (`4ced7b2`), unified gates S6c.
- `origin/claude/instance-c-research` (PR #66, draft, base main): LBL-15 (`tools/calibration/{train,shift}.py`, `report.py` additions, 4 test files, 2 schemas).
- `origin/chatgpt/corpus-1` (PR #68, draft, base d-gui): 24 candidate recipe files under `tools/calibration/catalogue/*-candidate.json` plus `docs/plans/chatgpt-corpus-1-continuation.md`. All 24 have `source_pin.commit = null`; none is admitted (audit `docs/audits/20261015-corpus-candidates-verified.md`: VERIFIED 0, NEEDS-OWNER 24). 20 are C; jsoncpp, pugixml, snappy, tinyxml2 are C++ (blocked, the factory is C only).
- `origin/chatgpt/unified-fixtures-1` (PR #71), `chatgpt/kb-fixtures-1` (#69), `chatgpt/panels-1` (#72), `chatgpt/help-docs-1` (#70), `chatgpt/deferred-audit-fixes-1` (#67): not label training.
- `origin/claude/instance-b-features` (`6e1e153`): no change under `tools/calibration` relative to main (checked with `git diff --stat origin/main origin/claude/instance-b-features -- tools/calibration`).
- `origin/main` `00db4c9`: has the original workflow (no nightly, no determinism step, no `msvc-advisory`), 13 recipes' worth of foundation (#51, #55), no LBL-15.

Owner decisions already given (`docs/plans/owner-decisions-20261015.md`): grow the corpus (ChatGPT prompt 2 plus worker verification of every SHA and licence); lock the preregistration YES after the pre-lock audit (LBL-26, now done, see T-03); compute budget of 150-250 runner-hours YES; Tier W runs are done by the owner with `docs/runbooks/tier-w-local-run.md`.

## 2. What is DONE

| item | where | evidence |
|---|---|---|
| Contracts for corpus, labels, report | `tools/calibration/tier_r/{contracts,schemas,report_schemas}.py`, `docs/schemas/corpus/**` | `tests/test_tier_r_contracts.py`, `tests/test_tier_r_lbl00.py` (schema drift) |
| Factory: fetch, build, label, A/A, noise, CLI | `tools/calibration/tier_r/{fetch,build,factory,labeler,csrc,debuginfo,pe,toolchain,cli}.py` | `tests/test_tier_r_factory.py`, `tests/test_tier_r_csrc.py`; `docs/qa.md` zlib card and libdeflate/stb/c-ares rows |
| 16 recipes, 50 release/CVE cards | `tools/calibration/tier_r/catalogue/{recipes.json,releases.json,cves.json,recipes.d,releases.d}` | `python -m tools.calibration.tier_r catalogue-check`; `tests/test_tier_r_catalogue.py`, `tests/test_tier_r_tranche.py`, `tests/test_corpus_cards_audit.py` (103 pass, 3 strict xfail) |
| 25 authored suites | `corpus/ours/*/*/suite.json` | `python tools/corpus_check.py all` |
| 25 mutation operators, IR and opt layers | `tools/calibration/mutations/{operators,ops_more,registry,ir,opt_transforms,labels,coverage}.py` | `tests/test_mutations_*.py` (hand-computed goldens; real clang/opt 18.1.3 tests assert BLOCKED when absent) |
| MSVC `cl` profile (code only) | `tools/calibration/tier_r/msvc.py`, `toolchain.py`, workflow job `msvc-advisory` | `tests/test_tier_r_msvc.py` with fake `cl`/`link`; no real `cl` build yet |
| Manifest, annotation, lineage roles | `tier_r/{manifest,annotate}.py`, `lineage.py`, `guards.py` | `tests/test_calibration_hardening.py`, `tests/test_lbl26_audit_fixes.py` |
| Evaluation core | `tools/calibration/evalcore/**`, `tier_r/evaluate.py` | `tests/test_evalcore_*.py` (synergy-1 numbers are hand-computed in LBL plan s5) |
| Channel packs (synthetic inputs) | `tools/calibration/channels/{strings,capabilities,environment,rules,leadlist}.py` | `tests/test_calib_channels_*.py` |
| Calibration math and gates | `tools/calibration/{cv,threshold,ece_null,metrics,gates,fit,ood_fit,stats,bootstrap,ablation,baselines}.py` | `tests/test_calibration_*.py`, `tests/test_prereg_constants.py` (P-2: constants equal the prereg table) |
| Sharded CI, never-silent summary, nightly | `.github/workflows/corpus-tier-r.yml`, `tier_r/shard.py`, `ci_summary.py` | `tests/test_tier_r_shard.py`, `tests/test_ci_summary.py`; two `workflow_dispatch` runs on main completed green (ids 38675568102, 38675570414; their inputs UNVERIFIED U-1) |
| Preregistration tooling | `tools/calibration/prereg.py`, `vendoring_scan.py`, `tier_r/bodyrecord.py`, `tier_r vendoring` verb | `tests/test_prereg_tools.py`, `tests/test_tier_r_bodyrecord.py`, `tests/test_tier_r_vendoring_cli.py` |
| Pre-lock audit LBL-26 (harness) | `docs/audits/20261015-lbl26-pre-lock-audit.md` (on d-gui), fixes `4ced7b2` | 21 tests in `tests/test_lbl26_audit_fixes.py`; 2 High, 4 Medium fixed; 12 deferred (D-01..D-12) and 8 "for C" items (C-1..C-8) still open (T-03) |
| Honest-scope runtime | `src/patchtrace/calibration/{scope,ledger,artifact,policy,context}.py` | `tests/test_calibration_scope.py`, `tests/test_calibration_runtime.py`; no ledger file ships, so status is "untested" |
| Training driver, shift ladder, Tier R report | PR #66 only: `tools/calibration/{train,shift}.py`, `report.py` (`TIER_R_CLAIM`, `verify_tier_r_report`) | 124 passed on the main-based tree; 83 on the merge with d-gui |
| Tier W precursor | `tools/calibration/tier_w/{catalogue,pairs,guard,msf,pe_tables,run_local,make_fixtures}.py`, runbook | `tests/test_tier_w_corpus.py`; stages fetch, symbols, labels, run, evaluate do not exist |

## 3. What REMAINS (ordered checklist)

Reading order and dependencies: T-01, T-02 first; T-03 and T-04 can run in parallel (different files); T-06 (R1) needs T-01; corpus growth (T-08, T-09, T-10) runs beside the code items; R5 needs T-03 and T-04; the lock needs everything before it. One worker at a time on `tools/calibration/` files that overlap (`tier_r/shard.py`, `tier_r/cli.py`, `tier_r/evaluate.py`, `train.py`).

End-to-end sequence from today to the final preregistered result (each step names its item):
1. T-01 fix three red tests. 2. T-02 merge PR #66 into the integration branch. 3. T-06 R1 diagnostic dispatches; read them; fix the first failing recipe (T-09 step 8). 4. In parallel: T-03 (train.py audit wiring), T-04 (data path), T-05 (decision), T-07 (planner), T-08 (licence rows), T-10 (card audit rest). 5. T-09 corpus growth tranches, each verified by a real build. 6. T-11 mutation follow-ups, T-12 MSVC run. 7. T-14 vendoring scan, shift declaration, stratified sample list, manual noise sample. 8. T-15 R2 and R3 dispatches (mutation farm, Ghidriff leg). 9. T-16 R5 dev training run on throwaway prereg SHA, read the report, run the determinism re-run. 10. Owner decisions (section 4). 11. T-17 lock commit, P-1 verify, qa.md row, sign-off. 12. T-18 R6 final run once, R7 determinism. 13. T-19 and T-20 after the Tier R result.

---

### T-01 Fix three red tests
- Goal: calibration suite fully green so CI signals mean something.
- Files: `tests/test_tier_r_shard.py` (`test_workflow_structure_and_pins`: expected job set `{'plan','shard','merge','windows-advisory'}` becomes `... 'msvc-advisory'`), `tests/test_ci_summary.py` (`test_artifacts_hold_only_labels_and_reports`: expected upload paths gain `msvc-toolchain.json\nmsvc-status/\n` from the new job), `tests/test_tier_r_eval_cli.py` (`test_evaluate_with_imports_scores_and_exits_0`).
- How: (1) Read each assertion and the workflow `.github/workflows/corpus-tier-r.yml`. (2) For the two workflow tests keep every existing assertion and add: `msvc-advisory` exists, has `if:` containing `workflow_dispatch` and `vars.TIER_R_MSVC`, `continue-on-error: true`, `runs-on: windows-2022`, uploads only `msvc-toolchain.json` and `msvc-status/`. (3) For the eval_cli test: run it with `-vv --tb=long`, print `doc` (the parsed CLI output) to see the provider reasons for `bindiff` and `ghidriff` (both `failed`), find the cause (likely the imports fixture or a changed provider contract after LBL-11c), fix the code or the fixture, never relax `(code, status, engines) == (0, 'ok', {'bindiff': 'ok', 'ghidriff': 'ok'})`.
- Tests first: the failing tests are the red; add one test that the `msvc-advisory` job never runs on `pull_request` or `schedule`.
- Commands: `PYTHONPATH=src python -m pytest -q -p no:cacheprovider tests/test_tier_r_shard.py tests/test_ci_summary.py tests/test_tier_r_eval_cli.py`; `python -m ruff check tests tools/calibration`.
- CI: workflow `QA and Windows standalone` (`.github/workflows/qa-windows.yml`, job `qa`, matrix ubuntu-latest and windows-latest, dispatch or PR) for the full suite, and `corpus-tier-r` (pull_request trigger, `plan`/`shard`/`merge` smoke).
- Gate: 3 tests green, no test weakened (diff reviewed).
- Size S. Tier haiku for the two workflow tests; sonnet for the eval_cli root cause. Depends on nothing.

### T-02 Merge LBL-15 (PR #66) into the integration branch
- Goal: `train.py`, `shift.py`, `report.py` additions on the branch that everything else builds on.
- Files: none to write. Merge `origin/claude/instance-c-research` (or its PR) into `claude/instance-d-gui`. Conflicts: none expected (merge-tree clean at snapshot). `docs/modules.md` gets the LBL-15 block; `docs/specs/calibration-corpus-and-model.md` gets section 20; `docs/schemas/calibration/{PairRows,ShiftLadder}.json` are new.
- How: (1) `git fetch origin`. (2) Re-run `git merge-tree --write-tree --name-only HEAD origin/claude/instance-c-research` and read it. (3) Merge with a merge commit; do not squash instance C's history. (4) Run the train tests and `python -m tools.calibration.schemas` regenerate-and-compare test (`tests/test_calibration_tools.py`). Do not force-push either branch: the owner restored `claude/instance-c-research` once after an accidental force-push (owner decision 2).
- Tests: `tests/test_train_helpers.py`, `tests/test_train_pipeline.py`, `tests/test_train_report.py`, `tests/test_train_shift.py`, `tests/test_lbl26_audit_fixes.py`, `tests/test_calibration_tools.py`.
- Commands: `PYTHONPATH=src python -m pytest -q -p no:cacheprovider tests/test_train_*.py tests/test_lbl26_audit_fixes.py tests/test_calibration_tools.py`.
- CI: `QA and Windows standalone`, job `qa`, on PR #64/#66.
- Gate: all listed tests green; `python -m tools.calibration.train --help` prints `run`, `shift`, `report`.
- Size S. Tier haiku (mechanical) unless a conflict appears; then sonnet. Depends on T-01 only for a clean baseline.

### T-03 Wire the LBL-26 "for C" items into `train.py` (LBL-30)
- Goal: close the audit items the audit could not fix because `train.py` was not in its tree, so that the run fails closed instead of reporting an optimistic G1.
- Files: `tools/calibration/train.py` (functions `build_rows`, `run_training`, `_run`, `_prereg_sha`, `sample_guard`), `tools/calibration/report.py` (limits prose only if needed), new tests `tests/test_train_lbl26.py`. Do not edit `guards.py`, `lineage.py` (already fixed).
- How, one commit per sub-item:
  - C-1: after `identity_groups(cand, hub_max_lineages=cfg.hub_max_lineages)` in `build_rows`, call `guards.audit_identity_roles(cands, roles, hubs=grouping.hub_identities)`; a non-empty result stops the run with `TrainError('PT-KA-LEAK', ..., FINDINGS)` (exit 1). Roles come from `lineage.assign_roles(lineage ids, 'c9-v1', shift lineages from the manifest)`. If it fires, assign the role per identity group (never split a group, PREREG 2.4).
  - C-2: for every stratum, report indeterminate share `excluded['indeterminate'] / (rows + excluded)`; above 0.05 add a `worst_case` result with indeterminate read as y = 0 (precision and coverage) next to the point result; carry both into the report.
  - C-3: only `sampling.stratum == 'natural'` rows enter the calibrator, tau and headline. Resolve T-05 first (authored suites).
  - C-5 (D-01): `choose_tau` runs on the same out-of-fold rows that then give precision, coverage and intervals at that tau. Either select tau inside outer folds and report held-out precision, or print the G1 precision as "dev-selected" in the report. Recommended: label it dev-selected now (cheap, honest) and make nested selection a follow-up; the labelled-only route needs no statistics redesign. Escalate to opus only if sonnet cannot implement nested selection after one serious attempt.
  - C-6: halt in code (exit 1, report still written with `insufficient-data`) when: fewer than 30 lineages among evaluated evidence rows, fewer than 12 in a locked role (only when a locked form is requested), any `audit_manifest` violation. The determinism re-run check is in CI (`ci_summary determinism`).
  - C-8: count resamples with an undefined statistic (`bootstrap._interval` reports `undefined`); refuse a headline interval when more than 5% (value is a proposal; record it in the lock commit) are undefined.
  - Preregistration file: replace `_prereg_sha` (plain `hashlib.sha256` of the file) with `prereg.prereg_sha256` (refuses CR bytes) and, when `--prereg` is given, require it to equal the `C9-PREREG-v1` row of `docs/qa.md` (`prereg.recorded_sha`); a draft file may only run with a flag that marks the report "unlocked".
  - Single use: wrap the final run in `run_locked_test(corpus_dir, prereg_sha, evaluate)` behind an explicit option (name it in the PR; do not reuse a flag name from another module). Only the final R6 run uses it; R5 uses a throwaway SHA (T-16).
- Tests first (names): `test_identity_shared_across_roles_stops_the_run` (feeds two lineages that share a non-hub body across roles; expects exit 1 and `PT-KA-LEAK`), `test_indeterminate_over_five_percent_adds_worst_case_block`, `test_under_30_lineages_halts_with_insufficient_data`, `test_report_marks_tau_precision_dev_selected`, `test_prereg_file_must_match_qa_row`, `test_second_final_run_for_one_sha_is_refused`, `test_authored_rows_not_in_natural_table` (after T-05).
- Commands: `PYTHONPATH=src python -m pytest -q -p no:cacheprovider tests/test_train_*.py tests/test_lbl26_audit_fixes.py`; `python -m ruff check tools/calibration tests`.
- CI: `QA and Windows standalone`, job `qa`. No corpus run needed.
- Gate: the audit's section "For C" has every line marked done or deliberately deferred in the PR text; deferred items D-02..D-12 each get an owner or a "documented limit" in `docs/qa.md`.
- Size M. Tier sonnet. Depends on T-02. Statistics redesign (nested tau) opus only after a failed sonnet attempt.

### T-04 Real data path: engine outputs and feature rows from runs (LBL-31)
- Goal: `train.py` can consume real Tier R runs. Today nothing writes `tier-r-engine-output/1` files or `tier-r-feature-rows/1` documents, and `shard.py` cannot carry them: `sanitize()` rejects lists over 5,000 items and strings over 2,000 characters and drops code or table keys, but feature rows can be up to 200,000 per pair (`train.MAX_ROWS_PER_PAIR`).
- Files: `tools/calibration/tier_r/evaluate.py` (add an option to write `engine_output_doc` per pair and engine into a directory), `tools/calibration/tier_r/cli.py` (`evaluate`: new option name chosen in the PR), `tools/calibration/tier_r/shard.py` (`run_shard` copies those files into `shard-out/outputs/`; `merge` verifies their SHA-256 against the aggregate's per-pair `output_sha256`), `.github/workflows/corpus-tier-r.yml` (upload `shard-out/outputs/*.json` as a second artifact `tier-r-outputs-<shard>`; labels documents too, see below), `tools/calibration/train.py` (`--labels` + `--outputs` already reads them). New spec: `docs/specs/program-e/LBL-DATA-integration-plan.md` section 2.
- How: (1) Spec first (section 2 of the new spec defines the file layout and size caps). (2) In `evaluate.py` write each `engine_output_doc(out, labels, symbols)` to `<dir>/<pair_id>.<engine>.json` with canonical JSON; the SHA must equal the `sha` already stored in the report (`RS.output_sha256`). (3) The label documents (`<store>/labels/*.json`, `known-answer-labels/1`) are also needed by `train.py --labels`; they are open-source function tables, not binaries, so uploading them is within the workflow comment ("labels metadata, feature tables and aggregate metrics only") but the workflow header and `shard.refuse_microsoft` must be re-read before changing it; add them as a third artifact file set. (4) Add a `train` job (needs: merge) that downloads the three artifacts and runs `python -m tools.calibration.train run --labels <dir> --outputs <dir> --out train-out --smoke` on dispatch with a new input, never on pull_request.
- Tests first: `test_evaluate_writes_engine_outputs_matching_report_sha`, `test_shard_carries_outputs_and_merge_checks_their_sha`, `test_train_reads_outputs_written_by_evaluate` (round trip on the template suite with the synthetic engine), `test_outputs_artifact_contains_no_binaries` (extension and size cap).
- Commands: `PYTHONPATH=src python -m pytest -q -p no:cacheprovider tests/test_tier_r_eval_cli.py tests/test_tier_r_shard.py tests/test_train_pipeline.py tests/test_tier_r_eval_corpus.py`.
- CI: `corpus-tier-r` smoke (dispatch `subset=smoke`, `engines=rz-diff`, `shards=2`), then the new `train` step on its output: expected exit 0 with all of G0/G2/G3 `insufficient-data` and G1 `insufficient-data` (smoke has far fewer than 30 lineages).
- Gate: smoke run produces a `train-out/report.json` that `python -m tools.calibration.train report train-out/report.json` verifies.
- Size M-L. Tier sonnet. Depends on T-02. Touches `shard.py` and `cli.py`, so do not run alongside T-07.

### T-05 Decision then change: do authored suites count as natural rows?
- Goal: remove a contradiction. LBL plan 7.3 says natural = every engine candidate of release, CVE and control pairs, adversarial = mutation, noise and identity-negative suites. LBL26-01 made `annotate.candidates` treat stratum `authored` as adversarial. `train.build_rows` hard-codes `'natural'` for every row of every pair that `guards.evidence_pairs` keeps (it drops only `aa`, `noise`, `mutation`), so authored suites become natural rows in training.
- Consequence if authored suites are adversarial: natural lineages are the 16 recipe lineages (plus growth), below the 30 needed for a non-anti-conservative headline, so G1 is `insufficient-data` until about 30 recipe lineages exist. The "38 lineages" in the plan assumed the 24 suites counted. This is my reading of the code, not a run (UNVERIFIED U-13).
- Files after the decision: `tools/calibration/train.py` (`build_rows`: use the pair's stratum from the document, put authored rows in an `adversarial` table that is reported but never calibrates), tests as in T-03.
- Decision owner: owner (section 4, decision D-A). Recommendation: authored suites are adversarial (consistent with the plan and LBL26-01), and corpus growth targets recipe lineages.
- Size S after the decision. Tier sonnet. Depends on T-03 for the shared file.

### T-06 R1 diagnostic runs (no code)
- Goal: learn whether the catalogue builds on a runner and what an A/A floor looks like, before writing more code.
- Prereq: T-01 merged (a red `merge` job hides real signal). Dispatch from the branch that holds the workflow you want; main's copy lacks nightly, determinism and `msvc-advisory` (UNVERIFIED U-7: whether a branch copy can be dispatched while main has a different file).
- How:
  1. `gh workflow run corpus-tier-r.yml --ref claude/instance-d-gui -f shards=4 -f seed=1 -f engines=rz-diff -f subset=cards`. Workflow inputs (checked in the file): `shards` (default 4, 1-256), `seed` (default 1), `engines` (comma list: rz-diff, ghidriff, bindiff; default rz-diff), `subset` (smoke, suites, cards, mutations, noise or full; default smoke). Cards subset runs `fetch <id>` then `build-card <id>` for every buildable card (recipe exists, licence permissive), then `evaluate --engine rz-diff --symbols hidden` per shard.
  2. `gh workflow run corpus-tier-r.yml --ref claude/instance-d-gui -f shards=2 -f subset=noise` and `-f subset=suites` (these run `noise:<suite>`, `aa:<suite>`, `build-suite` on the 25 authored suites only, not on recipes: see T-07).
  3. Wait; find the run with `gh run list --workflow corpus-tier-r.yml --limit 5`; read it with `gh run view <id>`; download with `gh run download <id> -n tier-r-aggregate -D r1-aggregate`. Files: `tier-r-aggregate.json`, `tier-r-merge.json`, `tier-r-report.md`, `ci-summary.json`, `ci-summary.md`.
  4. Read with Appendix A. For each card whose case status is not `ok`, open the job log of its shard: the log prints `[BLOCKED|FAILED|TIMEOUT] <case>: <reason>` plus a stderr tail.
  5. Record in `docs/qa.md` under a new heading `### [LBL-R1:diagnostic] <date>`: run id, inputs, counts per case status, per-recipe result, measured shard minutes (replaces the estimates), first failing recipe.
- Expected runtime (estimates, UNVERIFIED U-3): cards subset about 50 cards over 4 shards; the plan guessed 6-10 runner-hours total for R1. Job caps are 120 minutes per shard job (`timeout-minutes: 120`) and 1,800 s per case (`--timeout 1800`).
- Gate: every card is `ok` or has a recorded reason; any `findings` status (labels disagree) is listed. Stop and fix the first failing recipe (T-09 step 8) before any other dispatch.
- Size S. Tier haiku. Owner or any session with `gh` write access to Actions. Depends on T-01.

### T-07 Planner gaps: A/A, noise and mutation only run on authored suites (LBL-32)
- Goal: A/A, noise and mutation cases for recipe lineages. `shard.py` `case_steps` maps `aa:` and `noise:` ids to `--suite corpus/ours/<name>` and `mutate:` to `--suite`; `tier_r aa` and `noise` also accept `--card` but the planner never emits them; `mutate` has only `--suite`. So the planned mutation farm over recipe sources (plan R2: 25 operators x recipe lineages) cannot be dispatched.
- Files: `tools/calibration/tier_r/shard.py` (`_CASE` regex, `case_steps`, `plan_cases`), `tools/calibration/tier_r/cli.py` (`mutate`: accept a card/version source, only after `mutations/engine.py` supports non-suite bases; check `factory.BaseSource`), `tests/test_tier_r_shard.py`.
- How: add case ids `aa-card:<card id>:<side>` and `noise-card:<card id>:<side>` mapping to `aa --card <id> --side <old|new>` / `noise --card ...`; keep the id grammar's character class; extend `refuse_microsoft` coverage by test. Defer recipe-source mutation until the mutation engine can take a recipe base (spec first; ship A/A and noise first).
- Tests first: `test_plan_includes_card_aa_and_noise_for_every_recipe`, `test_case_steps_for_card_aa`, `test_unknown_side_rejected`.
- Commands: `PYTHONPATH=src python -m pytest -q -p no:cacheprovider tests/test_tier_r_shard.py`; then dispatch `subset=noise` and read A/A byte identity per recipe.
- CI: `corpus-tier-r` dispatch.
- Gate: A/A byte-identical X-vs-X for every recipe (stop-and-ask 4 otherwise).
- Size M. Tier sonnet. Depends on T-04 only if both touch `shard.py` (do sequentially).

### T-08 Licence register and card decisions (from the LBL-05 audit)
- Goal: close the three strict xfails in `tests/test_corpus_cards_audit.py`.
- Files: `tools/calibration/tier_r/catalogue/recipes.d/pcre2.json` and `recipes.json` (`license_spdx`), `docs/plans/calibration-licences.md` (rows for brotli and zstd), `corpus/catalog/crypto-net-db-script.json` (the `postgresql-libpq` card), `tests/test_corpus_cards_audit.py` (remove the xfail markers when fixed).
- How: pcre2: the register says `BSD-3-Clause WITH PCRE2-exception`; first check that string is on `PERMISSIVE_SPDX` (`tier_r/contracts.py`), then change both recipe layouts in one commit and re-run `catalogue-check`. brotli (MIT per recipe evidence) and zstd (BSD-3-Clause elected over GPL-2.0; record the election) get register rows. PostgreSQL: owner decides allow-list vs `excluded` with reason (section 4, D-C).
- Tests: the three xfails flip to passing: `test_pcre2_recipe_licence_matches_the_register`, `test_brotli_and_zstd_are_in_the_licence_register`, `test_no_found_card_uses_a_blocked_licence`.
- Commands: `PYTHONPATH=src python -m pytest -q -p no:cacheprovider tests/test_corpus_cards_audit.py tests/test_tier_r_catalogue.py`; `python -m tools.calibration.tier_r catalogue-check`.
- Gate: 0 xfail left in that file; recipe digest change recorded (pcre2 digest changes, so cached builds miss once).
- Size S. Tier haiku. Depends on owner answer for PostgreSQL.

### T-09 Corpus growth: add recipe lineages (LBL-33; the biggest remaining body of work)
- Goal: enough independent lineages for a defensible headline. Targets: at least 30 lineages in the evaluated natural population (below that every interval is `anti_conservative` and the headline cannot pass) and 12 in a locked role if a locked-form G1 is wanted (about 48 total at 25%; roles are hash-assigned, so the real count differs; compute it, step 1). Whether suites count as natural decides the arithmetic (T-05).
- Candidates: the 20 C entries in `origin/chatgpt/corpus-1` `tools/calibration/catalogue/*-candidate.json` (hiredis, http-parser, inih, jsmn, libhydrogen, libogg, libspng, libtomcrypt, libtommath, libvterm, llhttp, monocypher, nanopb, nghttp2, parson, protobuf-c, qoi, speex, tinycbor, yyjson) plus the reserve named in the LBL plan (libsodium ISC, libssh2, minizip, libuv, libwebp, libarchive; licences and pins UNVERIFIED). C++ candidates (jsoncpp, pugixml, snappy, tinyxml2) stay blocked (C source locator only). Subset recipes (libtomcrypt, nghttp2, hiredis) and dependency cases (libspng needs zlib) need the scope decision in the candidate file. 16 existing plus 20 C candidates is 36; 48 needs about 12 more from the reserve and the plan's 6 leads (mpack, tlsf, minIni, libbase64, libb64, simdjson; all UNVERIFIED, simdjson is C++).
- Per recipe procedure (one recipe, one PR, never batch an unverified recipe):
  1. Role preview (informational only; do not choose recipes by role, that is selection bias): put the project names through the same function the manifest uses: `lineage.assign_roles([factory.pair_id('L', project)], 'c9-v1')`. Today's counts are in section 1.
  2. Read the candidate file: `git show origin/chatgpt/corpus-1:tools/calibration/catalogue/<name>-candidate.json`. It contains proposal data only (AUTHOR-DEFINED keys, not `tier-r-recipe/1`). Do not copy it wholesale.
  3. Pins (network, allow-listed host `github.com`): list tags `git ls-remote --tags https://github.com/<owner>/<repo>.git`. `--refs` lists tag objects; an annotated tag's `^{}` line is the peeled commit: use the peeled 40-hex commit. Pick at least 4 consecutive stable tags (3 adjacent pairs) of one build layout; projects without tags (stb, parson, qoi, libhydrogen have no tags) use version-bump commits that are ancestors of the default branch. Verify each commit exists: `git ls-remote https://github.com/<owner>/<repo>.git <tag>` and compare, or fetch it through `python -m tools.calibration.tier_r fetch <CARD_ID>` (which checks `git rev-parse HEAD == pin`).
  4. Licence at each pin: read the licence file at that commit, elect a permitted SPDX id from `PERMISSIVE_SPDX`, record `license_sha256` (SHA-256 of the file bytes at that pin). `fetch` writes `.ka-fetched.json` with the licence SHA-256; compare. Dual-licensed: record the election in `license_evidence` (<= 500 characters).
  5. Write the recipe (`tier-r-recipe/1`, strict): fields `project`, `family`, `upstream_git`, `license_spdx`, `license_file`, `license_evidence`, `libc` (`mingw` or `freestanding`), `output` (`<name>.dll`), `sources` (explicit globs), `exclude`, `include_dirs`, `defines`, `cflags`, `libs` (bare names), `copy_files`, `write` (authored config headers; no configure scripts are ever run), `depends`, `variants`, `pins`, `notes`. Existing examples: `recipes.d/libdeflate.json`, `recipes.d/c-ares.json` (libs), `recipes.d/stb.json` (commit pins, TU wrappers).
  6. Write release cards (`case-card/1`) for each adjacent pair (`kind: release`) and CVE fix cards only with a real CVE id and a fixing commit that is a pin; never invent either. Declared changed functions come from the factory labels after the first build (the libdeflate/stb/c-ares cards were written that way, "declared lists taken from the factory labels").
  7. Both layouts must match: add the recipe to `recipes.d/<project>.json` AND to `recipes.json`, cards to `releases.d/<project>.json` AND `releases.json` (CVE cards also in `cves.json`). The shard planner and the CLI read the monolithic files (`shard.py:90`, `cli.py:73`); `test_per_project_split_mirrors_the_monolithic_files` enforces equality.
  8. Build and verify locally (needs mingw-w64 and LLVM; `toolchain` shows readiness): `export PATCHTRACE_CALIB_ROOT=<short dir outside the repo>`; `python -m tools.calibration.tier_r fetch <card ids...>` then `python -m tools.calibration.tier_r build-card <card id> --opt O2`; then `python -m tools.calibration.tier_r aa --card <card id> --side old` (A/A rebuild pair; expect byte-identical images) and `... noise --card <card id> --side old`. The card build prints counts per label (unchanged, changed, address-only, ambiguous, no-counterpart) and `check` results; every declared function needs 0 `disagree`.
  9. Add the recipe to `TRANCHE` in `tests/test_tier_r_tranche.py` (project -> SPDX, minimum cards, adjacent pins) or a sibling test; run `catalogue-check`.
  10. Record in `docs/qa.md` under `### [LBL-NN:<recipe>]`: tags and commits verified by ls-remote (date), licence hashes, build host and compiler versions, counts, A/A result, what was not verified (runner build).
  11. Dispatch `corpus-tier-r` with `subset=cards` once per batch of recipes (T-06 procedure) and record the runner result.
- Tests first: add the recipe to the tranche test (red because the files do not exist), then create files until green.
- Acceptance gate per recipe: 3 consecutive pairs build; 0 unexplained `disagree` on declared functions; A/A byte-identical; `catalogue-check` ok; licence permissive with a recorded hash; vendoring scan (T-14) shows no unmerged overlap.
- Size L overall; S-M per recipe (a recipe with generated headers or a dependency is M). Tier sonnet for recipes that need `write` rules or dependencies; haiku for plain explicit-file-list recipes (the build is the check). Opus not needed.
- Dependencies: T-08 (so new work does not inherit the licence register mismatches), T-06 for the runner check.
- Stop rule: do not lower the 12/30 minima to make G1 pass; report the shortfall (`insufficient-data` is a valid result).

### T-10 Card audit leftovers (LBL-05 continuation)
- Goal: close what `docs/audits/20261015-lbl05-card-audit.md` left open.
- Files: `tools/corpus_check.py` (`--cve-list` is described in the LBL plan but not implemented), `corpus/catalog/*.json` or `case-card/1` additive field for Windows-scoped CVEs (needs a decision, D-D), `tests/test_corpus_cards_audit.py`.
- How: (1) Implement `--cve-list` as a checker that reads a local clone of CVE List V5 (`cves/<year>/<n>xxx/CVE-<year>-<n>.json`; no network inside the tool) and reports existence plus vendor/product match; run it where the network is allowed and paste the result in `docs/qa.md`. (2) Re-run `run_card` for the releases without a recorded `disagree` count: brotli, cJSON, expat, jansson, libpng, lua, lz4, mbedtls, miniz, pcre2, zlib, zstd (R1 produces this). (3) Windows-scope annotation after D-D.
- Tests first: `test_cve_list_option_flags_unknown_id` with a 3-file fake CVE tree.
- Commands: `python tools/corpus_check.py all`; `PYTHONPATH=src python -m pytest -q -p no:cacheprovider tests/test_corpus_check.py tests/test_corpus_cards_audit.py`.
- Gate: 33 CVE ids checked (existence, vendor/product) or each unresolved id marked `excluded` with a reason; ids from 2026 are the least checkable (UNVERIFIED U-8).
- Size M. Tier haiku. Depends on T-06 for the `run_card` part.

### T-11 Mutation follow-ups (LBL-06/07 leftovers)
- Goal: finish what the todo rows list: the `locate/cases/cli` split of LBL-06 is optional (the 25 operators already work through `engine.apply_case`); required: `buf-resize` must land `review` in the evaluation (frame-only), add `opt` to `tier_r/toolchain.CANDIDATES` so `probe()` reports it, wire `agreement_by_operator` (source vs IR label agreement) into the farm report, IR counterparts for the remaining semantic operators.
- Files: `tools/calibration/tier_r/toolchain.py`, `tools/calibration/mutations/{ir,coverage}.py`, `tools/calibration/tier_r/evaluate.py` or `evalcore/report.py` (agreement table), tests `tests/test_mutations_ir.py`, `tests/test_evalcore_report.py`.
- How: agreement rate per operator = share of mutants where the C-locator label and the IR-layer label agree; report it as the direct estimate of source-layer label noise. Stop-and-ask item 8 uses it (threshold 0.95 is a proposal, not in the prereg).
- Tests first: `test_toolchain_probe_reports_opt`, `test_agreement_by_operator_in_report`, `test_buf_resize_lands_review`.
- Commands: `PYTHONPATH=src python -m pytest -q -p no:cacheprovider tests/test_mutations_ir.py tests/test_mutations_opt.py tests/test_evalcore_report.py`.
- CI: `corpus-tier-r` `subset=mutations` (suites only until T-07).
- Gate: every operator class has at least 20 accepted mutants (G-U2) or is listed as thin; agreement table present.
- Size M. Tier sonnet. Depends on T-04 (report plumbing).

### T-12 MSVC `cl` leg (LBL-08, advisory)
- Goal: first real `cl` build; record `cl` version; check A/A byte identity under `/Brepro`, `/d1trimfile` path normalisation, `llvm-strip` on a MSVC image.
- Files: none unless the run exposes defects (`tier_r/msvc.py`, `build.py`).
- How: the owner sets the repository variable `TIER_R_MSVC=1` (Settings, Secrets and variables, Actions, Variables); dispatch `gh workflow run corpus-tier-r.yml --ref claude/instance-d-gui -f subset=smoke`; the job `msvc-advisory` (windows-2022, `continue-on-error`) runs `python -m tools.calibration.tier_r toolchain` and `tests/test_tier_r_msvc.py` with `PATCHTRACE_REQUIRE_MSVC=1`. Download `tier-r-msvc-advisory`.
- Expected: `msvc-toolchain.json` shows `cl` path and version; tests that record `blocked` on Linux now run. Advisory until 10 green runs (LBL open question 2).
- Gate: the real-compiler test passes; if MSVC never runs, PREREG Q2 default applies (gcc-versus-clang shift split).
- Size S (run) to M (if it exposes build defects). Tier sonnet. Depends on T-01. Owner sets the variable.

### T-13 Unified adapter (LBL-12) [blocked on the unified engine]
- Goal: `evalcore/engines/unified.py` mapping `unified-result/1` rows per LBL plan 7.1 (flag mapping: `material` and `review` flag; `cosmetic`, `unchanged` do not; `unknown` abstains; `matched`/`tentative` paired; `candidate`/`contested`/`ambiguous`/`unknown` abstained; `older-only`/`newer-only` unpaired), fixtures in `tests/fixtures/known_answer/unified/`.
- Until the unified engine produces results on this corpus, the run reports `unified` as `blocked`, not absent.
- Tests first: `test_unified_rows_map_per_flag_table`, `test_report_never_pools_engines` (exists for others).
- Size S-M. Tier sonnet. Depends on T-04 and the unified engine plan (`docs/plans/unified-engine-plan.md`). Not required for the Tier R headline.

### T-14 Pre-lock data steps
- Goal: everything the lock commit needs besides the code (PREREG 8.1).
- Steps:
  1. Vendoring scan. Produce body records during builds (`tier_r/bodyrecord.py` writes `<store>/bodies/*.bodies.json`), then `python -m tools.calibration.tier_r vendoring --threshold 0.15 --hub-max-lineages 3 [--store ...] [--out ...]` (both flags are required; the code has no defaults). Equivalent standalone: `python -m tools.calibration.vendoring_scan <bodies> --threshold 0.15 --hub-max-lineages 3`. It prints merge PROPOSALS and hub bodies; apply merges to the lineage definition; never split. zstd/brotli/zlib/libpng and Lua/Mbed TLS bundles are the expected hits (UNVERIFIED U-14).
  2. Shift declaration. Write into the manifest `split.shift_test_lineages` before anyone looks at labels: every lineage whose recipe uses the `msvc` profile, plus one named family; if the MSVC leg never ran, the gcc-versus-clang split of PREREG Q2. `tier_r/manifest.SPLIT` is empty today (audit D-12); add a manifest option or a post-step and test it.
  3. Manifest: `python -m tools.calibration.tier_r manifest --corpus-id <id> --created <date> --tool-git <sha> --out <file>`, then `python -m tools.calibration.corpus verify <file>` and `python -m tools.calibration.corpus guard --manifest <file>`. Record the manifest SHA.
  4. Stratified sample list hashed (PREREG 2.6, spec 5.3): generated by `tools/calibration/sample.py`; commit the list and its hash.
  5. Manual noise sample (proposal): 100 accepted labels (50 mutants, 50 release or CVE pairs) drawn before the lock; the owner reviews with the terminal tool (`label.run_terminal`, hash-chained `AnnotationLog`); report the error rate with a Clopper-Pearson interval (about 2.5 h of owner time, an estimate).
  6. Guideline `g1` final: `tools/calibration/guidelines/g1.md`.
- Tests: existing `tests/test_tier_r_vendoring_cli.py`, `tests/test_prereg_tools.py`; add `test_manifest_records_shift_declaration`.
- Gate: manifest verifies, guard passes, shift list present, sample list hashed.
- Size M. Tier sonnet (shift declaration code), haiku (running tools). Depends on T-09, T-12 (or Q2 default).

### T-15 R2 mutation farm and R3 Ghidriff leg (dispatch only)
- R2: `gh workflow run corpus-tier-r.yml --ref claude/instance-d-gui -f shards=32 -f seed=1 -f engines=rz-diff -f subset=mutations`. Planner: `plan --seeds-per-operator` exists in the CLI (`python -m tools.calibration.tier_r.shard plan --help`) but the workflow does not pass it; default per `make_plan`. Cases: `mutate:<suite>:<operator>:<seed>` for every authored suite (not recipes, T-07). Plan estimate 40-60 runner-hours for 6,500 mutants was for recipe lineages; re-estimate from R1.
- R3: `gh workflow run corpus-tier-r.yml --ref claude/instance-d-gui -f shards=32 -f engines=ghidriff -f subset=cards` (Ghidra 12.0.4 and Ghidriff are installed by the job when `ENGINES` contains `ghidriff`; Java 25 temurin). One Ghidra JVM at a time per shard; case timeout 1800 s is a row in the report, not a silent drop. Plan estimate 90-160 runner-hours [inf, U-3]; replace by the first measured shard.
- Read both with Appendix A. Gate: engine completion at least 90% (below: stop-and-ask 5).
- Size S per dispatch. Tier haiku. Depends on T-04, T-06, T-07, T-11.

### T-16 R5 dev training run
- Goal: the full pipeline on real Tier R data with a throwaway SHA, then read it, before the lock.
- How: (1) From the merged artifacts: `python -m tools.calibration.train run --labels <labels dir> --outputs <outputs dir> --out train-r5 --tool-git <git sha>`; alternative inputs: `--rows <dir>` or `--merge tier-r-merge.json --aggregate tier-r-aggregate.json`. Add `--smoke` only for a plumbing check (500 bootstrap draws and 200 null sims instead of 2,000 and 1,000; recorded in the report). (2) `python -m tools.calibration.train shift --labels ... --outputs ... --out train-r5-shift` writes only `shift.json`. (3) `python -m tools.calibration.train report train-r5/report.json --out train-r5/report.md` verifies the claim. (4) Run it twice and compare `report_sha256` (determinism, stop-and-ask 3). (5) Read with Appendix A. Do not pass `--prereg` with the draft file for anything but a dry run: without it the run key uses the placeholder `unlocked-placeholder`.
- Runtime: UNVERIFIED (plan estimate 1-2 runner-hours for 1 job).
- Gate: G1 evaluated or `insufficient-data` with reasons; G0/G2/G3 `insufficient-data`; no `audit_manifest` violation; no leakage finding; identical SHA twice. If anything in stop-and-ask list B fires, stop and ask.
- Size M (reading is the work). Tier sonnet. Depends on T-03, T-04, T-09 (at least a first tranche), T-14 steps 1-3.

### T-17 Preregistration lock (LBL-16)
- Preconditions (PREREG 8.1): (a) manifest verifies and guard passes; (b) shift declaration in the manifest; (c) `g1` final; (d) `docs/plans/c9-preregistration-v1.md` has its final bytes (decide Q1, Q2, Q3, Q4, Q5 defaults in section 4 and edit the file now, before the lock; any edit after is v2); (e) owner sign-off O3 recorded in `docs/qa.md`; (f) stratified sample list committed with its hash; (g) no locked-test or shift-test label analysed (T-16 must have used only dev rows for any tuning: it does not tune, but note the shift ladder R5 reads shift lineages; the plan treats the shift look as part of the single preregistered run, so for R5 either exclude shift lineages or accept that R5 is a rehearsal on a throwaway SHA and re-declare nothing; record which in qa.md).
- Steps: (1) Confirm no end-of-line conversion: `.gitattributes` has no entry for this path (`git check-attr eol text -- docs/plans/c9-preregistration-v1.md` prints "unspecified"); commit it with LF; add a `.gitattributes` line `docs/plans/c9-preregistration-v1.md text eol=lf` in the same commit (that edit does not change the file bytes). (2) Commit everything in (a)-(f) in one lock commit C. (3) `git show C:docs/plans/c9-preregistration-v1.md | sha256sum` (lowercase hex) must equal `python -m tools.calibration.prereg` printed value (P-1). (4) Add a row to `docs/qa.md` containing the text `C9-PREREG-v1`, the 64-hex SHA, the commit C, the date and the owner's sign-off (this is a later commit; do not edit the preregistration file). (5) Verify: `python -m tools.calibration.prereg --qa docs/qa.md` prints the SHA then `MATCH`, exit 0. (6) P-2 is `tests/test_prereg_constants.py` (already in the suite). (7) PREREG 8.5 iii (the section 2.3 lists equal the manifest) has no code or test yet: add `test_shift_declaration_matches_manifest` or check by hand and record it. (8) Add the registry row to `docs/specs/REGISTRY.md` (integrator ask in the prereg).
- Files: `docs/plans/c9-preregistration-v1.md`, `docs/qa.md`, `.gitattributes`, `docs/specs/REGISTRY.md`, `tasks/todo.md` (tick C9-0), `docs/plans/hard-problems/calibration-plan.md` (step 1) only after sign-off.
- Gate: `prereg --qa` returns MATCH; owner sign-off text present. Size S. Tier sonnet for the checks; the methodology wording needed opus once in the plan and is already drafted. Depends on T-03, T-14, T-16, and the owner.

### T-18 R6 final run and R7 determinism
- R6: exactly once per SHA: `python -m tools.calibration.train run <inputs as T-16> --prereg docs/plans/c9-preregistration-v1.md --out train-final` with the single-use option added in T-03. A crash still spends the SHA (receipt created before evaluation; `run_locked_test`), by design. Dry-run the locked path first on the template suite with a throwaway SHA.
- R7: re-run from the manifest and artifacts and compare `report_sha256` byte-for-byte (`python -m tools.calibration.ci_summary determinism <dir1> <dir2>` compares two merged directories; for train reports compare the field by hand or add a helper).
- Output goes to `docs/qa.md` as: report SHA, G1 status, the numbers with intervals from the report, `TIER_R_CLAIM`, and the stop-and-ask list outcome. A failed or aborted run is reported as it happened and is not retried under the same SHA (PREREG 8.7).
- Size S. Tier sonnet. Depends on T-17.

### T-19 After the Tier R result: channel inputs, GUI scope line, reports, status CLI
- LBL-13 real inputs: channel packs run on synthetic inputs only. Real inputs need the FLOSS and capa runners (T track) and YARA-X for `rules`. Files: `tools/calibration/channels/*.py` adapters. Detectors join the default lead-list profile only with: precision above base rate with a lineage interval, A/A false-lead rate at most 0.1% with the Clopper-Pearson bound within it (about 2,995 clean functions, LBL26-03), non-inferior hit@10 (margin -0.02, paired lower bound). Audit deferred D-02: channel `no_violations` style flags pass after one clean pair; set an owner minimum (D-E).
- LBL-18 (GUI scope line; M, sonnet): `ui_evidence.py` seam of at most 40 lines, `secondary/evidence_view.py`, `tooltips.py`, `tests/test_ui_calibration_scope.py`: `EvidencePanel.set_scope(notice)`, `evidence_calibration` label, "Show evidence limits" checkbox, offscreen tests run 20 times. Copy is fixed in LBL plan 8.6 and contains no percent sign and none of the banned stems. Status stays "Order only" whatever the Tier R result is. Do not start before the result exists.
- LBL-19 (S, haiku): `src/patchtrace/reports.py` additive `evidence_scope`; `calibration/status.py`; `cli_commands/calibration.py` of at most 25 lines; `patchtrace calibration status [--json]` exits 4 when nothing is bundled (normal today), then 0 once a ledger ships; frozen smoke expects exit 4.
- Ledger: a `synthetic-validated` entry (with `tier-r` evidence and the report SHA) may be added only from the locked run's report; never `windows-validated`.
- Gate: tests named in the LBL plan 8.6 and 8.4; the banned-stem sweep `test_scope_copy_sweep` (named in `scope.py`).

### T-20 Tier W (LBL-20..25) and the owner run
- State: only `catalogue`, `pairs`, `guard`, `msf`, `pe_tables`, `run_local`, `make_fixtures` exist. Missing: `fetch.py` + transport, `symbols*.py` (Ghidra exporter, `symbol-map/1` writer, optional llvm-pdbutil adapter), `labels.py`, `audit.py`, `runner.py`, `evaluate.py`, `aggregate.py`, `pipeline.py`, `__main__.py` (the `all` command). Until they exist `run_local` exits 3 (BLOCKED) on a real run, and the owner's Tier W run (owner decisions 13, 14) cannot happen. Check the real status first: `ls tools/calibration/tier_w`.
- Slices, each M, sonnet, self-made fixtures, hermetic tests, live paths record passed/failed/blocked: LBL-20 fetch and `SymbolTransport` (binaries through `quarantine.acquire`, PDBs through a Transport subclass, throttle, resume, disk check, cancel file); LBL-21 symbols (spec `docs/specs/tier-w-local-corpus.md`, SPEC-33 s11 subcommands); LBL-22 labels, N2/N3/N9/N10 tags, audit queue (cap 150) and error rate; LBL-23 runner (symbols hidden, visible only with a flag); LBL-24 `evaluate` over `evalcore` and `aggregate` (`tier-w-aggregate/1`, cells under n = 30 suppressed, joins `tier_w/guard.py` contract list); LBL-25 `pipeline.py` and `__main__.py` (`all`), dry run on fixtures.
- Owner steps (cannot be done by an agent; Microsoft data never enters git or CI, `tier_w/guard.py` enforces): follow `docs/runbooks/tier-w-local-run.md` (prerequisites: short root path without dot components, `PATCHTRACE_CALIB_ROOT` outside the work tree, Python with the repo installed and a Python with `pyghidra`/`ghidriff`, Ghidra and Java, network to `winbindex.m417z.com` and `msdl.microsoft.com` for catalogue, resolve and fetch only). Command (from the runbook): `python -m tools.calibration.tier_w.run_local --corpus-id tier-w-2026q4 --consent-hosts winbindex.m417z.com,msdl.microsoft.com --python <py> --ghidra-dir <dir> --timeout 3600`; `--dry-run`, `--only run,evaluate` resume. Exit codes 0 ok, 1 partial or guard findings, 2 configuration or consent, 3 BLOCKED, 5 cancelled. After the run: guard stage `ok`, `git status` shows no new files, record only aggregate numbers in `docs/qa.md`.
- What only the owner can decide or verify: legal reading of the symbol-server terms (O1), second annotator (O2, G3 cannot pass without it), Tier W families covering kernel, usermode DLL and driver (at least 6, G0), Tier W shift lineages (O4), symbol-audit error at most 0.02, what aggregate may enter `docs/qa.md`, any `windows-validated` ledger entry, the frozen-EXE smoke of a bundled artifact.
- Size L overall. Depends on T-04 (evalcore reuse) for LBL-24 only; the rest are independent of the Tier R result.

## 4. Decisions only the owner can make (with recommendation)

| id | decision | recommendation |
|---|---|---|
| D-A | Do authored suites count as natural rows in training (T-05)? | No: adversarial table only, as the LBL plan and LBL26-01 say. Consequence: corpus growth targets recipe lineages and G1 stays `insufficient-data` until about 30 natural lineages exist. State this in the lock commit |
| D-B | PREREG Q1: which split gives G1? | Keep the draft default: out-of-fold over all Tier R lineages, labelled synthetic; a locked-form look only if the locked role has 12 or more lineages (11 today by hash). Do not choose recipes to hit 12 |
| D-C | PostgreSQL card (`postgresql-libpq`): `PostgreSQL` is not on the permissive allow-list | Mark the card `excluded` with the reason; do not widen the allow-list for one card |
| D-D | Windows-scoped CVE annotation (CVE-2024-20696, CVE-2024-26256 are Microsoft-scoped records on libarchive): which field | Add an additive optional field to `case-card/1` named in the PR; labels stay source-level and no Windows-binary claim is made |
| D-E | Minimum pool for channel "no violation" flags (audit D-02) | Reuse the Clopper-Pearson rule (0.1%, about 2,995 clean items) so the gate can be passed only by a pool large enough to show it |
| D-F | PREREG Q2: shift set when MSVC never runs | gcc-versus-clang split declared in the lock commit, rung 2 labelled accordingly |
| D-G | PREREG Q3 `hub_max_lineages`, Q4 interval method, Q5 where the H5 "n >= 200" filter is applied | 3; percentile B = 2000 as the primary plus a studentized cluster bootstrap and a leave-one-lineage-out jackknife as preregistered sensitivity rows (LBL remaining plan Q3: percentile may undercover at about 38 clusters); evaluation step applies the filter |
| D-H | O3: sign-off on targets (A only, B/C/D reserved null) and display rounding (down to 5%, L2 only) | Sign. Nothing numeric is displayed from Tier R in any case |
| D-I | Single-annotator workflow and manual noise sample (T-14 step 5; O2) | Owner alone, 100-item blind sample before the lock, report the error rate with an interval; G3 stays out of reach until a second annotator exists |
| D-J | MSVC leg required or advisory (LBL open question 2) | Advisory until 10 green runs; pin `windows-2022` |
| D-K | Are 150-250 runner-hours acceptable? | Already YES (decision 6); the repository is public (`gh api` says `private: false`), but the free-minute terms were not read (UNVERIFIED U-10), so check the Actions usage page after R1 |
| D-L | Does a Tier R lock wait for Tier W? | No. Tier R result is a pipeline check; Tier W is a separate preregistered look that is owner-only |

## 5. Pitfalls and lessons

- Natural stratum with no negatives (found in LBL-26): `annotate` once marked a candidate natural only if it was a truth pair, so every natural row had y = 1 and precision was 1 by construction. Fixed (`sampling_of`); regenerate any `calibration-labels` file written before the fix. A label-only `annotate` run (no engine outputs) now yields no natural rows on purpose.
- Roles are per lineage but CV groups are per identity group: two merged lineages can sit in different roles, leaking a body from dev into locked-test (LBL26-02). `guards.audit_identity_roles` exists but `train.py` does not call it yet (T-03).
- `hub_max_lineages` has no safe code default (`None` disables hubs). Always pass 3 explicitly; `vendoring_scan` and `tier_r vendoring` refuse to run without it.
- Two catalogue layouts: the planner and CLI read `recipes.json` and `releases.json`; `recipes.d/` and `releases.d/` are the split source. Edit both or the test `test_per_project_split_mirrors_the_monolithic_files` fails and cards silently drop out of `_cards()`.
- `shard.sanitize` drops table keys and rejects long lists: aggregate numbers fit, feature rows do not. Do not try to ship rows through `shard-*.json` (T-04).
- Windows: CRLF breaks mutation `site` columns and the preregistration hash. Fixtures are LF through `.gitattributes` (`tests/fixtures/known_answer/** text eol=lf`; `corpus/** text eol=lf`); `tier_r/catalogue/**/*.json` has no such line (UNVERIFIED U-5); the prereg file has none either, so hash from git (`git show C:path | sha256sum`) and refuse CR (`prereg.py` does).
- Short parametrize ids (Windows limit on `PYTEST_CURRENT_TEST`), `>=` on timings (15.6 ms clock), quote YAML scalars that contain ": ", `pip install --only-binary=:all:`, scratch paths under 240 characters (Ghidra rejects dotted project paths; the runbook uses a short root outside the tree).
- Toolchain drift: pin `ubuntu-24.04` and `windows-2022` (done in the workflow); `ubuntu-latest` moves to 26.04 in Nov 2026. Record compiler versions in `BuildInfo.compiler_version`; cross-digest comparison is refused.
- A/A and ICF: byte-identical X-vs-X is required; any flagged material change on it is stop-and-ask 4. `/Brepro`, path maps and `/d1trimfile` are why MSVC A/A may differ until the first real run.
- zlib v1.3 to v1.3.1 has 9 of 128 functions `ambiguous` (7%), above the 5% limit: expect the release stratum to be flagged on the first run. That is the bound working, not a bug; report point and worst-case results together.
- Ghidriff lists only added, deleted and modified functions, so unmentioned truth pairs count as matched: its identity numbers are an upper bound (note printed by the evaluator). Never average engines.
- Hostile names in reports: `sanitize_text` and Markdown escaping; do not render function names raw.
- Candidate files from `chatgpt/corpus-1` carry Git blob ids, not commits or licence SHA-256 values: they are leads only; every pin must be re-resolved.
- The workflow header says artifacts hold "labels metadata, feature tables and aggregate metrics only" and Tier W data is refused by `shard.refuse_microsoft`. Keep both when adding artifacts (T-04).
- Locked-look spent by a crash: the receipt is written first. Rehearse on a throwaway SHA.
- Parallel contributors: PR #64 and #66 are both based on main and both draft; the owner once restored an instance branch after a force-push. Never force-push; re-check SHAs and open PRs before each slice (CLAUDE.md).
- `gh` from the sandbox cannot use GraphQL (`gh pr list` returned HTTP 403 here): use `gh api repos/<owner>/<repo>/pulls` and `.../pulls/<n>`; `gh run list`, `gh run view` and `gh workflow run` use REST.

## 6. Verification checklist before calling the area finished

Tier R:
- [ ] T-01 to T-05 merged; the full calibration test set above is green on Linux and in the Windows leg of `QA and Windows standalone`.
- [ ] R1 recorded in `docs/qa.md` with measured runtimes; every card `ok` or listed with its reason.
- [ ] A/A byte-identical for every recipe lineage and suite; noise pairs present per lineage.
- [ ] At least 30 natural lineages (or the shortfall is stated and G1 reads `insufficient-data`); locked-role count stated.
- [ ] `catalogue-check` ok; licence register has a row for every recipe; 0 xfail in `tests/test_corpus_cards_audit.py`.
- [ ] Vendoring scan applied; manifest verifies; guard passes; shift declaration present; sample list hashed; `g1` final.
- [ ] LBL-26 "for C" items all closed in `train.py`; deferred D-01..D-12 each have an owner or a written limit.
- [ ] R5 dev run read and recorded; two runs give the same `report_sha256`.
- [ ] Owner sign-off O3 in `docs/qa.md`; row `C9-PREREG-v1`; `python -m tools.calibration.prereg --qa docs/qa.md` prints MATCH.
- [ ] R6 run exactly once; report SHA, G1 status, intervals, stop-and-ask outcome recorded; R7 identical SHA.
- [ ] Report text carries `TIER_R_CLAIM`; `train report` verifies; no banned wording; no percent derived from synthetic data shown anywhere in the product.
- [ ] Artifact stays `experimental`, display `none`, not bundled; ledger has at most a `synthetic-validated` entry citing the report SHA.
- [ ] `docs/modules.md`, `tasks/todo.md`, `docs/qa.md` updated per slice; the "not verified" lines say what remained unproven.

Tier W (owner):
- [ ] LBL-20..25 merged with fixture tests; `run_local` real run no longer exits 3.
- [ ] Owner run completed, guard `ok`, no new files in `git status`, aggregate only in `docs/qa.md`.
- [ ] G0 inputs: at least 6 families covering kernel, usermode-dll, driver; symbol-audit error at most 0.02; second annotator or test-retest kappa; toolchain profiles at least 2.
- [ ] No display level above order-only without G0 and G2 on a bundled artifact with `tier-w` evidence, owner sign-off and a `docs/qa.md` report SHA.

---

## Appendix A. How to read the outputs

Shard and merge (workflow artifacts):
- Case status per shard (`cases[].status` in `shard-*.json`): `ok`, `findings` (the command ran but labels disagree or an engine failed a pair; exit 1), `skipped` (with a reason), `blocked` (tool or input missing, exit 3; never a pass), `failed`, `timeout`. A shard file digest mismatch or a missing, duplicate or foreign shard makes `merge` fail.
- `ci-summary.json` (`tier-r-ci-summary/1`): `status` is `ok`, `warning` (an engine completed under 90% of its pairs, or attempted none), `failed` (a case failed), `error` (the shard set was rejected or merge failed). Per engine and stratum: attempted, completed, blocked, failed, completion. `report_sha256` is the merged report digest; `ci_summary determinism` must report `ok` (two merges, same digest).
- `tier-r-aggregate.json` (`tier-r-report/1`) and `tier-r-report.md`: starts with the claim line; Engines table (status, version, runs, failures, reason); Strata table per engine (pairs, identity precision and recall, changed precision and recall, false-positive rate). Read the status column first: `blocked` and `partial` engines mean the numbers cover fewer pairs. Read the strata `release`, `cve`, `control` separately from `mutation`, `noise`, `aa`, `authored`; never pool them.
- Per-label tables, rank block (hit@k, MRR, nDCG, `pool_median`) and `anti_conservative` flags appear in the evalcore blocks of the report JSON; planted and real-fix populations are separate. A flagged interval (`anti_conservative`) is not a result.

Training (`train run` output):
- stdout summary: `train_key`, `report_sha256`, `gates` (G0..G3 status). `report.md`: claim quote, preregistration SHA (`unlocked-placeholder` means the run was not preregistered), manifest, label set, tool git, Gates list with reasons, per profile metrics (Brier, Brier skill, ECE, AUC, log loss, slope, intercept, precision, coverage with 95% intervals, tau, tau_low, `n_groups`), shift ladder rungs, Blind spots.
- Expected on Tier R: G1 `pass`, `fail` or `insufficient-data`; G0, G2, G3 always `insufficient-data` (`verify_tier_r_report` rejects anything else). `insufficient-data` is never a pass.
- Headline conditions (LBL remaining plan 4.1; frozen values in PREREG 5-6): precision at the frozen tau point at least 0.95 with CI lower at least 0.93 and width at most 0.06 (L2, used by G1) and LTT certified; coverage at least 0.50 (lower 0.40); Brier skill CI lower above 0; ECE excess at most 0.03 (upper 0.05); FDR reduction against the best of M0, M0b, M1, M2 with CI lower above 0 and relative reduction at least 0.25; every stratum with weighted n at least 200 has precision CI lower at least 0.88; shift precision at least 0.90 (reported; a miss is a blind spot, not a retry trigger).
- `n_groups` below 30: intervals are `anti_conservative`, the headline cannot pass.

## Appendix B. Stop-and-ask thresholds (exact)

Stop, post the report as it is, and ask the owner; do not retune, retry under the same SHA, or relax a gate (PREREG 2.3, 8.7). Values 1-7 are quoted from PREREG 5-6 and LBL plan 6, 7.6; the number in 8 is a proposal.
1. G1 `fail`, or any of (a)-(e) in the headline list misses its L1 value on the dev out-of-fold result, or the locked look misses it. `insufficient-data` is also a stop-and-ask.
2. Fewer than 30 lineages in the evaluated population, or fewer than 12 in a locked role.
3. Any `audit_manifest` violation, orientation (`PT-KA-ORIENT`) or symbol-leak (`PT-KA-LEAK`) error, or a different `report_sha256` on the determinism re-run.
4. Any flagged material change on byte-identical X-vs-X, or an A/A false-lead rate above 0.1% for a detector proposed for the default profile.
5. Indeterminate share above 0.05 in a headline stratum, or engine completion below 90%.
6. FDR-reduction or hit@10 paired interval includes zero or is negative against the best baseline (honest result: no demonstrated benefit; no more variants).
7. Shift-rung precision below 0.90.
8. Any operator class with fewer than 20 accepted mutants, or source/IR label agreement below 0.95 [proposal].

## Appendix C. Honest-scope wording rules

- Required statement: "Tested on test builds of open-source libraries (N code sets, compilers, tool versions). Not tested on Windows system files." Report claim constant: `TIER_R_CLAIM` = "Measured on test builds of open-source code; says nothing about Windows system files." (`src/patchtrace/calibration/scope.py`).
- Forbidden anywhere (tests enforce a banned-stem sweep plus `accurate` and `validated for windows`): "accurate", "validated for Windows", any percentage derived from synthetic data, "confirmed by two engines" where `D_ghidra` evidence is shared, any statement that a score is the chance a pairing or a patch is correct, "vulnerab...", "exploit...", "safe", "secure", "verified", "proven", "certain", "fixed" in new UI or report copy (full stem list: `scope.BANNED_STEMS`).
- "Fix function" means a function the upstream commit changed, nothing more. Engine scores are never averaged across engines or channels. Planted-mutation and real-fix results are separate populations. Unknown or missing is not a negative vote. Synthetic results may set a ledger entry to `synthetic-validated` only; never raise the display level; artifact stays `experimental`, display `none`.
- Lead-list claims are relative ("on test builds, variant A ranked the changed function higher than variant B, interval ...") and carry the population and lineage count.

## Appendix D. Quick command index (all argparse-checked at the snapshot)

- `python -m tools.calibration.tier_r {toolchain, fetch, build-suite, build-card, aa, noise, mutate, evaluate, manifest, annotate, vendoring, schemas, catalogue-check}` (exit 0 ok, 1 findings, 2 usage or contract, 3 BLOCKED). Options: `fetch CARD_ID...`, `build-card ID [--opt O0|O1|O2|O3|Os]`, `build-suite DIR`, `aa|noise [--suite S --version V | --card C --side old|new] [--opt ..]`, `mutate --suite S --operator OP --seed N [--version V]`, `evaluate [--labels --imports --symbols hidden|visible --engines --rz-diff --out]`, `manifest [--labels --out --corpus-id --tool-git --created]`, `annotate [--labels --log --out --engines --imports]`, `vendoring --threshold T --hub-max-lineages N [--bodies --out]`. All take `--store` (default `$PATCHTRACE_CALIB_ROOT/known-answer`).
- `python -m tools.calibration.tier_r.shard {plan, run-shard, merge}`; `plan [--seed --shards --engines --subset smoke|suites|cards|mutations|noise|full --seeds-per-operator --root --plan-out]`; `run-shard --shard N [--of --seed --plan-sha256 --cases --engines --subset --timeout] --out DIR [--plan FILE]`; `merge --in DIR [--plan FILE] --out DIR`.
- `python -m tools.calibration.ci_summary {summarize --shards DIR [--plan FILE] --out FILE, determinism DIR1 DIR2}`.
- `python -m tools.calibration.corpus {init, verify MANIFEST, fetch-plan, fetch, guard [--manifest --worktree]}`; `python tools/corpus_check.py {catalog FILE, suite DIR, all [ROOT]}`.
- `python -m tools.calibration.prereg [--file F] [--expect SHA | --qa docs/qa.md]` (exit 0 match or print, 1 mismatch, 2 nothing recorded).
- `python -m tools.calibration.vendoring_scan BODIES --threshold T --hub-max-lineages N`.
- After T-02: `python -m tools.calibration.train {run, shift, report}`; `run|shift` take exactly one of `--labels` (with `--outputs`), `--rows`, `--merge` (optional `--aggregate`), plus `--prereg FILE --out DIR [--tool-git --smoke --artifact]`; `report REPORT [--out FILE]`.
- Dispatch: `gh workflow run corpus-tier-r.yml --ref <branch> -f shards=N -f seed=N -f engines=rz-diff[,ghidriff,bindiff] -f subset=smoke|suites|cards|mutations|noise|full`; list `gh run list --workflow corpus-tier-r.yml`; fetch `gh run download <id> -n tier-r-aggregate`.
- Tier W (owner): runbook command in T-20.

## Appendix E. UNVERIFIED register (14)

U-1 Inputs of the two completed `workflow_dispatch` runs on main (38675568102, 38675570414), and whether a `cards` or `ghidriff` leg ever completed on a runner. U-2 Whether the 16 recipes build on an Actions runner (only libdeflate, stb and c-ares were built, locally, mingw-w64 gcc 13-win32; zlib via smoke). U-3 All runtime and runner-hour figures (estimates in `docs/plans/lbl-remaining-plan.md` section 3). U-4 Cause of the red `test_evaluate_with_imports_scores_and_exits_0`. U-5 Whether `tier_r/catalogue/**/*.json` needs an LF `.gitattributes` pin on Windows checkouts. U-6 Whether the manifest counts the `_template` suite as a lineage (the 41-lineage role count includes it). U-7 Whether a branch copy of the workflow can be dispatched while main holds a different file. U-8 The 33 CVE ids against CVE List V5 (`--cve-list` unimplemented; 2026 ids least checkable). U-9 `opt` availability on a Windows runner. U-10 Free-minute and Windows multiplier terms for this public repository. U-11 `train.py` on real Tier R data (only synthetic worlds have run). U-12 Recorded pin licence SHA-256 values against upstream today (not re-fetched). U-13 Lineage consequence of treating authored suites as adversarial (reading of the code, not a run). U-14 Whether libpng/zlib/zstd/brotli/Lua/Mbed TLS body overlap reaches the 15% merge threshold (no body records exist yet).
