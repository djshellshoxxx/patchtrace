# PatchTrace handoff — LBL-30 preregistration and Tier R integration (2026-10-16)

This is a **persistent, evidence-based handoff** for the next worker. Read `AGENTS.md` and
`CLAUDE.md` first, then `docs/handoff/lbl31-output-persistence-chatgpt-20261015.md`,
`docs/handoff/label-training.md`, `docs/plans/lbl-remaining-plan.md`,
`docs/specs/program-e/LBL-DATA-integration-plan.md`, and
`docs/specs/program-e/LBL-LOCK-CLI.md`. Check live branch heads before any write.
Main is **not** an assumed integration base.

## Repository and parallel-agent state

- Authoritative integration target at review: `claude/instance-d-gui`, draft PR #64,
  base SHA `53f366e8b50ac60a95bdb3734b815daac82cd63d`. Do not write to `claude/*`.
- LBL-31: PR #78, branch `chatgpt/lbl31-output-persistence-20261015`. It was at
  `5f30a79119b59e337b11a21d81b5e3b12d2bd92a` when this branch was created.
  **Parallel activity:** PR #78 advanced to `0fbe5a5a68f9aae7556ce765632ad2452e711f4d`
  during this session, adding COFF string-symbol masking and related tests. Re-read head.
- This worker owns PR #85, branch `chatgpt/lbl30-prereg-guard-20261016`, created
  from the original PR #78 head. Its base is `claude/instance-d-gui`.
  PR #85 includes inherited unmerged LBL-31 commits; re-sync *after* PR #78 integrates
  and verify that only the intended LBL-30 diff remains. Do not rebase a shared branch.
- Two **other** LBL-32 worker branches appeared while checking branch ownership:
  `chatgpt/lbl32-card-controls-20261016` (`0bb6290`) and
  `chatgpt/lbl32-recipe-aa-noise-20261016` (`c83c92d`).
  Do not repeat or overwrite their A/A and noise work; compare and coordinate their PRs.

## Current-work completion register

| ID | Work | Evidence and location | Status / next gate |
| --- | --- | --- | --- |
| LBL-31 | Capped per-pair engine-output persistence and sharded training artifact transfer | PR #78; sharded CI run 38883698797 current original head passed | Implemented; Windows full QA **failed**, not merged |
| LBL-30a | Protocol exact LF SHA and QA receipt matching | `tools/calibration/prereg_gate.py`; direct CLI in `train.py` | Implemented; `tests/test_train_prereg_gate.py` pending live CI |
| LBL-30b | Draft never presented as preregistered | `--unlocked-prereg` passes no prereg SHA to training; separate summary marker | Implemented; test and CI acceptance pending |
| LBL-30c | Exclusive final looked-once gate and owner sign-off | `--final-locked-test --locked-form --corpus-dir` uses `run_locked_test` receipt before `_inputs` | Implemented; dry synthetic tests pending CI; actual final run **not performed** |
| LBL-30d | Disallow `--locked-form` without receipt | `train._run` rejects bare `--locked-form` | Implemented; pending tests |
| LBL-30 docs | Spec, module index, QA and todo entries | `docs/specs/program-e/LBL-LOCK-CLI.md`, `docs/{modules,qa}.md`, `tasks/todo.md` | Committed; no passing CI claim |
| LBL-32 | Both recipe-card sides, A/A and noise | Other agents' two branches named above | In progress elsewhere; ownership reserved |
| LBL-33 | New pinned C recipes, license verification and live 3-pair admission | `docs/plans/lbl-remaining-plan.md` section 4 | Open; do not admit without runner proof |
| LBL-34 | Freeze exact C9 protocol SHA and execute true locked holdout | QA row C9-PREREG-v1 pending owner approval | **Not done** |
| Unified live G-U1..G-U8 | Real gate run and report | `docs/handoff/unified-engine.md`, PR #64 | Pending live runners and dependencies; no real gate outcome |

## Windows QA blocker on PR #78

The original current-head QA workflow run 38883698492 reported:
- Ubuntu full QA: **success**.
- Windows Qt gate (5): **success**.
- Windows full suite: **failure**; `17,891 passed, 81 skipped, 6 xfailed, 2 failed`
  in 53:08. Failing cases:
  1. `tests/test_mutations_more.py::test_masked_body_rule_rejects_address_only_changes_and_records_them[string-literal-shout]`;
     Clang 20 emits quoted COFF MSVC relocation references like `"??_C@...hello"`:
     the unquoted RIP symbol regex leaked address-only changes into the masked body.
     The other PR #78 worker pushed a targeted normalization and test in three commits,
     moving head to `0fbe5a5`. Rerun **not yet verified**.
  2. `tests/test_unified_read_model.py::test_filter_and_sort_budget_at_100000_rows`;
     default sort took 0.8823358 seconds against 0.75-second 5x-slack gate; column sorts
     were 0.0699 and 0.0756 seconds. Optimize `read_model.sort_rows` without dropping
     None-last and stable-tie behavior, test across OS; do not merely inflate the threshold.
- Qt 20x Ubuntu gate was still running at last check. Do not merge PR #78 until Windows
  and all required checks are green. Artifact report of run 38883698797 only proves Tier R sharding.

## LBL-30 API and safety decisions

`PG.select(path, qa_path, allow_unlocked, require_signoff)` returns a frozen `Selection`.
A SHA enters the model train key only when matched to the explicit `C9-PREREG-v1`
record. A draft rehearsal's SHA is *only* printed under `unlocked_rehearsal`.
Final mode requires a manual `owner approval recorded` (or explicit accepted synonym)
on that matching QA row. The marker is NOT cryptographically authenticated.
Final mode prohibits a repository-local corpus root and smoke config, and refuses
`shift`, unlocked mode, bare `--locked-form`, repeat runs and missing protocol.

`run_locked_test` exclusively writes `locked-test-<SHA>.lock` BEFORE opening the
evaluation corpus. A failed callback also consumes the look. It is deliberate that
a crash yields no report and still spends the SHA. Do not invoke final mode
on real data until the owner freezes the prereg protocol and explicitly approves it.
No target binary was executed, and no real locked-test artifact or receipt was created.

## Next worker actions

1. Read CI **for the latest head** of PR #85. Run/inspect the targeted
   `tests/test_train_prereg_gate.py` first, then `tests/test_train_pipeline.py`,
   `tests/test_train_lbl26.py`, `tests/test_prereg_tools.py`, Ruff and full Windows/Ubuntu QA.
   Fix actual failures with another red test; do not mark TODO tests passed without logs.
2. Verify `docs/specs/program-e/LBL-LOCK-CLI.md` matches implementation, especially
   `--locked-form` receipt requirement and owner-signoff language. Ensure no synthetic
   approval row is ever written into the production QA lock record.
3. Confirm no concurrent worker has taken the same files. **Do not merge PR #85 while PR #78
   or base integration CI fails**. Reconcile inherited PR #78 changes after it merges,
   keeping unrelated agent work intact. Use merge commits rather than rewriting shared history.
4. Address and verify the two Windows PR #78 gate failures on a **separately owned**
   branch/PR if the PR #78 owner has not fixed them; inspect the new branch head first.
5. Only after C9 prereg is actually locked and all labels are audited: perform exactly
   one owner-approved final run via the single-use CLI. Never try a second look or
   claim numeric Windows-system-binary accuracy from Tier R synthetic results.

## Tooling limitation

A connected GitHub session enabled repository read/write and workflow-log inspection,
but the working container had no DNS access to raw.githubusercontent.com; no local
checkout or executable end-to-end Tier R suite was available in this session.
Test-first commits are present but the red and green tests were **not run locally**.
Statements above distinguish committed implementation from live verification.
