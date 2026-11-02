# Shared synthetic rz-diff fixture repair, 2026-11-01

The shared synthetic positive fixtures used rz-diff version 0.9.1, which the new orientation quarantine correctly refuses. At exact base `d317c7941429fa189dbcff88749935a2b885cd71`, the unchanged worker tests reproduced four failures: one expected ten rows but obtained nine, and three expected complete results but obtained partial results. The red worker/quarantine selection had 4 failed and 88 passed in 1.41 seconds. A second red consumer selection retained one pilot contradiction failure and one CLI fixture error (the quarantined fixture made its run return the partial-result exit code). These are retained in `red.log`, `red-junit.xml`, and `red-consumers.log`.

Commit `91ea120785a380e9d2a8acfb14f05db56a298899`, tree `13f0613163ff033f6d70364d2f9c97d2c235c701`, changes only three test files:

- `tests/unified_s0_fixtures.py`: row and set defaults become synthetic version 0.9.0, with an explicit statement that this exercises the existing parser-family policy and does not establish native compatibility or side ownership.
- `tests/test_rzdiff_orientation_20261101.py`: all three historical negative set constructions explicitly use 0.9.1 on both the set and every row.
- `tests/test_unified_cli_show.py`: the two displayed-version expectations track the synthetic 0.9.0 input.

The worker assertions, root-owned scoring tests, source/native gates, thresholds, version pins, and production code are unchanged. No specification contract changes were needed: SPEC-31 `06-adapters.md` section 4 explicitly quarantines 0.9.1 while retaining the existing policy for other versions without claiming their native compatibility. The original four worker failures pass after this fixture-only correction; the expected counts and statuses have not been weakened.

Validation used `/workspace/scratch/142cb233d750/full-venv/bin/python` with `PYTHONPATH=src` from the isolated `wt-rz-fixtures` worktree and `QT_QPA_PLATFORM=offscreen`. `environment.json` records the verified source import path. The prior full-verification environment was not reinstalled.

- Worker, pipeline, source, fusion, facts, read-model, CLI, source-identity, quarantine, pilot, report, reconciliation and evidence tests: **634 passed in 17.56 seconds** (`green.log`, `green-junit.xml`).
- Remaining indirect shared-fixture consumers, including wire/refacts/UI/pilot CLI controls: **227 passed, 2 skipped in 28.22 seconds** (`indirect.log`, `indirect-junit.xml`). The two skips are `test_unified_live_pairs_r1.py::test_workflow_restores_archived_executables_after_python_zip_extraction[pairs|mutants]`, because `yaml` is unavailable. They are unverified, not passes.
- Scoped Ruff and `git diff --check`: passed.
- `check_scope.py` / `scope-controls.log`: negative-control AST is identical except explicit version arguments; original worker and scoring files are byte-identical; CLI AST differs only in displayed version labels; all three negative normalized sets are byte-identical to their pre-change construction; forward/reverse positive row and set versions agree.
- Independent reviewer `/root/cancel_fix`: **129 passed in 1.69 seconds**, scoped Ruff and diff check passed; original assertion semantics and all explicit quarantine inputs independently inspected. Final SHA-bound review: `reconciliation/rzdiff-shared-fixtures-independent-review-20261101.json`; all three tested file hashes match the clean commit.

These are bounded synthetic regression checks. No full-suite, performance, native rz-diff, target execution, or remote mutation was performed for this patch. This does not qualify native 0.9.0 or undo the 0.9.1 quarantine.
