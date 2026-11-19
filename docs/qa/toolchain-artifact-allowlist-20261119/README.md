# Required Windows toolchain report: CI assertion repair

Source change: `db7c3ffb6b6799bc4957b2f0ce6609de5b1c991c`, based on core
local `ac3a98150bd17bbbd973c7e7dcadb7edcf551934` (published #319 originally
`f6c4b084`). The unchanged failing test blob is identical on broad #318
`2e301a74649e59e27b19a83bc283d646109ccd09` and core #319.

The actual hosted [Linux full QA job](https://github.com/djshellshoxxx/patchtrace/actions/runs/44488945595/job/135439504114)
on #318 completed **1 failed, 25,705 passed, 60 skipped, 3 xfailed** in
2,633.42 seconds. The sole failure was
`test_ci_summary.py::test_artifacts_hold_only_labels_and_reports`: its expected
upload paths omitted the Windows toolchain JSON receipt introduced by the
prerequisite repair. This is a failed full run, not a full-suite pass. Its
unavailable live adapters remain explicitly blocked by that job's receipts.

The existing `known-answer-corpus.md` Windows prerequisite contract requires
the actual toolchain report alongside the shard JSON. The workflow produces it
with `python -m tools.calibration.tier_r toolchain`. Its actual Windows job
`135441373926` already completed 11 smoke cases with no failures or blocked
cases. The narrow test repair adds precisely
`shard-out/shard-*.json\nwindows-toolchain.json\n` to the existing exact upload
allowlist in place of the old single-line Windows shard path. All other allowed
paths remain exact. No binary upload, workflow step, smoke case, runtime source,
exception suppression or test skip is added.

The exact test reproduced locally before the change: **1 failed in 1.81 s**.
Afterward, `test_ci_summary.py`, `test_tier_r_windows_dependencies.py` and
`test_workflow_contract_dependencies.py` passed: **20 passed in 3.14 s**.
Focused Ruff and `git diff --check` passed. `evidence.zip` and `manifest.json`
retain the red/green output and JUnit. Fresh exact-head hosted checks remain
required after publication; the 20 local controls do not reclassify the earlier
full run or clear the separate strict security scan.
