# Test fixture lifetime and plan-preview checks, 2026-11-19

This is a bounded test-only repair based on
`d7842532e0a19244c8e87bb333241c83b6ebff08`, the completion branch after the
acquisition-plan binding merge. Work took place in `/tmp/pt81-test-harness` on
`codex/patchtrace-test-harness-20261119-81e4`. The frozen diagnostic candidate,
production modules, and AF_UNIX test were not modified by this slice.

## Observed failures and repairs

| Test | Proven cause | Repair and retained assertion |
|---|---|---|
| `test_nway_recovery_copy_20261105.py::test_new_copy_descriptor_closed_on_setup_failure` (`fstat`, `fdopen`) | The test patches the shared `os` module for the entire fixture lifetime. With `tmp_path_retention_policy=failed`, pytest removes the passed test's temporary directory before restoring the monkeypatch. `shutil.rmtree` reaches the test's `os.open` replacement with `dir_fd`, causing a teardown `TypeError`. | Restrict both injected faults to `_keep_corrupt_copy` using `monkeypatch.context()`. Preserve the `PT-NWAY-STORAGE` exception, exactly one created descriptor, closed descriptor, and unchanged original bytes. |
| `test_report_export_backup.py::test_a_failed_backup_leaves_the_old_file_and_no_staging_debris` | The backup-refusal `os.open` replacement similarly intercepts pytest cleanup and rejects `dir_fd`. | End the fault patch immediately after the export operation. Preserve the typed `PT-EXPORT` refusal, original report bytes, and absence of staging debris. |
| `test_rules_matrix.py::test_digest_works_when_o_nonblock_is_absent` | Deleting shared `os.O_NONBLOCK` remains active during pytest cleanup; `shutil.rmtree` requires that attribute on this host. | Scope the deletion around the digest call and its existing exact hash/length assertion. The assertion still runs while the attribute is absent. |
| `test_research_qualification_perf_harness.py::test_plan_executes_nothing_and_names_only_env_names` | The blanket `"-c" not in json.dumps(out)` assertion also matches the permitted `out_dir`, including the diagnostic runner's `pt81-candidate` path. | Check the exact returned output directory separately, then exclude only that field from the command-switch nondisclosure check. Exercise ordinary and explicitly `-c`-containing directory names. Retain the no-execution marker and executable-name checks; add argument-count, unique payload, exact allowed environment names, and environment-value nondisclosure checks. |

These changes do not broaden the injected failures to accommodate cleanup. They
restore shared process state before unrelated fixture teardown. The command
preview test still rejects a disclosed command switch anywhere outside the
explicitly allowed output-directory field, and rejects its unique code payload
or authored environment values anywhere in the preview.

## Evidence

The diagnostic partition receipts are preserved unchanged in the workspace
`verification` directory. They remain failed observations after these repairs.

| Original partition | Recorded result |
|---|---|
| 27 | 304 passed, 2 teardown errors, 1 warning in 14.08 s |
| 32 | 441 passed, 1 teardown error in 12.53 s |
| 33 | 492 passed, 3 skipped, 1 failed in 19.15 s |
| 34 | 1,076 passed, 1 skipped, 1 teardown error in 84.60 s |

The original diagnostic run stopped after partition 34 of 54 at its disk-reserve
boundary. This slice does not turn that interrupted run into an aggregate pass.
The separate AF_UNIX constructor refusal remains an environment limitation to
check on a capable runner; no assertion or production guard for that case changed.

Controlled replays used the isolated checkout and Python 3.12.14 with pytest
9.2.0. An isolated `-I` import check confirmed that `patchtrace` and the N-way
module came from `/tmp/pt81-test-harness/src`; dependency checks passed. Before
the all-retention replay, the private venv was recreated with symlinks to the same
interpreter to recover disk space. Its source and read-only dependency paths,
versions, import checks, and dependency checks stayed unchanged.

| Replay | Result | Receipt prefix under `verification` |
|---|---|---|
| Original N-way descriptor cases and report refusal, failed retention | 3 passed, 3 teardown errors in 1.61 s | `test-harness-baseline` |
| Original plan-preview test, output path containing `-c` | 1 failed in 1.20 s | `test-harness-plan-baseline` |
| Original absent-`O_NONBLOCK` test, failed retention | 1 passed, 1 teardown error in 2.92 s | `test-harness-rules-baseline` |
| All four repaired test files, failed retention | 85 passed, 1 skipped in 11.99 s | `test-harness-final-failed` |
| All four repaired test files, all retention | 85 passed, 1 skipped in 8.70 s | `test-harness-final-all` |

Each replay has its original `.log` and `.xml`. The one skip in each final replay
is `test_resource_peaks_are_measured`: optional `psutil` is absent. No new skip or
xfail was added. Ruff on the four changed files and `git diff --check` passed;
receipts are `test-harness-ruff.log` and `test-harness-diff-check.log`.
`test-harness-original-receipts.json` records original file/partition hashes;
the `partition27-peer-*` and `partition32-peer-original.*` through
`partition34-peer-original.*` receipts retain the initial diagnostic evidence.

## Reproduction

Run from the isolated checkout with its interpreter, substituting `all` for
`failed` for the second retention policy:

```bash
PYTHONDONTWRITEBYTECODE=1 QT_QPA_PLATFORM=offscreen \
  /tmp/pt81-test-harness-venv/bin/python -B -m pytest -q -p no:cacheprovider \
  tests/test_nway_recovery_copy_20261105.py \
  tests/test_report_export_backup.py \
  tests/test_research_qualification_perf_harness.py \
  tests/test_rules_matrix.py \
  --basetemp=/tmp/pt81-harness-review-failed \
  -o tmp_path_retention_policy=failed \
  --junitxml=/workspace/scratch/81e4938f4a3a/verification/test-harness-review-failed.xml
```

The completed replays qualify these four test modules under both cleanup
policies. Full-suite continuation, remote CI, Windows execution, and main-branch
integration have separate evidence and are not claimed by this record.

## Symbol scanner follow-up

The unchanged candidate's continuation group 40 found the same fixture-lifetime
problem in `test_symbols_staging.py::test_cancel_during_large_nonmatching_folder_scan_stops_and_closes_iterator`.
The temporary `os.scandir` replacement expected the authored PDB directory but
intercepted pytest's later cleanup call with an integer directory descriptor.
The original group recorded 519 passed, 8 skipped and one teardown error in
14.51 seconds. A single-case replay reproduced 1 passed and 1 teardown error in
1.14 seconds before the correction.

The fault patch now ends immediately after the staged-symbol operation. Its
`PT-CANCEL`, exact 12-entry cancellation, closed-iterator and absent-store
assertions are unchanged. The complete staging and local-symbol backend files
pass **30 tests in 2.42 seconds** with immediate failed-only cleanup. Production
symbol handling and the frozen diagnostic candidate were not modified. Receipts
are `verification/symbol-fixture-{red,green}.{log,xml}`.
