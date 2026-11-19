# PW-01 resource-bounded full-file qualification

**Result: INCOMPLETE, with one preserved failure in a completed batch.**

- Source commit: `c023dec36a464c3e7e1a8689f52a22263f0c24c5`
- Source tree: `d390d0f2f77b34cdb0a265b9bfb33e06d4428e09`
- Detached worktree: `/workspace/scratch/e83fbf4505c3/qualification-pw01-batched-c023dec3`
- Interpreter: `/workspace/scratch/3a6632a6e5ff/venv/bin/python`
- Started: 2026-11-18T08:37:29.318804+00:00; finished: 2026-11-18T08:49:10.852713+00:00

## Coverage and method

All 845 tracked pytest-pattern files were enumerated from the configured `tests` path and verified against 
the filesystem inventory. Neither conftest adds collection exclusions. The fixed manifest divided the 
files into 12 sequential processes of 70–71 files; no parallel test process, test edit, file omission, 
filter, failure limit, or retry was added. Every file appeared in exactly one attempted batch.

Each command used the same interpreter, `PYTHONPATH=src`, `QT_QPA_PLATFORM=offscreen`, 
`python -m pytest -q`, and a separate JUnit output. `PYTHONUNBUFFERED=1` preserved progress before 
termination. Every batch has an exact argv/environment receipt and raw log. A 30-minute per-process 
limit was configured; no batch reached it.

4 batches covering 282 file arguments produced completed reports. 
8 batches covering 563 file arguments terminated with SIGKILL 
(`returncode=-9`, shell-equivalent exit 137), without JUnit. Execution of every test inside those 
terminated batches is unproven; their partial logs are preserved. This is not full-suite coverage.

## Batch results

| Batch | Files | Status | Exit | Seconds | JUnit outcomes |
|---|---:|---|---:|---:|---|
| batch-01 | 71 | PASS | 0 | 91.059 | 1101 passed, 0 failed, 0 errors, 1 skipped |
| batch-02 | 71 | FAIL | 1 | 65.054 | 1434 passed, 1 failed, 0 errors, 7 skipped |
| batch-03 | 71 | INCOMPLETE | 137 | 14.019 | No completed report |
| batch-04 | 71 | INCOMPLETE | 137 | 13.016 | No completed report |
| batch-05 | 71 | INCOMPLETE | 137 | 45.073 | No completed report |
| batch-06 | 70 | INCOMPLETE | 137 | 25.310 | No completed report |
| batch-07 | 70 | INCOMPLETE | 137 | 42.336 | No completed report |
| batch-08 | 70 | INCOMPLETE | 137 | 114.191 | No completed report |
| batch-09 | 70 | PASS | 0 | 99.204 | 1704 passed, 0 failed, 0 errors, 20 skipped |
| batch-10 | 70 | INCOMPLETE | 137 | 89.076 | No completed report |
| batch-11 | 70 | PASS | 0 | 68.038 | 1069 passed, 0 failed, 0 errors, 3 skipped |
| batch-12 | 70 | INCOMPLETE | 137 | 32.018 | No completed report |

**Completed-report subtotal only:** 5,340 reported test cases: 5,308 passed, 1 failed, 
0 errors, 31 skipped. No complete-suite total is available. Existing test-provided skips were 
retained; no extra skip rule was introduced.

## Preserved failure

`tests/test_binexport_isolation.py::test_run_process_memory_cap_is_enforced`, line 255, failed 
because its uncapped helper attempting six 64-MiB allocations (384 MiB) returned -9 with an 
empty log instead of returning 0 and printing `allocated`. This occurs before the capped-memory 
branch, so that branch was not reached. See `batch-02.log`, `batch-02.xml`, and `batch-02.json`.

The cause of the helper and pytest terminations is not established. Two separate observer 
snapshots reported 1,539,928 and 1,607,268 kB MemAvailable out of 10,206,472 kB MemTotal, with 
zero swap. Cgroup memory counters/limits and memory-pressure counters were unavailable in 
the observer environment. Those snapshots are not causal evidence.

## Other gates and integrity

- Repository Ruff (`python -m ruff check src tests tools`): PASS.
- KB schema check (`python tools/generate_kbc_schemas.py --check`): PASS.
- Whitespace check (`git diff --check`): PASS.
- Post-run worktree status: clean; HEAD and tree still match the exact source identifiers above.

Hosted whole-process QA and Qt-repeat remain required. This bounded attempt does not replace 
them or resolve the missing coverage. A focused check of the uncapped allocation prerequisite 
could help diagnose the known failed control; no such retry was performed.

## Evidence

`manifest.json` and `test-files.txt` fix the source, configuration, environment and file plan. 
`batch-NN.json` records each exact argv, exit, duration, observed main-process peak RSS, and 
log/JUnit hashes. Raw logs and all four completed JUnit reports are preserved. `summary.json` 
sets `totals` to null and stores only `observed_partial_totals`. Resource observations and 
the controller source are included. `evidence-manifest.json` hashes every evidence file.
