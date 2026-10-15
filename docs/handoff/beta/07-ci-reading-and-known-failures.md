# CI: how to read it, and every failure we hit on the way to green (with real examples)

Audience: an LLM (or person) with repository access and no memory of this project. Written 2026-10-15 from the
session that took PR #64 (branch `claude/instance-d-gui`) from "CI never finishes" to "CI finishes with a short list of
failures". Everything below was observed in real GitHub Actions logs; the quoted lines are real. Where a fix is named,
the commit is named so you can read the diff.

## 0. Glossary

- **qa**: the full test suite, one job per OS (`qa (ubuntu-latest)`, `qa (windows-latest)`) in
  `.github/workflows/qa-windows.yml`. Runs `python -m pytest -q --junitxml=qa-results.xml`, then `ruff check src tests tools`,
  then BinExport memory-cap tools, then `tools/build_windows.py` (see the workflow for the exact order).
- **qt-gate**: the same GUI test files repeated in ONE pytest session (`tools/qt_gate.py --repeat N`; 20 on Linux, 5 on
  Windows) to expose teardown aborts and thread leaks.
- **head**: the commit a CI run was started for. Notifications carry a `head_sha`. Only the newest head matters.
- **cancel-in-progress**: a workflow `concurrency` setting. A newer push CANCELS the older run of that workflow. It is
  why a push made while `qa` is running throws away the run.
- **junit**: `qa-results.xml`, uploaded as an artifact; it is tiny (160 bytes) when the job was cancelled.
- **faulthandler dump**: the all-thread Python stack that `PYTHONFAULTHANDLER=1` prints when the process dies or is killed.

## 1. Golden rules for working with this CI (learned the hard way)

1. **Never push while `qa` or `qt-gate` is running on the head you care about**, unless you must. Every workflow that
   matters has `concurrency: ... cancel-in-progress: true`. In this project's history we threw away several hour-long
   runs by pushing a docs-only commit. If a stop hook demands a push, push, but expect the restart.
2. **Judge only the newest head.** GitHub keeps sending `check_suite.completed` notices for old heads
   (`head_sha` that is not your branch tip). Compare with `git rev-parse HEAD` / `git rev-parse origin/<branch>`.
   A "no check suite failed" notice for an old head tells you nothing.
3. **A job that ends exactly at its `timeout-minutes` is hung, not slow.** Compare the job's `started_at` and
   `completed_at` from `get_check_runs`; a duration of 60:xx or 120:xx minutes with `conclusion: cancelled` is a timeout.
   Then read the end of the log for the LAST progress line (see section 3.1).
4. **The failure list is only printed at the end of the pytest run** (`short test summary info`). `-q` shows dots, so a
   hang hides the names of the earlier `F` marks. Fix the hang first, then read the list.
5. **This development host runs tests as root; the CI runners do not.** Permission-based tests (read-only dirs,
   `chmod`) behave differently. Several real bugs only appeared in CI for this reason (section 3.4).
6. **Windows differs**: no execute bit, `\\` path separator, `ZipInfo` rewrites names, coarse timers (about 16 ms),
   `clang` defaults to LLP64 (`size_t` is `unsigned long long`), checkout may convert line endings, and open file handles
   block deletes.
7. **Read logs from the bottom up.** The pytest summary is within the last ~120 lines of the job log. With the GitHub
   MCP tool use `get_job_logs` with `tail_lines` of 60 first, then 120-300 if the summary is not there.

## 2. The jobs and what green looks like

| Job (check name) | What it proves | Typical duration | Green looks like |
|---|---|---|---|
| `linux`, `windows` (core build) | package builds and quick tests | 5-12 min | `conclusion: success` |
| `qa (ubuntu-latest)` | whole suite on Linux | about 21-28 min | last line `NNNNN passed, NN skipped, N xfailed` with no `failed` |
| `qa (windows-latest)` | whole suite on Windows | about 50-62 min | same; then the BinExport memory-cap step |
| `qt-gate (windows-latest, 5)` | GUI tests x5 in one session | about 40-46 min | `9129 passed` style line, no `ABORT` |
| `qt-gate (ubuntu-latest, 20)` | GUI tests x20 in one session | not yet observed to completion at the time of writing; allow up to the 120-min timeout | no `qt_gate: ABORT` line |
| `native (...)` x5, `shard 0/1 of 2`, `merge`, `plan` | Windows-native and Tier R sharded jobs | 3-8 min | success |
| `live rz-diff`, `live BinDiff`, `live intel tools`, `probe` | live tool lanes | 1-3 min | success |
| `msvc cl advisory (windows-2022)`, `live build environment`, `release-gate`, `linux-package`, `linux-smoke`, `release` | optional or release-only | skipped on PRs | `skipped` is normal |

A fully green PR means: `qa` both OS, `qt-gate` both OS, and every non-skipped job success, on the newest head.

## 3. Catalogue of failures, with the real evidence and the fix

### 3.1 The two-hour hang at 83 percent (a modal dialog under the offscreen platform)

Symptom: `qa` on both OSes sat for 60 then 120 minutes and was cancelled. The last progress lines:

```
2026-10-15T15:23:35Z ....x.....F............................................................. [ 83%]
2026-10-15T17:07:44Z ##[error]The operation was canceled.
```

The Windows log additionally printed the faulthandler dump at cancel time, whose first frames named the test:

```
Thread 0x000007d4 (most recent call first):
  File "...\src\patchtrace\ui.py", line 1880 in show_error
  File "...\src\patchtrace\ui.py", line 1871 in _guard
  File "...\src\patchtrace\ui.py", line 2855 in preview_interpretation
  File "...\tests\test_ui.py", line 240 in test_context_budget_is_used_in_preview
```

Cause: the test's wrapper `capture(project, ids, max_chars)` did not accept the new `notes` keyword that `build_context`
had gained, so the call raised `TypeError`; `ui.py` catches exceptions in `_guard`, calls `show_error`, which runs
`QMessageBox.exec()`. With `QT_QPA_PLATFORM=offscreen` nobody can click it, so the event loop blocks forever.

How to find such a hang locally: run the suspect test with a plugin that turns the dialog into an exception:

```python
# boxplug.py  (run: PYTHONPATH=src:. python -m pytest -p boxplug <test>)
import pytest
from PySide6.QtWidgets import QMessageBox
@pytest.fixture(autouse=True)
def _no_modal(monkeypatch):
    monkeypatch.setattr(QMessageBox, 'exec', lambda self: (_ for _ in ()).throw(RuntimeError('MODAL: ' + self.text())))
```

It printed `MODAL: ...capture() got an unexpected keyword argument 'notes'`, which is the real error.

Fix (commit `f030ed3`): the wrapper takes `**kwargs`; and `tests/conftest.py` now has an autouse fixture
`_no_blocking_modal_dialogs` that keeps real dialogs but rejects any `QMessageBox.exec()` left unanswered for 30 s and fails
the test that opened it (`MODAL_WATCHDOG_MS = 30_000`). Success looks like: the same test run finishes in 1-2 s and the whole
`qa` finishes in about 21 minutes.

Lesson: when the job ends at exactly the timeout, find the LAST test that ran, not the first failure.

### 3.2 Segfault in `qt-gate` (garbage collection on the GUI thread)

Symptom (Linux, `qt-gate (ubuntu-latest, 20)`):

```
Fatal Python error: Segmentation fault
Current thread 0x00007f209f997b80 (most recent call first):
  Garbage-collecting
  File ".../src/patchtrace/gui/qt/metrics.py", line 40 in eventFilter
...
qt_gate: ABORT, pytest died with status -11 (see the faulthandler dump above)
```

Cause (best evidence, not proven): cyclic garbage holding Shiboken wrappers of widgets from earlier tests was collected on
the GUI thread while a later test's worker thread ran. The test that was running passed on its own (3 of 3 runs), so the
trigger was test order, not the test.

Fix (commit `85f1b9e`): an autouse fixture `_collect_qt_garbage` in `tests/conftest.py` calls `gc.collect()` after every
test that uses `qtbot`. Evidence it helped: after the fix the Windows `qt-gate` completed the full suite
(`9129 passed`) on three consecutive heads with no abort. The Linux 20-repeat result was still pending when this was written;
if it aborts again, run with `QT_FATAL_WARNINGS=1` and read which thread is "Current thread".

Related earlier fixes: `src/patchtrace/gui/qt/tasks.py` frees task callback captures on the GUI thread
(`_Task.release()`, commit `0c62189`); the 100-thread teardown stress test was cut to 32 threads
(`test_shutdown_with_many_blocked_tasks_joins_every_worker`) because `Thread.start` itself segfaulted on the runner.

### 3.3 `qa` timeouts added by another contributor (60 minutes was too short)

PR #74 (Codex audit-2) added `timeout-minutes: 60` to every job. The suite had grown past that on Windows (about 50-62 min).
Evidence: `qa (windows-latest)` finished in 1:02:34 on one run. Fix (commit `a2740e5`): `qa` and `qt-gate` use 120. The
test `tests/test_codex_pkg_workflows.py::test_every_job_has_timeout` only requires a positive integer.

### 3.4 Failures that only appear as a non-root user or on Windows

Examples with the real messages and fixes:

| Test | Real message | Cause | Fix |
|---|---|---|---|
| `tests/test_acquisition_quarantine.py::test_remove_staging_tolerates_a_locked_file` | `PermissionError: [Errno 13] Permission denied: '.../b.bin'` (Linux CI) | `remove_staging` chmod'ed a DIRECTORY to `S_IWRITE|S_IREAD`, removing its search bit | `stat.S_IRWXU` for directories (commit `78ded8f`) |
| `tests/test_enrichment_cache.py::test_crash_while_writing_the_owner_leaves_no_torn_file[lease]` (Windows) | leftover `...lease-<id>.new-<id>` file | `_write_file` leaked its fd when `os.fdopen` failed; Windows cannot delete an open file | close the fd in an `except BaseException` (commit `0268517`) |
| `tests/test_build_backend_bundle.py::*[linux]` x12 (Windows) | `PT-BUNDLE-MODE: 2 file(s) lost the execute bit (pattern 'jdk/bin/*'): ['jdk/bin/java', 'jdk/bin/javac']` | modes were derived from NTFS `stat`, which has no execute bit | on `os.name == 'nt'` treat files under `bin/` as executable in `reduce_jdk` |
| `tests/test_mutations_more.py::*` x15 (Windows clang 20) | `m.c:1:23: error: typedef redefinition with different types ('unsigned long' vs 'unsigned long long')` | test code declared `typedef unsigned long size_t;` and clang on Windows has LLP64 | `typedef __SIZE_TYPE__ size_t;` |
| `tests/test_prereg_tools.py::test_repo_prereg_file_is_lf` (Windows) | `docs\plans\c9-preregistration-v1.md: contains CR bytes; the locked hash is over LF bytes (check .gitattributes)` | git converted line endings on checkout | `.gitattributes`: `docs/plans/c9-preregistration-v1.md text eol=lf` |
| `tests/stress/test_fuzz_archives.py::...[backslash-name]` (Windows) | `Failed: DID NOT RAISE OfflineBundleError` | `zipfile` rewrites `os.sep` to `/` when reading a name on Windows, so the hostile name never reaches the inspector | case is skipped on Windows only, with the reason in `BACKSLASH_WINDOWS`; it still runs on POSIX. This is a platform property, not a pass |
| `tests/test_gui_tasks.py::test_shutdown_with_a_hung_worker_returns_in_time_and_names_it` (Windows) | `(1604.671 - 1604.484) >= 0.2` false | `Thread.join(0.2)` returned about 13 ms early (timer granularity) | tolerance `>= 0.15` |
| `tests/test_mutations_opt.py::test_real_opt_or_blocked` (Windows) | `Failed: DID NOT RAISE Blocked` | the runner has `clang` but no `opt`; emitting IR needs only clang | only expect `Blocked` from `emit_opt_input` when `clang` is missing |

How to reproduce the non-root class here: copy the checkout and run `su nobody -s /bin/bash -c "..."`; make the path
traversable (`chmod a+x` on each parent). Permissions reset between tool calls on some hosts, so do it in one command.

### 3.5 Stale-expectation failures after features merged (Linux `qa`, 22 failures at first)

These are NOT product bugs; the tests described a smaller codebase. Pattern: a purity or inventory test enumerates files
or imports. Fixes (commit `78ded8f`):

- `tests/test_fabric_contracts.py::test_package_imports_no_qt_io_or_other_feature`: the fabric package gained `panel.py`
  and `related.py`. Added `PANEL_LAYER` with the GUI modules they may import.
- `tests/test_kbc_contracts.py` (4 params), `tests/test_kev_boundaries.py[panel]`, `tests/test_rules_candidates.py`,
  `tests/test_rules_cli.py`, `tests/test_rules_contracts.py`: panel/Qt modules (`panel.py`, `panel_qt.py`, `panel_state.py`,
  `tooltip_entries.py`, `qt_panel.py`) are exempted by name, and nothing else.
- `tests/test_spec_registry.py`: three new spec files were not cited by path in `docs/specs/REGISTRY.md`. Add a row for every
  new spec file.
- `tests/test_fabric_contracts.py::test_no_fabric_file_hides_an_invisible_character`: `tests/test_fabric_adversarial.py` had
  literal U+202E etc. Replaced with `\\u202e` escapes. Rule: never type invisible characters.
- `tests/stress/test_gui_stress_docks.py`: asserted exactly five docks; the manifest now builds thirteen. Asserts the five core docks are present.
- `tests/test_unified_live_tool.py`: the concurrency group used `github.event_name`, which the test forbids ("workflow is
  free of event data"). The group is now `${{ github.workflow }}-${{ github.ref }}` in `live-unified.yml`.
- `tests/test_unified_corpus_catalogue.py`: the allowed licence set gained `BSD-3-Clause WITH PCRE2-exception`.
- `tests/test_search_cli.py::test_anchors_from_is_a_capability_error_until_s10`: the search CLI silently ignored
  `--anchors-from` once `patchtrace.search.anchors` existed. The CLI now raises `PT-SEARCH-CAPABILITY` until the verb is wired.
- `tests/test_intel_cli.py`: after the QA-CLI-1 fix a usage error in `--json` mode prints exactly one failed JSON document; the test expected empty stdout.

### 3.6 Test-order pollution of the global tooltip registry

Symptom: `tests/test_tooltips.py::test_every_registry_id_is_applied_somewhere` failed with ids such as
`['angry.action', 'angry.dock', 'boom.action', ...]` or `['related.action', 'related.detail', ...]`, but passed when the file
ran alone. Cause: fake panels (stress tests) and the Related controller register tips globally; whether they exist when
the test runs depends on order. Fixes: stress modules import the `private_tooltip_registry` autouse fixture from
`tests/host_support.py` (it snapshots `tooltips.REGISTRY` and `TEMPLATES` with `monkeypatch`); the tooltip test exempts
`related.*` until the Related panel ships in the manifest. Rule: any test that registers tooltips must use that fixture.

### 3.7 Merge conflicts GitHub does not tell you about

When `main` moves and conflicts with the PR, GitHub builds NO merge ref, so the PR head gets ZERO check runs
(`get_check_runs` returned `total_count: 0`) and `mergeable_state` is `dirty`. Fix: `git fetch origin main`,
`git merge origin/main`, resolve (here: `tests/test_codex_pkg_packaging.py` and `tests/test_codex_pkg_workflows.py`, where
`main` had removed `xfail` markers, so take main's version with `git checkout --theirs`), commit, push.

### 3.8 The Ghidriff source tarball pin mismatch (bundle)

Real log:

```
error: PT-BUNDLE-PIN-MISMATCH: ghidriff.source_tarball: rebuilt 7086648 bytes sha256 8f96e687c72ae191def725e1753e3701be74bb80d30f5a29f7294717322802bc, pinned 7086648 bytes sha256 613449a2743e50a11c96b8a6cf6856095816cfece77a021c49cac6e4fe4fe87f
git version 2.55.0; python 3.12.15
ghidriff-4f5d895 n=1 951b5414c31904b9
...
ghidriff-4f5d895/www n=86 684b1390386f979e
```

Same size, different hash, and the per-directory member digests printed by the diagnostic equalled the local ones: the
CONTENT is identical, only the tar/gzip byte layout differs (runner git 2.55 / zlib vs git 2.43 locally). Fix (owner
approved option 1, commit `7c1f5a2`): the pin keeps `sha256` and `size` and gains `content_sha256` (sorted name/kind/exec-bit/
link/body-hash rows); `rebuild_ghidriff_tarball` accepts the rebuild when the content digest matches; a changed file or a wrong
digest still fails. Not yet proven on a runner at the time of writing: re-run the bundle build workflow and read the log.

### 3.9 Smaller recurring traps

- `test_cli_seam_budget` (tests/test_cli_registry.py, `CLI_BASELINE_LINES`) fails when `src/patchtrace/cli.py` grows. Bump the
  baseline only for real fixes and say why in the comment next to it.
- The SEC-1 hash check: Tier R tests that feed placeholder image bytes must use labels whose `sha256`/`debug_sha256` equal the
  hash of those bytes (`_with_real_hashes` in `tests/test_tier_r_eval_engines.py`); otherwise the engine run is `failed`.
- `from conftest import ...` collides between `tests/conftest.py` and `tests/stress/conftest.py`; shared helpers live in
  importable modules (`tests/live_status.py`, `tests/host_support.py`).
- Tests that need tools (`clang`, `opt`, `mingw`, `cl`) are `BLOCKED`/skipped on hosts without them; the end of the pytest
  output lists `LIVE ACCEPTANCE BLOCKED: ...` lines. Those are evidence gaps to report, not passes.
- Never apply the "keep both sides" regex used for docs conflicts to code or JSON; it once broke `tools/backend_pin.json`.
- `ruff check src tests tools` locally may report import-order (I001) noise that CI's pinned ruff does not; `origin/main` itself
  has such noise. Do not mass-reformat unrelated files.

## 4. A repeatable loop for "make CI green"

1. `git fetch origin && git status -sb`; confirm no merge conflict with `origin/main` (section 3.7).
2. Run the focused tests for the files you changed (commands in each feature file). Run `ruff check <changed files>`.
3. Push ONCE. Do not push again until the newest head's `qa` and `qt-gate` report.
4. Poll `get_check_runs` (PR #64) until `qa` completes; read the summary from the bottom of the log (section 1.7).
5. Group the failures by cause (sections 3.1-3.6), fix all groups, push once.
6. When all non-skipped jobs are green on the newest head and `mergeable_state` is clean: mark the PR ready, squash-merge with a
   message that does NOT contain `[skip ci]`, then notify the other instances (see `docs/plans/multi-instance-coordination.md`).

## 5. Effort and cost

Reading CI and fixing stale tests is Sonnet-class work, S-M size, mostly bounded by runner wall-clock (Linux `qa` about 21-28 min;
Windows `qa` about 50-62 min; `qt-gate` 40+ min). Do not pay for an expensive model to read logs; use the cheapest model that
can follow the log-reading rules in section 1.
