# N-way recovery timestamp compatibility — 2026-11-06

Base: frozen #205 `f33e2a0aaa3399644367f2419fee21cfe2e8702b`. Isolated branch
`repair/nway-windows-recovery-20261106`; no original qualification worktree,
process, branch or log was changed. Scope is `nway/series.py` recovery-file
validation, its focused controls and the SPEC-09b clarification. No model,
schema, dependency, CLI contract, native comparator or input execution changes.

## Hosted failure and pinned source evidence

The [#205 Windows QA job](https://github.com/djshellshoxxx/patchtrace/actions/runs/42122458590/job/127578061546)
used CPython **3.12.10**. Its summary was 19,660 passed, six failed, 89 skipped,
five xfailed. Five failures were in recovery-copy/series-tolerance tests; the
sixth was the separately owned crash-test `park(..., created=...)` double.
The recovery errors occurred even for byte-identical pre-existing copies and
ordinary damaged files. The replaced-copy test found no recovery path at all,
consistent with refusal before copy creation.

Official CPython source was fetched at **v3.12.10**, the runner's actual version:

| Source | Git blob | Relevant behavior |
| --- | --- | --- |
| [Modules/posixmodule.c](https://github.com/python/cpython/blob/v3.12.10/Modules/posixmodule.c) | `c21c6f06c729de2ac1a4598180a394261c86e53b` | `win32_xstat` copies `st_birthtime` into `st_ctime`; `os_fstat_impl` returns its descriptor result without that copy. |
| [Python/fileutils.c](https://github.com/python/cpython/blob/v3.12.10/Python/fileutils.c) | `c7521751cd26d14ce41b9ea0f93b95e27221f8a7` | `_Py_fstat_noraise` calls `_Py_attribute_data_to_stat`, which sets `st_ctime` from `FILE_BASIC_INFO.ChangeTime` and keeps creation time in `st_birthtime`. |

PatchTrace compared the entire pathname and descriptor tuples, including
`st_ctime_ns`. The two APIs can therefore disagree on an unchanged Windows file.
A real-file Linux fault probe that shifted only descriptor `st_ctime_ns`
reproduced the exact `PT-NWAY-STORAGE` error before any backup was created.
This is source-backed diagnosis and deterministic fault evidence, not a native
Windows execution result.

## Correction and preservation invariants

Cross-API comparisons still require the same device, inode, byte length and
modification time. Each API now has its own complete baseline, including its
change-time value; a changed pathname or descriptor baseline refuses recovery.
The opener also checks the pathname again after opening the descriptor.

Both streaming passes, their SHA-256 equality, exact existing-copy byte
comparison, regular/non-link checks, exclusive creation, fsync, and ownership
checks before incomplete-copy cleanup remain. A foreign replacement cannot
pass the cross-view identity comparison even when its new pathname baseline
is sampled after replacement. A prior recovery copy is never overwritten or
removed. The existing cooperative-filesystem limitation remains: no atomic
filesystem sandbox against arbitrary writers after the last check is claimed.

## Deterministic red/green checks

The unchanged #205 Linux baseline passed all 20 tests in
`test_nway_recovery_copy_20261105.py` and `test_nway_series_tolerance.py` in 1.95 s.
Six new controls were then added before production edits. Selecting
`distinct_path_and_handle or change_time_drift` produced **two failures and
four passes** in 1.19 s. Both failures were the exact false refusal for a new
or existing recovery copy. The four controls require metadata-only change
in either view after both byte-identical reads to refuse recovery, retain the
damaged original and prior copy, and remove only an owned incomplete new copy.

After the correction:

```bash
QT_QPA_PLATFORM=offscreen PYTHONPATH=src python -m pytest -q \
  tests/test_nway_recovery_copy_20261105.py \
  tests/test_nway_series_tolerance.py tests/test_nway_series.py
python -m ruff check src tests tools
git diff --check
```

Result: **47 passed in 3.37 s**; whole-tree Ruff and whitespace checks passed.
The passing tests include the six new controls and the existing collision,
directory/symlink, bounded-read, changed-source, descriptor-closure, oversized
input and replaced-copy preservation cases. Counts overlap the baseline.

## Remaining qualification

Independent review and coordinator integration are required before publication.
Native Windows QA of the resulting commit remains required; this Linux run and
fault injection do not establish Windows file-sharing, timestamp-publication,
packaging or release acceptance. No additional full suite was started. The
descendant #218 Windows job `127595647308` was still in progress when checked;
its result cannot qualify this new repair. Existing scanner/review/release
gates remain unchanged.

## Independent coordinator integration — 2026-11-06 UTC

The coordinator independently reviewed the 26-line production delta, retrieved the exact official CPython source, and reran the affected recovery/series selection: **47 passed in 3.71 s**. The branch is combined with the separately reproduced #205 crash-test correction from #219 (`park(*args, **kwargs)`); the original crash test first failed with the hosted `created` keyword error, then all seven crash-recovery tests passed in 1.83 s. The real child-kill and committed-state/retry assertions are unchanged.

Combined repair at local source commit `640cf36784698c02b1e1579b5a9a38795a4b0b15` / tree `a913fbadcf48e701116213c322d1dd6df0fac19e`: **54 passed in 4.51 s**, whole-tree Ruff and diff hygiene passed. Counts overlap the separate runs. The only production change is the recovery timestamp comparison; no later feature wave is back-merged into frozen #205.

Full Linux qualification will run on the published repair candidate. Its final outcome belongs in the PR description with the exact head and raw-log digest, so evidence updates need not restart the hosted candidate checks. Native Windows qualification and the original Sonar dispositions remain open. The original frozen #205 source ref is unchanged.
