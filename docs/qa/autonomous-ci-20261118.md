# Fresh qualification failures and Windows sharing repair — 2026-11-18

## Observed repository state

At the 13:52 UTC GitHub REST snapshot, canonical `main` remained
`9c411ca3d7b47f950be5f0c6f01b3c54184554c6`. PR #304's source head was
`75ffee3840894adb52aff7f3df28043cc8e832ba`; PR #307's source head was
`1418617a80d6057de11f985488cfe6043a7787a2`, stacked on #304.
The ruleset collection and both PR review collections were empty. This is not
permission to merge a failing candidate: the owner's full qualification rule
continues to apply, including independent review and exact-source acceptance.

The following hosted executions were inspected in this session. They are not
local Windows runs or passing qualification of the later repair commit.

| Source | Hosted job | Observed result |
|---|---|---|
| #304 `75ffee38` | [Ubuntu QA](https://github.com/djshellshoxxx/patchtrace/actions/runs/44282386440/job/134726180447) | **1 failed, 22,866 passed, 50 skipped, 6 xfailed**, 34m45s. `test_same_update_variants_are_retained_without_invented_chronology_and_order_is_stable` fails with `assert 0 == 1`. |
| #307 `1418617a` | [Ubuntu QA](https://github.com/djshellshoxxx/patchtrace/actions/runs/44293307844/job/134763761753) | **3 failed, 23,606 passed, 50 skipped, 6 xfailed**, 34m58s. The same chronology failure, plus fixture-manifest completeness and tooltip-application completeness. |
| #304 `75ffee38` | [Windows publication gate](https://github.com/djshellshoxxx/patchtrace/actions/runs/44282386440/job/134726180099) | **17 failed, 83 passed, 3 skipped**, 2.68s. Native publication reports `PermissionError (OS error 32)`. Full Windows QA and packaging did not start. |
| #307 `1418617a` | [Windows publication gate](https://github.com/djshellshoxxx/patchtrace/actions/runs/44293307844/job/134763762162) | **17 failed, 83 passed, 3 skipped**, 3.89s. Same sharing violation. Full Windows QA and packaging did not start. |

The job logs identify GitHub's PR merge checkouts, not the source heads themselves:
`eac93835f3104319015e8c975a27c19143645b38` for #304 and `c63065b…` for #307.
The original logs retain the complete checkout identities. Their workflow metadata
associates each run with the source SHA above. No later candidate inherits acceptance
from these runs.

The initial snapshot also shows unfinished Qt gates, unified extraction and corpus
aggregation for #304, and unfinished Qt gates for #307. Linux package/smoke and
Windows installer acceptance cannot pass while their QA prerequisites fail.
An intentionally skipped release job is not release qualification.

## Windows defect and candidate repair

The held-directory opens requested `FILE_SHARE_READ` only. Microsoft's
[FILE_RENAME_INFORMATION contract](https://learn.microsoft.com/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_file_rename_information)
describes an internal destination-directory open requesting
`FILE_WRITE_DATA | SYNCHRONIZE`. The
[NtCreateFile sharing contract](https://learn.microsoft.com/windows/win32/api/winternl/nf-winternl-ntcreatefile)
requires this new access to be compatible with all existing share masks. The
held directory's missing `FILE_SHARE_WRITE` conflicts with that internal open.
This explains a concrete source-level sharing conflict consistent with the hosted
error 32. The original error-87 record remains unchanged; this repair does not
retroactively assign a cause to that earlier failure.

Candidate commit `e250f683c9f1770639772e33142978f4c3bd0575` changes only directory
guard sharing to `FILE_SHARE_READ | FILE_SHARE_WRITE`, at both the root Win32 open
and rooted native child opens. It continues to omit `FILE_SHARE_DELETE`, so the
guarded directory cannot be renamed/deleted through another handle. The staged
source still shares reads only, preserving its write and rename exclusion. The
rooted handles, no-reparse opens, no-replace rename, hash and identity checks, exact
handle cleanup and primary-exception preservation remain unchanged. The contract
in `docs/research/winpairs.md` was updated before implementation.

This is a candidate native repair until the new published head passes Windows
filesystem tests. The portable tests inspect actual requested access/share modes
against the documented sharing rule; they do not emulate native filesystem behavior.

## Local regression evidence

The seven new contract controls were first run against production source at
`1418617a`, producing **3 failed, 4 passed**. Each failing case selects a different
directory guard (volume root, ancestor, leaf). Four passing controls verify that
the source continues to reject other data writers, appenders and renamers.

With the repair, this command completed with **108 passed, 2 skipped in 0.61s**:

```bash
QT_QPA_PLATFORM=offscreen python -m pytest -q \
  tests/test_research_qualification_winpairs.py \
  tests/test_research_qualification_winpairs_integrity.py \
  tests/test_research_qualification_winpairs_publication.py
```

The two skips are actual Windows sharing/reparse controls on the Linux execution
host. No existing test was disabled or weakened. Ruff for the changed Python files
and `git diff --check` passed. Code tree:
`ef99b1812087bfb452c9b7410e29806259465cb3`.

The local interpreter was `/workspace/scratch/3a6632a6e5ff/venv/bin/python`
(pytest 9.2.0, PySide6 6.12.0, pydantic 2.13.5). The red and green logs and JUnit
files retain exact commands' outcomes; overlapping invocations are not summed.

## Native engine evidence and limits

The retained #304 clean Ghidriff job and #307 seeded-store-without-adjacent-PDB
Ghidriff job both executed the actual backend check and printed
`Known patch accepted: 1 change records`. These are acceptance of the authored
`read_item` DLL fixture and tested workflow, not CVE-attribution accuracy.
The retained #304 Linux and Windows Rizin logs contain `status: passed` with
`engine_run.status: ok`. This is separate from the unrerun L2 http-parser miss and
from #307's research parser identity controls.

The BinDiff Windows lane is explicitly advisory and permits a failed native test
without failing its workflow. A green workflow badge alone is insufficient;
the lane's actual status receipt must be inspected. Path-filtered absence on #307
also supplies no new-head acceptance. Optional-wheel import probes do not constitute
a dependency security audit.

The current publishing job depends on QA, repeated Qt, Linux smoke and the cadence
gate. Separate native and dependency workflow outcomes are not currently wired as
publication prerequisites. The `[no release]` hold remains mandatory for this
integration. Completing broader fail-closed release qualification remains an open
task; this narrow Windows repair does not change release or test gate behavior.

## Evidence retention and next acceptance

The [manifest](autonomous-ci-20261118/manifest.json) lists sizes and SHA-256 hashes
for 13 exact raw captures and the compressed archive. All archived payloads were
read back and checked against that manifest. Original failures and historical
research receipts remain untouched.

Independent review must examine the exact repair, followed by new-head Windows
publication controls, full Linux/Windows QA, Qt repetition, packages/smokes and
the other applicable native/dependency gates. Root coordination owns the chronology,
fixture-manifest and tooltip repairs reported above. No merge, closure, target
binary download/execution, release, tag or deployment was performed by this worker.
