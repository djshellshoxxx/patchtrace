# Retained output metadata repair — 2026-11-02 UTC

Published PR #157 head `aff72cddc902f31a2cf44dea9c48797edabc1c30` failed Windows
QA on Python 3.12.10 x64: **18,360 passed, 60 failed, 27 errors, 81 skipped,
6 xfailed**. [Job 124877832666](https://github.com/djshellshoxxx/patchtrace/actions/runs/41316567247/job/124877832666)
records ordinary retained files rejected by `read_output_bytes`, including the
actual `train.load_outputs` consumer. The raw job log is retained in the companion
archive; later checks do not replace this failure record.

The exact CPython 3.12.10 sources explain an incompatible comparison:
[`win32_xstat`](https://github.com/python/cpython/blob/v3.12.10/Modules/posixmodule.c#L2139)
copies creation time into pathname `ctime`, while
[`_Py_attribute_data_to_stat`](https://github.com/python/cpython/blob/v3.12.10/Python/fileutils.c#L1108)
sets change time and
[`_Py_fstat_noraise`](https://github.com/python/cpython/blob/v3.12.10/Python/fileutils.c#L1233)
returns it without that compatibility adjustment. The upstream
[CPython issue](https://github.com/python/cpython/issues/157671) independently
documents the mismatch. This is source-backed diagnosis plus a portable modeled
reproduction; fresh native Windows confirmation remains required.

Source `cb22780bffbabf0e6fddfbc7562fe20ee699e35e` now compares descriptor snapshots
with descriptor snapshots and pathname snapshots with pathname snapshots,
including each API's `ctime`. Cross-API checks retain device/inode identity, size
and modification time. The change does not remove descriptor change-time
protection, change publication/cleanup, relax link/reparse rejection, bypass byte
caps or alter digest/credit verification. Failed artifacts remain preserved.

The new unchanged-file split-clock control failed before repair: **1 failed,
14 passed**. New controls also cover each API's identity, size, modification-time
and `ctime` changes; cross-API content disagreement; same-size mutation with
restored modification time; and an actual unmocked rewritten file/managed marker.
Final new/credited-replay/persistence selection: **100 passed**, 3 expected legacy
warnings in 1.54 seconds. Existing synthetic training pipeline separately:
**34 passed, 1 native-tool blocked skip**, 8 expected warnings in 27.49 seconds.
No actual corpus, locked final evaluation or native engine accuracy is claimed.
Whole-tree Ruff, dependency consistency and diff hygiene pass; no schema changed.

The first combined invocation returned a tool exit of zero but retained only
mid-progress output without a completion summary or JUnit. It is **unqualified**,
preserved separately and not included in the passing counts. The focused run and
separate training run above provide complete output, including training JUnit.

The [machine receipt](output-windows-stat-20261102.json) and
[original logs](output-windows-stat-20261102.tar.gz) record source, commands and
hashes. Current-head native Windows/full QA/Qt/package gates and the separate generic
Sonar output-path finding remain open at this source checkpoint. No scanner issue was suppressed and no acceptance gate was weakened.

Independent helper review subsequently found **no blocking finding** at exact
source `cb22780bffbabf0e6fddfbc7562fe20ee699e35e`: 100 focused checks passed in
1.75 seconds, with scoped Ruff and diff checks clean. The reviewer additionally
replaced the pathname during a real bounded read using identical bytes, size and
restored modification time; the reader refused it. The source-bound
[review receipt](output-windows-independent-review-20261102.json) is retained.
This is independent source review, not a formal GitHub approval or native Windows
result. Production and test bytes are unchanged by this evidence follow-up.

Root merged accepted main `25c9795bd9cd58bfad855f30594ee3a0c7584cec`, preserving both additive QA/todo histories. An initial command named a nonexistent test file and ran no tests; retained separately. Corrected exact selection (test_tier_r_output_stat_compat, test_tier_r_credited_replay, test_tier_r_output_persistence): 100 passed, with zero failures/errors/skips. Completed JUnit and log retained. Whole-tree Ruff passed; fresh native Windows/full gates remain required.
