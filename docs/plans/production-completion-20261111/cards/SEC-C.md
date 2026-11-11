# Slice card SEC-C - path, archive and process boundaries (TB-12, TB-10, TB-15, TB-09/WP-09)

Sources: `jq '.actionable_now[] | select(.id=="I1-T03" or .id=="I1-T04" or .id=="I1-T07" or .id=="I1-T14")' docs/status/inventory/I1.json` and the
matching defects `jq '.features[].defects[] | select(.id=="TB-12" or .id=="TB-10" or .id=="TB-15" or .id=="TB-09")' docs/status/inventory/I1.json`.
The audit record is docs/qa/audit-trust-boundaries-20261107.md (read the four items there).

Do the four items in this order, one commit each, red test first each time.

## 1. TB-12 - ingestion.safe_path refuses Windows device names and trailing dot/space components
File: src/patchtrace/ingestion.py. `safe_path` guards every persisted relative path; `AnalysisRun.raw_path` is a free
string that an edited snapshot can set. src/patchtrace/offline_bundle.py already has the reserved-name rule: reuse its
logic by moving the pure predicate to one place both import (keep offline_bundle's public behaviour identical) or by
importing it - no second copy of the list.
Acceptance: safe_path raises the existing PT-STORAGE error for CON, nul.txt, COM1, LPT9.bin, "a./b", "a /b", "aux" in any
letter case, on EVERY platform (the check is on the string, not the OS), and still accepts
`artifacts/<sha>.bin` and `runs/<id>/raw/json/result.ghidriff.json`. Tests in tests/test_core.py or a new
tests/test_safe_path_reserved_names.py.

## 2. TB-10 - offline bundle: check the ZIP entry count before zipfile materialises the directory
File: src/patchtrace/offline_bundle.py (around line 294: MAX_MEMBERS is enforced only after ZipFile has read every entry).
Read the end-of-central-directory record yourself (stdlib struct; handle a trailing archive comment up to 65535 bytes and
the ZIP64 EOCD locator/record) and refuse with the EXISTING member-count error when the declared total exceeds the cap,
without constructing ZipFile. If the EOCD cannot be parsed, fall through to the existing path (zipfile then reports its
own error) - never refuse a valid bundle because of your parser.
Acceptance: an archive whose EOCD declares more than the cap fails with the existing message while `zipfile.ZipFile` is
patched to raise if called; a ZIP64 case; a crafted EOCD that under-declares still hits the existing post-open check;
every existing test in tests/test_offline_bundle.py passes unchanged.

## 3. TB-15 - jobs.run_process validates the child environment
File: src/patchtrace/jobs.py (the Windows environment block is joined with NUL at about line 147 without validation).
Before any spawn, on every platform, reject: an empty name, a name containing "=" or NUL, a value containing NUL, a
non-str name or value. Raise the module's existing typed error for invalid process requests (look at how run_process
reports a bad argv/cwd today and match it; the audit calls it PT-BACKEND ValueError).
Acceptance: new tests in tests/test_jobs.py are red on the base and green after; no process is spawned for a refused env
(assert with a patched Popen that fails if called).

## 4. TB-09 / WP-09 - never signal a process group whose leader has already been reaped
File: src/patchtrace/jobs.py. Today `os.killpg(child.pid, ...)` is called after `poll()`/`wait()` reaped the leader and
again in `finally`; if the pid was recycled, an unrelated process group could be signalled. Required behaviour on POSIX:
descendants that keep the pipes open are still terminated on timeout/cancel/exit (existing tests cover this - keep them
green), but no killpg call happens once the leader has been reaped. The analyst's suggestion: observe exit with
`os.waitid(os.P_PID, pid, os.WEXITED | os.WNOWAIT)` (does not reap), signal the group while the zombie still holds the
pid, then reap. Windows behaviour must not change at all (job objects). Read the whole supervision loop first; this code
is shared by every engine, so keep the diff minimal and comment the invariant.
Acceptance: a new test wraps os.killpg and asserts at every call that the leader is not yet reaped (e.g. a waitid WNOWAIT
probe or a flag set by a wrapped wait), red on the base, green after; tests/test_jobs.py, tests/test_jobs_progress.py and
tests/test_secondary_scheduler.py stay green; run the three files 5 times in a row to check for flakiness
(`for i in 1 2 3 4 5; do ...; done`) and report the result.
If after two serious attempts item 4 cannot be made both correct and stable, leave items 1-3 committed, revert item 4 and
report exactly what blocked it. Do not ship a risky supervision change.

## Owned files
src/patchtrace/ingestion.py, src/patchtrace/offline_bundle.py, src/patchtrace/jobs.py, tests/test_core.py,
tests/test_offline_bundle.py, tests/test_jobs.py, new test files for these four items.
NOT yours: src/patchtrace/backend.py (another session's lane) even though it calls jobs.run_process - do not change any
signature or behaviour it relies on (check its call sites read-only and say in the report that they are unaffected).
