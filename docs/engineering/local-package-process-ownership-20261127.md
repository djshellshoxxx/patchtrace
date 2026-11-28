# PW-02 supervised borrowed Windows handles

Date: 2026-11-27 (America/Vancouver). Base:
`d27cb06a6613d8d85eef459b344545b5829b8dac`.

## Gap and bounded plan

The existing launcher used plain STARTUPINFO and
`CreateProcessW(bInheritHandles=True)`. The spawn lock serialized supervised
launches, but no explicit list excluded unrelated inheritable handles and no
borrowed-handle API existed. The plan was spec first, reproduce both gaps, add
owned duplicates with exact inheritance, preserve supervisor behavior, then add
portable and actual Windows ownership controls. Package decoding, held filesystem
I/O, accounting and project admission belong to their separate owners.

## Contract and implementation

`run_process(..., windows_borrowed_handles={name: parent_handle})` accepts at most
16 entries. Explicit uppercase ASCII environment names are at most 64 characters
and cannot collide with the supplied environment ignoring case. Values are
distinct nonboolean pointer-sized integers; null and known pseudo handles refuse.
The bounded mapping is captured before launch. Other platforms refuse nonempty
bindings; ordinary empty/omitted callers retain their existing path.

Under the spawn lock, `GetHandleInformation` checks originals and `DuplicateHandle`
creates inheritable same-access duplicates. The caller retains originals, with
unchanged flags/access, through supervisor return and synchronizes shared file
offsets. Child environment values are unsigned decimal duplicates under the named
`PATCHTRACE_FDI_*` variables; input environment and grant/accounting JSON remain
unchanged. Workers consume and close only their inherited duplicates.

All Windows launches use STARTUPINFOEX with exactly unique stdio child handles
plus approved duplicates. Attribute allocation is bounded to 64 KiB. Storage and
the handle array survive through attribute deletion. Extended startup is additive
to the existing suspended/unicode/no-window flags. Job configuration and assignment
still precede resume, with no uncontained fallback. Temporary duplicates, attributes
and stdio child ends are cleaned before unlocking on success or setup failure.
Existing memory/output/time/cancel behavior and other platforms are preserved.

This grants explicit launch access, not filesystem identity or an OS filesystem
sandbox. Held-I/O callers establish identity/access; a worker starting descendants
must prevent unintended further inheritance. No persisted contract changed.

Primary references:

- [Handle-list requirements](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute)
- [Attribute allocation and lifetime](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-initializeprocthreadattributelist)
- [Extended startup size](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-startupinfoexw)
- [Duplication access and ownership](https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-duplicatehandle)

## Red/green evidence

All 39 initial portable controls failed: 37 encountered the absent API and two
executed injected Windows launches and observed no restricted inheritance list.
No native Windows operation ran. The first implementation plus maintained launch
tests passed 95 with 3 existing native skips. Additional controls cover the exact
16-entry boundary, bounded iteration despite inaccurate mapping length, attribute
allocation limits, and failures through CRT stream transfer. Invalid-input tests
select Windows dispatch, so generic platform refusal cannot satisfy them.
Authored original/duplicate values above 32 bits test portable marshalling only.

The final selection passed **189 / skipped 13 / failed 0** in 20.53 seconds
(JUnit 20.434). All 47 new portable controls pass. The skips are exactly seven new
Windows tests and six existing Windows Job/launch cases. Whole-tree Ruff and
whitespace pass. The earlier 95-case selection overlaps this result.

```sh
PYTHONPATH=src PYTHONDONTWRITEBYTECODE=1 QT_QPA_PLATFORM=offscreen \
  ../.venv/bin/python -m pytest -q -p no:cacheprovider \
  tests/test_jobs.py tests/test_jobs_windows_launch.py \
  tests/test_jobs_windows_handles.py tests/test_jobs_windows_handles_native.py \
  tests/test_jobs_progress.py --tb=short \
  --junitxml=../pw02-process-evidence/borrowed-handles-supervisor-green.xml
```

Receipts beside the checkout in `pw02-process-evidence`: `borrowed-handles-red.xml`,
`borrowed-handles-first-green.xml`, `borrowed-handles-supervisor-green.xml`.

## Native qualification: BLOCKED on Linux

Seven authored Windows controls cover real unrelated-event exclusion, source/sink
same-access behavior, retained originals, failed assignment/resume before child
execution, cancellation, concurrent object isolation and stdout completion while
another job remains alive. They observe parent object state instead of assuming a
numeric handle cannot be reused in the child. All seven were collected and skipped
here; portable injections are not native qualification. Exact-source review,
Windows execution and integration remain pending at this commit. No package,
decoder, target or native helper was executed, no live fetch/remote write occurred,
and the shared environment binding was unchanged.


## Independent source approval

Root reviewed exact runtime `003d97c01d15b877136a3576ac83519cc7efbe5f`,
tree `2c15832d1ca2285069bed55b07c40a716d6cba38`, including explicit-list
lifetime, duplicates, Job-before-resume order, native callback signatures and
all error cleanup. No source-scope blocker remains. Five additional authored
controls enforce exact attribute-query results, allowlist lifetime through
CreateProcess and duplicate cleanup before unlocking, plus refusal of a closed
original without starting a child or closing another owner's handle.

These controls plus the authored handle and maintained Windows-launch modules
passed **108 tests, three existing native-only skips**, in 0.92 s. The first
command used a nonexistent test filename and collected nothing; its diagnostic
is retained alongside the completed corrected command. This was not a product
failure or a counted test pass. The independent controls are now retained in
`tests/test_jobs_windows_handles_independent.py`; original author and review
receipts are under `evidence/local-package-process-20261127/`. Native Windows
execution, exact-head full qualification and integration remain pending.

Retaining the independent module required only import-order formatting; its five
assertion sets passed again unchanged. Required Ruff and whitespace passed.
