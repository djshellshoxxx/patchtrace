# Security integration checkpoint — 2026-11-16

Baseline: `74010784` (`main`). Source: PR #290, `1d5a022d2840c5c071ccece503664c8c961d63f1`.
The source branch is merged without rewriting its history. The search cursor conflict preserves both main's `OverflowError` rejection and the source's `RecursionError` rejection.

## Finding disposition

| Finding | Integrated behavior | Evidence |
|---|---|---|
| TB-16 | Typed failures for deep JSON at six parsing boundaries; calibration finite-value traversal guarded | `test_json_recursion_boundaries.py` |
| WP-03, SEC-9 residual, PE-4/5 | Shared hostile-text predicate across storage sanitizers; legacy workspace identity verification retained | `test_hostile_text.py`, `test_kbc_products.py` |
| TB-12 | Shared portable Windows reserved-name/trailing-dot/space guard | `test_safe_path_reserved_names.py` |
| TB-15 | Validate environment names and values before spawning | `test_jobs.py`, `test_security_subprocess.py` |
| TB-09 | Observe exited leader with `waitid(WNOWAIT)`, kill descendants before reaping, never signal the group after reaping. External reaping produces an error and disables group signals | `test_jobs.py`: three exit variants failed before correction; successful exit, timeout, cancellation, descendant pipe ownership, memory-cap failure, final wait failure and external-reaper controls pass |
| TB-10 | Independent streaming central-directory header count and 128 MiB directory allocation cap before `ZipFile`; declared-count precheck retained | Underdeclared ordinary/ZIP64 tests failed with the source's precheck alone; now both refuse before constructing `ZipFile` |
| PE-2/3, PE-6/7/8 | Chunked Tier W directory reads, typed failures, import cap boundaries, linear export alias handling, accurate truncation wording | PE regression files and `test_tier_w_pe.py` |
| Worker exchange temporary-file attack | Unique exclusive temporary file, fsync, atomic replacement and failure cleanup | `test_security_atomic_writes.py` |

The unfinished TB-09 patch retained on `origin/claude/sleepy-fermi-y3z4yj` supplied the initial process-ordering implementation and regression cases. This integration additionally refuses unsupported POSIX supervision before spawning, handles external reaping explicitly, and tests observation errors. Windows uses its unchanged Job Object path. Older POSIX Python runtimes without `waitid`/`WNOWAIT` must be upgraded; no unsafe polling fallback remains.

Independent review identified the underdeclared ZIP count bypass during integration. The additional structural preflight closes that gap and supports normalized and legacy CPython ZIP64 end-record locations. This uses the standard library's bounded private EOCD parser, so compatibility is regression-tested but should be rechecked on Python runtime upgrades.

## Verification

Linux, Python 3.12, Qt offscreen:

- Broad security/PE/JSON/storage regression selection: **788 passed, 3 skipped** (44.76 seconds).
- Additional external-reaper and `waitid` failure controls: **2 passed**.
- Offline-bundle and archive-member selection, including actual-count and directory-byte preflight: **66 passed**; expected duplicate-ZIP-member fixture warning.
- `python -m ruff check src tests tools`: passed.
- `git diff --check`: passed.
- Independent reviewer separately ran 171 security tests, 19 selected process tests, and 65 offline-bundle tests; no remaining concrete blocker reported in reviewed changes.

These selections overlap and are not additive totals. The full repository suite and required CI merge gates belong to integration verification. Windows execution, native analysis-engine qualification, and release acceptance are not established by these results. No target binaries were executed.
