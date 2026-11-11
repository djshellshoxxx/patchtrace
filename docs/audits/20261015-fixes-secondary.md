# Secondary engines audit fixes 2026-10-15

Source: `docs/audits/20261015-secondary-engines.md`. Tests are in `tests/test_secondary_fixes.py` unless noted. Each test was red before its fix.

| ID | Commit subject | Test | Status |
|---|---|---|---|
| SEC-1 (rz-diff half) | verify declared SHA-256 of artifacts before rz-diff | `test_sec1_*` (2) | Fixed: scheduler copies and hashes artifacts in the workdir, refuses `PT-SECONDARY-INPUT` on mismatch, rz-diff reads the verified copy, cache key and run hashes describe those bytes. Adapters opt in with `reads_artifacts`. |
| SEC-2 | prefer the current artifact pair when selecting sets | `test_sec2_*` | Fixed: `select_current(rows, pair)`, wired in CLI reconcile, evidence panel and unified pipeline. An engine with no row for the pair still yields its newest row (shown stale). |
| SEC-3 | none | none | Deferred (backend.py). |
| SEC-4 | preserve a user-selected .BinDiff before parsing it | `test_sec4_*` | Fixed: `import_bindiff(preserve_dir=...)`; CLI and panel pass `runs/<id>/raw/secondary`. |
| SEC-5 | keep one BinExport snapshot per distinct file | `test_sec5_*` | Fixed for the unbounded growth (content-addressed folder, reused). No per-project byte cap (not added; would need a policy decision). |
| SEC-6 | cap BinDiff function-name length | `test_sec6_*` | Fixed: 64 Ki characters per name. No total-bytes cap. |
| SEC-7 | refuse non-positive or oversized engine deadlines | `test_sec7_*` | Fixed in the scheduler (0 < t <= 86400, `PT-SECONDARY-INPUT`). CLI `--timeout` flag not bounded separately. |
| SEC-8 | none | none | Deferred: `tests/test_secondary_rzdiff.py` pins U+FFFD rejection; strict decode changes that contract. |
| SEC-9 | strip bidi and line separators from stored stderr | `test_sec9_*` | Fixed. |
| SEC-10 | none | none | Deferred (backend.py default). |
| SEC-11 | docstring | none | Fixed: `validate_binexport` marked test-only. |
| SEC-12 | docs | none | Fixed: spec size cap 256 MiB and preserved-copy import text. |
| SEC-13 | tests | see above | Covered for (a) SEC-2, (b) SEC-1, (c) SEC-7, (d) SEC-5, (f) SEC-4. (e) is deferred with SEC-3. |

Existing tests adjusted for SEC-1: `test_secondary_scheduler.py` (`project()` now writes real files with matching hashes) and `FakeRz` in `test_evidence_panel_service.py` (`reads_artifacts = False`).

## Deferred

- SEC-3: both sites are in `backend.py` (probe `python -c` at about line 275, `python -m ghidriff` with `cwd=ghidra_dir` at about line 587). Needed: `-I` for every non-bundle child, a neutral scratch cwd, and an argv test.
- SEC-1 Ghidriff half: `backend.py` hashes at about line 542 and reads at about line 589. Needed: hash a private copy, or re-hash immediately before the run, and pass the verified copy.
- SEC-10: default `restrict_env` in `backend.py`; needs the native Windows check first.
- SEC-8: needs a decision to change the pinned U+FFFD contract (strict decode with byte offset).
- Suspicions in the audit were not addressed.

Verification: focused tests (secondary, scheduler, bindiff, binexport, CLI secondary, evidence UI/host/panel service, unified pipeline) pass; `ruff check` clean on touched files. Full suite not run.
