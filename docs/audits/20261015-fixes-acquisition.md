# Fixes: acquisition and enrichment audit (2026-10-15)

Fixes for `docs/audits/20261015-acquisition-enrichment.md` (ACQ-1 to ACQ-11) and the open acquisition twin of
`docs/audits/20261014-C-acquisition-gui.md` C-01. One commit per finding. All tests are offline (loopback socket
server or fake opener). Focused run: 280 passed, 2 skipped; ruff clean on touched files.

| Finding | Commit | Test | Status |
|---|---|---|---|
| ACQ-1 | 5367981 | `test_malformed_redirect_location_is_typed_network_error` (acquisition), `test_malformed_redirect_location_is_typed_and_batch_survives` (enrichment) | Fixed (red first) |
| ACQ-3 | deac283 | `test_http_protocol_error_is_typed_network_error`; `_read` also maps `HTTPException` (e.g. `IncompleteRead`) | Fixed |
| C-01 | ef881ec | `test_slow_drip_download_stops_at_the_total_deadline`, `test_slow_drip_download_observes_cancel` (`tests/drip_server.py`) | Fixed (red first) |
| ACQ-2 | 454db29 | `test_slow_drip_response_stops_at_the_total_deadline` | Fixed (red first) |
| ACQ-4 | a083767 | `test_unpaired_surrogate_escape_is_a_typed_provider_error`, `test_paired_surrogate_escape_still_parses` | Fixed (red first) |
| ACQ-5 | 1c4a5e1 | `test_remove_staging_tolerates_a_locked_file`, `test_create_staging_sweeps_stale_directories_only` | Fixed |
| ACQ-6 | 1c6075e | `test_absurd_manifest_size_is_corrupt_not_a_crash` | Fixed (red first) |
| ACQ-7 | 4e47b20 | `test_quarantine_counts_toward_the_budget_and_is_evicted_first` | Fixed (red first) |
| ACQ-9 | ec40ea9 | `test_crash_while_writing_the_owner_leaves_no_torn_file[lock, lease]` | Fixed (red first) |
| ACQ-8 | ae192b3 | `test_backup_swapped_during_verification_is_not_trusted` | Fixed |
| ACQ-10 | 8093589 | `test_acq10_import_checks_snapshot_identity_and_time` | Fixed (red first) |
| ACQ-11 | f8e82aa | `test_restore_rejects_a_torn_journal_before_writing_anything` | Fixed (red first) |

Some tests were written together with the fix (ACQ-3, ACQ-5, ACQ-8) rather than observed red beforehand.

## Notes on the fixes

- C-01, ACQ-2: reads use `read1`, which returns after one socket receive, so cancel and the total deadline are checked
  between receives. Worst-case overshoot is one socket timeout (10 s), not unbounded. Cancel of a fully silent
  server still waits for that timeout; prompt interruption needs socket access or `netutil.interruptible` per chunk
  (not adopted for acquisition: one thread per chunk on a 512 MiB download).
- ACQ-5: `remove_staging` retries, never raises and returns whether the directory is gone. `create_staging` sweeps
  `patchtrace-acquire-*` directories untouched for 24 h (far above the one-hour download deadline), so no caller changed.
- ACQ-7: quarantine bytes count in `_usage`; `prune` evicts quarantined entries oldest first (new result key
  `quarantine_removed`, additive). `status()['bytes']` still reports live entries only.
- ACQ-9: owner files are written to a temp name and hard-linked into place (exclusive and complete); filesystems
  without hard links fall back to the previous exclusive create. A pre-existing empty lock is still never stolen
  (existing invariant, tested); only new torn files are prevented.
- ACQ-8: a file replaced with a new mtime during verification is no longer trusted. A replacement with identical size
  and mtime remains undetectable by a `(size, mtime_ns)` fingerprint.
- ACQ-10: import now rejects a `snapshot_id` that does not match the recomputed identity and a bad `retrieved_at`,
  naming the snapshot index. No persisted field changed.

## Deferred

| Finding | Reason |
|---|---|
| ACQ-12 | Spec/code wording mismatch (SPEC-08 4.5 names `inspect_artifact`, code uses `validate_pe`); a spec decision, outside the requested ACQ-1..11 scope. |
| ACQ-13 | Binding `FetchConsent` to the previewed URL list changes the CLI consent flow in `cli.py` (frozen shared file) and is outside the requested scope. |
| ACQ-9 (part) | `verify` reporting pre-existing unreadable locks as a warning was not added (kept the "never steal" invariant; ~20 lines plus a result-contract key). |
| Cancel latency | Prompt cancel against a silent server still bounded by the 10 s socket timeout (see C-01 note). |
