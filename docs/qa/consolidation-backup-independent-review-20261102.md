# Independent review: backup byte-stability repair

## Decision

**APPROVE the bounded patch for integration**, subject to the coordinator's normal current-candidate CI gates. No correctness blocker found in the reviewed delta. This is not native Windows acceptance or a claim of an atomic filesystem snapshot.

- Reviewed commit: `b86159f4823c2e1bb2d21d00cf0b470749a289fe`
- Parent: `63d11d316c70e1f1e83baa80acabd3cf3c4c2245`
- Tree: `cf6628c8b57eeaa10f5c1cf9cdbb18aa596596a5`
- Worktree: `/tmp/patchtrace-backup-stability-20261102`
- Scope: three changed files; no edits by this reviewer; working tree remains clean.

## Source review

`verified_backup._fingerprint` now requires two separately opened observations to agree on device, inode, size, mtime, and SHA-256. A failed first observation returns immediately; a failed or unequal second observation returns no trusted version. The old reader remains in `_fingerprint_once`. Independent AST comparison, excluding the renamed function and docstring, confirms its complete executable body is identical to the parent. Existing regular-file, no-follow, descriptor/path identity, per-API change-time, initial-size read bound, and descriptor cleanup guards are preserved.

The cached verdict remains associated with the exact checked byte version. `_cached` invalidates its entry when the strengthened fingerprint fails or differs. `trusted_backup` retains its prefilter of ineligible project/snapshot/table facts, so clearly unacceptable cached verdicts still avoid reading bytes. `_remember` revalidates before caching. SQLite identity/integrity checks are not replaced by hash agreement.

The patch does not change hard-link publication, stage ownership, failure retention, or pending-stage admission. The strengthened checks feed the existing refusal paths before and after verification and at final-name publication. Existing tests cover changed final bytes, replacement inodes/stages, failed cleanup, retained evidence, restart refusal, and preservation of history/retention rows when a suitable backup is unavailable.

Cost is one extra full hash/read pass per successful fingerprint. Each pass is limited to the size observed at its start, reads chunks of at most 1 MiB, and has no stabilization retry loop. Total I/O remains linear in the observed file size; this is a memory/chunk bound, not a new maximum database-size limit. Successful cached reuse therefore performs two full byte reads. Publication retains its existing sequence of fingerprint calls, each now requiring the two observations.

## Test quality and independent results

The new regression builds a real SQLite backup, modifies real file bytes, retains real SHA-256 computation, and fixes only the three change-time observation channels. Its stable control still requires successful cached reuse; its mutation control requires refusal plus preservation of changed evidence. The write occurs after the first hash update and only once, so the test exercises the persistent behind-cursor edit that a second read can detect. It does not emulate Windows filesystem semantics or prove exclusion of arbitrary writers.

Independently rerun on the exact reviewed head:

```text
QT_QPA_PLATFORM=offscreen PYTHONPATH=.:src:tests python3 -m pytest -q \
  tests/test_verified_backup_byte_integrity.py \
  tests/test_verified_backup_stat_api.py \
  tests/test_verified_backup_publication_admission.py \
  tests/test_verified_backup_reuse_filter.py \
  tests/test_prune_backup.py tests/test_enrichment_storage.py
60 passed in 2.98s
```

Targeted Ruff passed for both changed Python files. `git diff --check` passed. A separate real-file observation over 2,097,189 stable bytes produced the exact expected SHA-256 in two complete digest observations, totaling 4,194,378 bytes hashed with a largest chunk of 1,048,576 bytes. No production source or tests were changed for this control.

The QA note explicitly states that two observations are not an atomic snapshot or a lock against concurrent/later writers. It separates the local invariant test from native Windows acceptance. Its historical Windows-job result was supplied by the author/coordinator and was not independently re-fetched in this review. Native Windows and full current-candidate acceptance remain the coordinator's gates.

## Reviewed file SHA-256

- `src/patchtrace/verified_backup.py`: `732a2017cc765bc9f08879a51583f4137b5b576ed4276b966d6f9b8a36364318`
- `tests/test_verified_backup_byte_integrity.py`: `b820aa3d3f357ad4ff6a27e89fb480a1fb3bce8dd61faf91c4487b46074c72c5`
- `docs/qa/backup-byte-stability-20261102.md`: `7230b929b4c7f50befd943e7ac71aab9e83a10e4ee64fd7c7c1c26094e2d14c4`
