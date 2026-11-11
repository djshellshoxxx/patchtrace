# Backup byte stability when timestamps do not advance

## Failure and diagnosis

Base source: `63d11d316c70e1f1e83baa80acabd3cf3c4c2245`.
The hosted Windows [QA job 125478435511](https://github.com/djshellshoxxx/patchtrace/actions/runs/41503995837/job/125478435511)
failed `test_edit_to_already_hashed_bytes_with_restored_mtime_is_not_trusted`:
`trusted_backup` returned the cached path after the test changed already-hashed
bytes and restored mtime. That run reported 1 failed, 18,465 passed, 81 skipped,
and 6 xfailed. The original test and its assertion remain unchanged.

A single digest can describe the old bytes when a write occurs behind its read
cursor. The old implementation rejected that case only if a descriptor, path,
or native change-time observation differed. Equal timestamps therefore left a
real gap in byte revalidation. This is distinct from the previously repaired
comparison of unlike path and descriptor ctime values.

The Windows log does not include the timestamp values, so it does not establish
whether resolution, update timing, or another Windows behavior produced equal
observations. Microsoft documents [filesystem-dependent timestamp behavior and
resolution](https://learn.microsoft.com/en-us/windows/win32/sysinfo/file-times)
and the separate meanings of
[`FILE_BASIC_INFO` times](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_basic_info).
Neither source establishes content identity from equal timestamps. No defect in
the native change-time helper is claimed here.

## Repair and limits

`_fingerprint` now requires two independently opened, complete byte observations
to agree on device, inode, size, mtime, and SHA-256. Each observation uses the
unchanged bounded reader and retains all descriptor, path, native change-time,
and regular-file checks. Either failed observation or a differing version
refuses trust. SQLite integrity/identity queries remain cached for the checked
bytes. Publication and failed-evidence handling are unchanged.

This adds one complete read/hash pass to each successful fingerprint. It has
linear I/O cost and bounded memory; it does not retry until a changing file
settles. It detects a persistent edit behind the first read cursor without
requiring timestamp movement. Two observations are not an atomic filesystem
snapshot and do not exclude arbitrary concurrent or later writers. Native
Windows acceptance remains pending.

## Local evidence

The new regression uses a real SQLite backup, real disk modification, and real
SHA-256, while holding only the three change-time channels constant. Stable bytes
remain reusable; a same-size/restored-mtime edit after the first hash update must
be refused and its diagnostic bytes preserved. The control is an invariant
test, not emulation or proof of native Windows behavior.

Before the production change:

```text
QT_QPA_PLATFORM=offscreen PYTHONPATH=.:src:tests python3 -m pytest -q \
  tests/test_verified_backup_byte_integrity.py::test_cached_reuse_matches_bytes_when_change_times_do_not_advance
1 failed, 1 passed in 0.60s
```

The failing case incorrectly returned the cached backup path. The stable-byte
case passed, showing that unchanged observations alone were not being refused.

After the change:

```text
QT_QPA_PLATFORM=offscreen PYTHONPATH=.:src:tests python3 -m pytest -q \
  tests/test_verified_backup_byte_integrity.py \
  tests/test_verified_backup_stat_api.py \
  tests/test_verified_backup_publication_admission.py \
  tests/test_verified_backup_reuse_filter.py \
  tests/test_prune_backup.py tests/test_enrichment_storage.py
60 passed in 2.64s
```

Whole-repository `python3 -m ruff check src tests tools` and `git diff --check`
passed. This focused Linux result includes the original Windows regression,
independent change-channel refusals, real backup reuse, publication/evidence
handling, and no-prune integration. The coordinator owns the full suite and
fresh native Windows CI; those gates have not been replaced by these controls.
