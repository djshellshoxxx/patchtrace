# Windows backup timestamp verification repair — resumed November 1, 2026

The exact published #151 head `ad63416348c122ade8419b11686164be09bb2af3` failed Windows QA (run41313917033): 563 failed / 17,644 passed / 81 skipped / 6 xfailed / 179 errors; the repeated Qt job also failed. The recurring root exception was `BackupError: backup changed during verification`. These original failures are retained and are not replaced by Linux results.

CPython's Windows path stat/lstat can expose creation time as `st_ctime_ns` while descriptor fstat exposes change time. The backup reader compared those unlike fields on the same unchanged file. Primary evidence: [CPython issue157671](https://github.com/python/cpython/issues/157671) and [3.12 os.stat documentation](https://docs.python.org/3.12/library/os.html#os.stat_result.st_ctime). The separate native FILE_BASIC_INFO.ChangeTime helper remains unchanged.

The repair compares descriptor before/after observations in full, independently compares path before/after observations in full, and binds them by device/inode/size/mtime. Fresh SHA-256 of every backup reuse, native change-time observation, SQLite content/integrity verification, non-replacing publication and owned-stage cleanup remain required. This changes no persisted format or prune permission policy.

Fresh reproduction: **2 failed, 7 passed** on the unchanged published source under a source-faithful split-timestamp control. The two failures exercise raw fingerprinting and actual SQLite backup/cache reuse. New negative controls reject changes to each independent timestamp channel and dev/inode/size/mtime mismatches. Existing tests retain same-size/restored-mtime corruption, during-read edits, post-publication mutation, collision preservation and no-prune failure behavior.

```
QT_QPA_PLATFORM=offscreen PYTHONPATH=.:src:tests /workspace/scratch/142cb233d750/venv/bin/python -m pytest -q --junitxml=/workspace/scratch/142cb233d750/reconciliation/backup-stat-green.xml tests/test_verified_backup_stat_api.py tests/test_verified_backup_byte_integrity.py tests/test_prune_backup.py tests/test_enrichment_storage.py
```

Result: **37 passed in 1.84 s**, JUnit zero failures/errors/skips. Scoped Ruff and diff check passed. Original red log, first green console capture (progress-only, not standalone count evidence) and completed JUnit are retained as compressed files. Native Windows verification and independent exact-source review remain pending; no local simulated test is called Windows acceptance. The broader source full suite is coordinated separately.

Independent reviewer approved exact source `7b238d1c28055eeed5811872057b2356a9b22c33`: 35 focused tests passed in 2.23 s, plus an independent same-byte/restored-mtime pathname-replacement refusal. These overlap author checks and are not additive. Main `25c9795bd9cd58bfad855f30594ee3a0c7584cec` was merged; only additive QA/todo prose needed conflict resolution, retaining both histories. Fresh exact-head Windows/full/Qt/package gates remain required.

Coordinator accepted-main integration: 41 backup/retention/refacts tests passed; JUnit and console retained. No extra failures/skips.
