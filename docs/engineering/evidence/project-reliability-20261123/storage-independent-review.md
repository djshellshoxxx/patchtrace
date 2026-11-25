# Project creation and recovery review

Reviewer used an independent detached worktree. Source main ea16019601486c831941f9bc1a7ba5862a170317. Reviewed candidate 7207c021b094fac9f3c8c289a14e3f5976fde94c.

| Reviewed commit | Evidence |
|---|---|
| b78775ff1e14265bca6d5e0b693234dcaaf09db5 | 82 tests passed across schema refusal, replacement refusal, existing service storage and GUI creation retry. |
| f88c5c30817c50d1ba2209c8ddf882c7fef5b630 | 83 tests passed. A normal Windows UNC name produced file://server/...; the default SQLite parser rejected the authority. Interrupting constructor validation after the transaction started kept the lock while the caller held the interruption traceback. |
| 686ff40d985f43ff0c3c3a86bd66b7e2cc479f6a | 88 tests passed, including filenames containing URI-reserved characters and both SQLite access modes. The UNC host and share are now encoded as the Windows VFS filename. |
| 7207c021b094fac9f3c8c289a14e3f5976fde94c | Six repository suites passed, 129 tests. Independent cancellation checks for new, zero-byte and recognized databases verified immediate lock reacquisition, byte preservation and journal cleanup while handling the interruption. |

Reproduce on Linux with the candidate checked out, repository dependencies installed, and Python 3.12.

```sh
QT_QPA_PLATFORM=offscreen PYTHONPATH=src python -m pytest -q \
  tests/test_creation_schema_refusal.py tests/test_creation_replacement_refusal.py \
  tests/test_service_storage_audit.py tests/test_gui_creation_retry.py \
  tests/test_project_database_uri.py tests/test_project_store_constructor_cleanup.py
```

The UNC parser tests use a local fixture and check SQLite's read-only and read-write URI handling. A native Windows project on a real SMB share was not exercised. This review is bounded to the listed storage changes and does not qualify other changes in a combined candidate.

## Pre-prune backup follow-on

Independently reviewed 997f5156 and efe85b01e33849dc4fb496503dd980b56f86b934 on a detached checkout of the latter. The backup verifier shares the same filename encoder as project open and keeps SQLite's mode=ro. At that commit, the six suites above plus all tests/test_verified_backup*.py returned 173 passed with no skips. Separate direct calls verified the retained row, write refusal and byte-for-byte file preservation for an ordinary name and one containing a space, non-ASCII text, %, # and ?. Opening a missing backup failed and created no file. The share-shaped URI test exercises real SQLite using a local file. Native Windows SMB remains unverified.
