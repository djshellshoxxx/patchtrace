# Incomplete-creation schema refusal — 2026-11-18

## Finding and source

The existing creation retry check could replace a database containing an
unrecognized view, trigger or additional column. It checked only non-internal
table names and whether `current_snapshot` and `history` held rows. Those checks
did not establish that the database was the empty schema created by PatchTrace.
The original independent probe reproduced three failures through the real
`ProjectService.create` path, with a healthy empty-current retry as its positive
control. All inputs and databases in these checks are authored temporary data.

| Checkpoint | Exact commit |
|---|---|
| Published baseline | `58fc130631f602b6e907bb054d30c21d810551d4` |
| Original independent-review source | `ac789497597fba3cb87696990d171a7a27024fca` |
| Specification and failing tests | `52873c1b1f2ebfa38ceb247aac7d3427ccddcb3d` |
| Candidate source | `e181d26bd5b7790a4f20e10cf360e465c57090a9` |

The baseline and original-review `persistence.py` bytes are identical, SHA-256
`4cdacd4d964e9b919e667d2d0e038a0d62251f0b49d751f60bb16f1b03101669`.
Their `_abandoned_creation` function hash is
`461aa98d6d87005e927d0401b69727fd01c207c2aded4c882d59fb8966c94e2c`.
The candidate file hash is
`41f90c526f1c193640e8bcb81c0f491b3a9cf0a9bc6e339147790b3e0675e1c6`.

Worktree: `/workspace/scratch/c7a9e8d98848/creation-schema`, branch
`codex/creation-schema-refusal-20261118`. Production changes are confined to
`src/patchtrace/persistence.py`. The existing current table definitions are
factored into constants and reused by initialization and validation; an AST
comparison against published source confirmed that both SQL strings are
byte-for-byte unchanged. There is no schema migration.

Historical `project_retry._database` at
`c13d3257c88140c23fb585a8a59a4dce81e81928` supplied the strict-schema and bounded
validation approach. Its extracted function and source identity are retained as
provenance. The historical publication, retry-service and GUI stack were not
ported. Current source and historical source are separate checkpoints.

## Behavior

Under the existing project lock, a nonempty retry candidate must be a regular,
singly linked file no larger than 1 MiB. Validation requires the current database
version, exactly the existing current/history/sequence table definitions, an
integrity-check success, and no rows in any of those tables. Extra schema
objects, altered table definitions, retained sequence state and unrecognized
empty-schema databases refuse reuse. The zero-byte regular-file retry remains
supported.

Any journal, WAL or shared-memory companion causes refusal before SQLite opens
the candidate. The subsequent probe uses a read-only immutable connection,
`trusted_schema=OFF`, 1 MiB value and 4 KiB SQL limits, and a progress-handler
instruction budget. Refusal preserves the database, companions and unrelated
entries, releases the project lock, and returns the existing storage error. The
ordinary lock holder record may change; the persistent lock inode remains.

The primary SQLite [URI documentation](https://www.sqlite.org/uri.html),
[trusted-schema documentation](https://www.sqlite.org/pragma.html#pragma_trusted_schema)
and Python [progress-handler](https://docs.python.org/3.12/library/sqlite3.html#sqlite3.Connection.set_progress_handler)
and [runtime-limit](https://docs.python.org/3.12/library/sqlite3.html#sqlite3.Connection.setlimit)
interfaces were checked. A bounded observation on SQLite 3.53.1 found that a
normal read-only connection saw one authored WAL row while an immutable read
saw zero. The normal read also changed shared-memory bytes. That observation is
retained honestly and supports refusing companions before opening SQLite; it
is not a claim that a general read-only connection preserves every companion.

## Verification

Runtime: Python 3.12.14, SQLite 3.53.1, shared virtualenv
`/workspace/scratch/3a6632a6e5ff/venv/bin/python`. All source runs used absolute
`PYTHONPATH` and `QT_QPA_PLATFORM=offscreen`; CLI subprocess tests explicitly
propagate the imported worktree source path. No target binary or native engine
was executed.

| Evidence | Result |
|---|---|
| Original independent probe replay on published source | **3 failed, 1 passed** in 0.26 s |
| First authored-test baseline | **20 failed, 2 passed**; one failure was a test-harness misuse of `ProjectLock` as a context manager |
| Corrected authored tests before production edits | **20 failed, 3 passed** in 0.54 s; corrected lock cleanup and added a linked-file refusal control |
| Focused candidate gate | **48 passed** in 0.72 s |
| Exact committed source, affected gate | **206 passed** in 4.55 s |
| Exact committed source, unchanged original external controls | **4 passed** in 0.21 s |
| Additional actual WAL view control on published source | **1 failed** in 0.20 s: creation did not refuse |
| Same unchanged WAL control on candidate source | **1 passed** in 0.21 s; database/WAL/SHM bytes preserved |
| Full normal Ruff, `src tests tools` | Passed |
| `git diff --check` | Passed |

The corrected baseline includes schema objects, changed constraints/version,
retained sequence metadata, absent canonical schema, all three companion types
for current-empty and zero-byte databases, pre-open size refusal, nonregular and
multiply linked files. Healthy current-empty and zero-byte inputs both create
and reopen through the real service. A foreign table is an existing refusal
positive control. Original and intermediate failures were retained without
rewriting them into later results.

The exact affected gate was:

```sh
env QT_QPA_PLATFORM=offscreen \
  PYTHONPATH=/workspace/scratch/c7a9e8d98848/creation-schema/src \
  /workspace/scratch/3a6632a6e5ff/venv/bin/python -m pytest -q \
  tests/test_creation_schema_refusal.py tests/test_service_storage_audit.py \
  tests/test_audit_core.py tests/test_audit116_create_rollback.py \
  tests/test_persistence_security_20261105.py tests/test_gui_creation_retry.py \
  tests/test_project_cli.py tests/test_core.py tests/test_enrichment_storage.py \
  --tb=short \
  --junitxml=/workspace/scratch/c7a9e8d98848/qa/creation-schema/affected.xml
```

`repair/affected-context.json` records the imported module, clean source commit,
runtime, full command and file hashes. `repair/final-context.json` records the
external replay identity and unchanged canonical DDL. The original independent
test remains untouched at
`/workspace/scratch/c7a9e8d98848/qa/semantic-disposition-batch1/test_incomplete_creation_refusal_review.py`.

## Scope and remaining review

This is a bounded refusal repair within the existing cooperative project-lock
model. It does not add an atomic conditional unlink, an OS filesystem sandbox,
a general SQLite migration/recovery feature or a wall-clock I/O deadline. The
existing noncooperating pathname-replacement limitation remains. Desktop and
CLI destination preflights keep their stricter existing behavior. No frozen
outcome was changed, no target was downloaded or executed, and no release,
native-platform acceptance or full-suite qualification is claimed.

Independent root review is required before integration. The S310/S603/S608
source-trace checkpoint remains a separate read-only triage task; this repair
does not settle those scanner dispositions.

## Retained packet

- `docs/qa/creation-schema-refusal-20261118/manifest.json` records every member size and SHA-256.
- `docs/qa/creation-schema-refusal-20261118/evidence.zip`: **34 members, 49,049 bytes**.
- Archive SHA-256: `49cae9cb991c4f075a7415f380dde95fd613c7566be5b0827110386a81531076`.

Every member was reread and verified against the manifest. Raw receipts remain
in `/workspace/scratch/c7a9e8d98848/qa/creation-schema`.
