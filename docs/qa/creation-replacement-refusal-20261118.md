# Creation retry ownership follow-up — 2026-11-18

## Why the first checkpoint was insufficient

Independent review of `e181d26bd5b7790a4f20e10cf360e465c57090a9` replaced
`project.sqlite3` with an authored foreign database immediately after the real
`_abandoned_creation` check returned true. Creation then deleted/replaced that
foreign database. Strict schema admission had repaired the earlier malformed
schema cases, but boolean admission still authorized a later pathname unlink.
The unchanged independent probe failed once in 0.24 s.

The earlier [schema-refusal receipt](creation-schema-refusal-20261118.md) and its
archive remain a historical checkpoint. They were not rewritten to claim this
replacement case had passed. The original archive still has SHA-256
`49cae9cb991c4f075a7415f380dde95fd613c7566be5b0827110386a81531076`.

| Checkpoint | Exact commit |
|---|---|
| Original schema repair / replacement-red source | `e181d26bd5b7790a4f20e10cf360e465c57090a9` |
| Historical QA tip | `b2cf236f2a85073625af7aed77443dfd0a5b968f` |
| Follow-up specification and regressions | `65ce9e629e1ca23ce2ffe031acf3a655a49c6353` |
| Follow-up source | `8b3c6472705cd486743ca4b2081d4a1df421945d` |

The spec/test commit has no production-source difference from the red source.
The worktree is `/workspace/scratch/c7a9e8d98848/creation-schema`, branch
`codex/creation-schema-refusal-20261118`. Production edits are confined to
`persistence.py` and the explicitly authorized service rollback ownership seam.
No historical project-publication or GUI retry stack was ported.

## Ownership strategy

An admitted database is reused in place. The retry path no longer unlinks the
preexisting database or any companion file. Candidate identity, size, timestamps
and companion absence are checked before and immediately after writable
connection opening. The exact schema, version, integrity and row-emptiness checks
then run on that actual SQLite connection within its initial transaction.
Temporary admission limits are restored before ordinary project saves.

Existing current tables are kept. For a preexisting zero-byte file, initialization
stays in the first-save transaction: ingestion failure, save failure or closing
an unpublished retry rolls it back to the original bytes. Successful first save
commits schema and project together. The controls retain the same database inode
for both current-empty and zero-byte retries.

A fresh database is reserved with exclusive file creation and recorded as this
attempt's creation. Service rollback receives that ownership record instead of
adopting a later `stat` of the public pathname. A reused database has no such
deletion record. Rollback first undoes any uncommitted retry initialization,
retains an already committed first snapshot, removes only recorded artifacts and
only considers deletion of an exclusively created database. Initialization
failure also retains any observed replacement of the newly reserved file.

This changes the destructive behavior, rather than relying on one more
stat-before-unlink for an admitted file. The existing project lock remains the
coordination boundary. The stricter schema and 1 MiB admission bounds from the
first repair remain; current DDL and schema version are unchanged.

## Red/green evidence

| Run | Result |
|---|---|
| Original unchanged independent replacement probe at the first repair | **1 failed** in 0.24 s |
| Initial authored replacement controls at the first repair | **13 failed**, no errors/skips, in 0.57 s |
| Expanded authored controls before follow-up production edits | **24 failed**, no errors/skips, in 0.57 s |
| Focused follow-up run | **86 passed** in 0.90 s |
| Exact committed source, affected gate | **230 passed** in 3.77 s |
| Exact committed source, unchanged external controls | **7 passed** in 0.21 s |
| Actual-connection schema control on detached spec/test source | **1 failed** in 0.28 s |
| Same actual-connection control on follow-up candidate | **1 passed** in 0.19 s |
| Full normal Ruff, `src tests tools` | Passed |
| `git diff --check` | Passed |

The 24 authored controls cover replacement immediately after admission for both
current-empty and zero-byte files, replacement at connection opening, all three
companion types, replacement before a forced initialization error, retry failures
at both ingestion steps and before/during save, close without publication, and a
replacement of a freshly reserved database. Failure controls compare retained
bytes and database identity and require that newly published artifacts are
cleaned up. Existing successful new creation, healthy retries, rollback and
post-commit preservation controls remain in the affected gate.

The seven external controls comprise the original independent replacement test,
the original three schema failures plus healthy control, the actual retained-WAL
view control, and a new actual-connection control. The last control commits a
real view through a separate SQLite connection after pathname checks and before
`BEGIN IMMEDIATE`; the actual-connection schema validation refuses it and retains
its bytes. It was replayed red against detached
`/workspace/scratch/c7a9e8d98848/creation-schema-replacement-red` at the spec/test
commit, whose source is the first repair, and green without changing the test.

Runtime was Python 3.12.14 with SQLite 3.53.1. All runs used the shared virtualenv
and an absolute source `PYTHONPATH`; CLI subprocess controls propagate that exact
source. The exact affected command was:

```sh
env QT_QPA_PLATFORM=offscreen \
  PYTHONPATH=/workspace/scratch/c7a9e8d98848/creation-schema/src \
  /workspace/scratch/3a6632a6e5ff/venv/bin/python -m pytest -q \
  tests/test_creation_replacement_refusal.py tests/test_creation_schema_refusal.py \
  tests/test_service_storage_audit.py tests/test_audit_core.py \
  tests/test_audit116_create_rollback.py tests/test_persistence_security_20261105.py \
  tests/test_gui_creation_retry.py tests/test_project_cli.py tests/test_core.py \
  tests/test_enrichment_storage.py --tb=short \
  --junitxml=/workspace/scratch/c7a9e8d98848/qa/creation-schema/replacement-affected.xml
```

The imported source and complete commands are retained in
`repair/replacement-affected-context.json` and
`repair/replacement-final-context.json`. Exact source SHA-256 values are:

- `persistence.py`: `148f30ebf736923177db43114d10277246fabd35f6c8be1366082ec4955ce9be`.
- `service.py`: `4833ea5b9a3e876081e04b86dbd89b2828ecccd6bc8c80f7e2192b65b180d550`.

## Practical limits

These checks establish the reproduced admission, connection-opening,
actual-connection and rollback behavior on this runtime. They do not provide
arbitrary namespace-race immunity. A noncooperating process can still rename
files or create journal state between checks. SQLite may perform recovery when
it first accesses database pages; this implementation does not add a private
quarantine/publication protocol or a custom SQLite VFS. Final cleanup of an
exclusively created file still uses the existing cooperative pathname/identity
model. The journal and namespace limitations are explicit in the specification.

A small separate runtime observation found that merely opening and closing a
connection, before any SQL/page access, retained three authored companion-file
forms. This supports the tested immediate post-open checks on SQLite 3.53.1; it
is not a portable proof that all SQLite recovery paths are non-mutating. The
earlier WAL observation remains preserved in the first packet.

All databases, payloads and PE inputs here are authored temporary data. No target
was executed, no frozen result was changed, and no native Windows/filesystem,
whole-suite, release or backend-accuracy qualification is claimed. Independent
root review of this exact follow-up source is required before integration.

## Retained follow-up packet

- `docs/qa/creation-replacement-refusal-20261118/manifest.json`: every member's size and SHA-256.
- `docs/qa/creation-replacement-refusal-20261118/evidence.zip`: **32 members, 58,258 bytes**.
- Archive SHA-256: `d4e51be8674867b57776ea2ae62dc20237d98caacc868fa157073b0d7bd1fd36`.

Every member was reread and matched to the manifest. Original external probe and
red evidence remain untouched under `/workspace/scratch/c7a9e8d98848/qa`; raw
follow-up receipts are under `qa/creation-schema` with `replacement-` and
`actual-connection-` prefixes.
