# Issue 116 explicit creation retry — November 2, 2026

Source `3b1b875161ddfc438dbac45327225e7a8161668b`, tree
`7f13fb0bacdb1a107323419fdfe7a512dde5ecec`, with initial checkpoint
`7c20e546ef2b759be963181f21177ec263aa71d6`, based on reviewed staging tip
`5b247c061c6faba5df2e42876d811807fae9d75f`. This follow-up addresses the remaining
GUI boundary for recognizable incomplete creation directories. It does not close
the broader issue or change the ordinary absent/empty-directory Create action.

The New dialog offers a separate **Check and retry incomplete creation** outcome.
That outcome requests validation, not acceptance of the directory. The existing
background worker stages both inputs privately, acquires the existing project
lock without creating or rewriting its file, then validates a closed directory
layout before the store can recycle a database. Validation permits only the lock,
an optional exact empty project database, and optional artifact copies matching
the selected input hashes. All relevant ancestors/entries are checked for links,
reparse points, identities and content versions; regular files with multiple hard
links are refused. Complete static PE/hash validation is required for reused
artifacts. No recovery receipt authorizes deletion.

The database validator is read-only/immutable, caps input at 1 MiB and SQLite work
at 100,000 VM steps, requires the exact generated version-1 empty schema and a
successful integrity check, and rejects snapshots, history, sequence rows,
foreign schema objects and sidecars. Ordinary service abandoned-database retry
behavior is unchanged. The explicit route refuses malformed/zero-byte databases
and unknown files instead of repairing them. A final identity/content/entry-set
recheck runs under the same held lock immediately before recycling. New database
and artifact paths are created exclusively; a newly appeared foreign database is
never adopted or overwritten, and retry never authorizes deleting sidecars.

Two database publication collision controls were red before exclusive creation:
a foreign SQLite database introduced at the connection seam gained project tables
and creation succeeded. With retry-only exclusive database creation, both controls
refuse the collision and preserve the foreign database. A modeled Windows
reparse-ancestor refusal exercises the actual retry consumer; it is a portable
control, not native Windows evidence.

Independent review of the initial checkpoint found that `abspath` removed a
linked component before `..`, preventing the intended lexical refusal. Real
symlink and modeled reparse controls both reproduced acceptance before repair.
The follow-up preserves the original lexical path, records every directory
identity before resolution, and rechecks those original components under the
held lock. Both controls now refuse without changing destination bytes; an
ordinary unlinked directory followed by `..` remains supported after checking.

The worker closes its SQLite service before GUI-thread reopening. The completion
value retains its own cancellation token and the initiating service/project key;
cancelled, changed-project and changed-revision results are not adopted. A
completed directory is retained and identified in the job log. Actual Qt worker
controls check background-thread execution and a live GUI timer while validation
is paused, cancellation during validation with every destination byte unchanged,
and cancellation or project/revision changes after commit with the created
project still reopenable.

Author validation, using the shared Python with offscreen Qt and
`PYTHONPATH=.:src:tests`:

```text
pytest -q tests/test_ui_project_retry.py tests/test_project_retry.py
  tests/test_creation_116.py tests/test_ui.py tests/test_tooltips.py
  tests/test_gui_host_seam.py tests/test_service_storage_audit.py
  tests/test_core.py tests/test_ingestion_core10.py
  tests/test_acquisition_quarantine.py tests/test_acquisition_workflow.py
  tests/test_ui_kb_create_cancellation.py tests/test_ui_kb_current_project.py
```

**239 passed in 38.69s**, with no skips. Whole-repository Ruff and diff checks
passed. `ui.py` is 2,987 lines after extracting/re-exporting the dialog; the ceiling
remains 3,077. Existing tooltip inventory and actual modal tests include the new
action. No model/wire schema changed.

Independent review at exact source `3b1b875` reported no remaining blocker:
**82 focused tests passed in 4.80s**, including six independent real symlink,
modeled reparse, ordinary `..`, malformed-both-input and pre-recycle cancellation
controls, plus actual Qt worker tests. This selection overlaps the author run and
is not an additive total. The coordinator owns
`reviews-resume/creation-explicit-retry-review-20261102.{json,md}`; the original
lexical blocker remains recorded as resolved, not omitted.

No full combined
suite, native Windows, native backend, performance or release acceptance is
claimed. Inputs were synthetic PE bytes and were never executed. No remote
mutation or issue closure was performed by this worker.
