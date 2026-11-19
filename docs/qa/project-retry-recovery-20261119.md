# Explicit project retry recovery — 2026-11-19

## Scope and implementation decisions

This slice follows the independently reviewed lifecycle checkpoints
`fbf95d94792ef45a0e875bfe4c921c0c7675d592` and
`950da8f1ce058b88c3f2d014fc1e252ab0a16e2f`.
The historical `project_retry.py` / `project_creation.py` behavior at
`c13d3257` identified a missing explicit desktop recovery action. Its old
database recycling and publication implementation was not carried forward.

The current port adds `ProjectService.retry_create` and a strict
`project_retry.py` adapter. It stages the selected inputs privately through
the current core, verifies a bounded incomplete destination under its
existing kernel lock, publishes through current ingestion and saves through
the current store. A private store validator runs and rechecks before
database admission. Its existing exact-schema, read-only eligibility,
writable-connection identity checks and in-place transaction remain intact.
The optional preserve-existing lock mode does not create or rewrite the
retained lock file. Ordinary creation behavior is unchanged.

The explicit retry accepts only the lock, an optional current-empty or
zero-byte database, and up to two exact selected artifact copies. It refuses
unexpected entries, linked/reparse paths, mismatched inputs and existing
project data. Original input names remain in the recovered project.
Private staging is cleaned before the destination can commit. Failure uses
the reviewed primary-preserving owned rollback; it never claims ownership
of preexisting database or artifact paths for deletion.

The desktop action shares the reviewed worker cancellation and captured
project-context adoption adapter. Ordinary Create still refuses incomplete
database/artifact directories. Retry validation and preparation run off the
GUI thread; refused/cancelled retry retains the current view and old files.

## Meaningful verification

The first 50 controls all failed before implementation because the explicit
retry API and action were absent. They then passed in 5.07 seconds. These
are feature-recovery controls, not 50 separate defects in existing ordinary
creation. Six further controls covered private cleanup failure (including
an unrelated handled caller exception), secondary cleanup interruption,
changed private source bytes, failure after real destination COMMIT and
invalid checkpoint admission.

Self-review then found an actual boundedness gap in the initial adapter:
current `sha256_file` reads until EOF, so a file growing after its initial
size check could keep verification reading. A real-file growth control
failed before the retry-local read-budget fix. The adapter now supplies
finite actual-read limits for private preparation, retained verification,
destination copies and final save, while forwarding each actual read to
the caller's checkpoint. The growth control stops after the first bounded
read exceeds the selected-input allowance; no database or lock bytes change.

The final selection passed **255 tests in 26.90 seconds** on the Linux
executor. It uses real SQLite transactions, actual artifact copies and
offscreen Qt workers with self-made PE fixtures. Fault and race injections
are explicitly authored test controls. The exact command was:

```sh
QT_QPA_PLATFORM=offscreen PYTHONPATH=.:src:tests \
  /workspace/scratch/792fd5ca6555/.venv/bin/python -m pytest -q -p no:cacheprovider \
  tests/test_project_retry_recovery.py tests/test_ui_project_retry_recovery.py \
  tests/test_project_creation_cleanup_primary.py tests/test_project_creation_checkpoint.py \
  tests/test_ui_project_creation_lifecycle.py tests/test_ingestion_held_inputs.py \
  tests/test_creation_operation_checkpoint.py tests/test_project_creation_identity.py \
  tests/test_project_creation_stat_views.py tests/test_audit116_create_rollback.py \
  tests/test_gui_project_adoption.py tests/test_gui_creation_retry.py \
  tests/test_creation_schema_refusal.py tests/test_creation_replacement_refusal.py \
  tests/test_tooltips.py::test_new_project_dialog tests/test_gui_host_seam.py \
  --junitxml=/workspace/scratch/792fd5ca6555/project-retry-final.xml
```

The command ran from `pt-adapters`. Task-root logs are
`project-retry-red.log`, `project-retry-growth-red.log` and
`project-retry-final.log`. Scoped Ruff and `git diff --check` passed,
including newly added files.

## Bounds of this receipt

No target program, native analysis engine or live transport ran. Portable
link/reparse controls do not establish native Windows qualification. The
operation retains the cooperative project lock model; it does not turn
multi-file publication into an atomic operation or defeat arbitrary
noncooperating pathname changes between checks. Existing uncertain-state
retention and owned-cleanup limits remain documented in the architecture
and the new project retry specification.

## Tested source fingerprints

| Path | SHA-256 |
| --- | --- |
| `src/patchtrace/project_retry.py` | `eaf7af99e4ac035342930bb1f6d6cca18aabb3eee6508f23b51b9fad1f825fbb` |
| `src/patchtrace/persistence.py` | `a78a7483ffa6473d64546fbf8cb1ded349ba3188aa4eb2af4366d285c74bf7e5` |
| `src/patchtrace/service.py` | `7719fa860b145a0ec3f98bba7e8523235773dc85bdd8ef0f2ff3b4cc6b0ef64e` |
| `src/patchtrace/ui_new_project.py` | `5215804b3274287f442d4ea830de585ed204ac267ce28968cdf76be199886405` |
| `src/patchtrace/ui.py` | `98dab69522ffe6b03b7e82a36494bdf5bf5e6e0ee7582449fb7c0a3545ef5964` |
| `src/patchtrace/tooltips.py` | `0bbba86b1ffc2e69dc7a39c74493636749276cbd2f43ae278caf9e0b46df091a` |
| `tests/test_project_retry_recovery.py` | `19e39fd028e559a2a8cf604f5b6ddd173009d3b23e81511847ffde27dbb35fe1` |
| `tests/test_ui_project_retry_recovery.py` | `9e41f45e94c80bb83a79bbbbb2c3d4ab1c1144038082dbbccb0e6f22a2c43147` |

## Independent-review follow-up: private stage substitution

Security review of `72255922d06baa51c3f3394c1d36931888456923` reran its
57 new controls successfully, then found a concrete preservation blocker:
after the second real destination copy but before cleanup, renaming the
private stage and placing an ordinary foreign directory at its old path
caused `TemporaryDirectory.cleanup()` to delete the replacement. The
independent probe is `project-retry-stage-substitution-probe.log` at the
task root. That checkpoint was held from integration.

The repair detaches the temporary directory's automatic finalizer
immediately, captures its ordinary directory and lexical ancestor
identities before use, and rechecks them before recursive cleanup.
Missing, linked or replaced ownership refuses completion and retains
ambiguous paths; an active primary cancellation survives with a bounded
cleanup note. No delayed finalizer may later remove the replacement.
The final check-to-removal race remains an explicit qualification limit;
this is not a native handle-based recursive deletion primitive.

Two actual rename-and-replacement controls first failed on the prior
checkpoint, then passed after repair. They cover both ordinary completion
and concurrent cancellation, check retained replacement bytes after
garbage collection, keep the displaced original stage observable, preserve
the prior destination, and verify release of the destination lock.
The final bounded selection passed **74 tests in 5.81 seconds**:

```sh
QT_QPA_PLATFORM=offscreen PYTHONPATH=.:src:tests \
  /workspace/scratch/792fd5ca6555/.venv/bin/python -m pytest -q -p no:cacheprovider \
  tests/test_project_retry_recovery.py tests/test_ui_project_retry_recovery.py \
  tests/test_project_creation_cleanup_primary.py \
  --junitxml=/workspace/scratch/792fd5ca6555/project-retry-stage-final.xml
```

Logs are `project-retry-stage-red.log` and `project-retry-stage-final.log`
at the task root. Scoped Ruff and `git diff --check` passed. The earlier
fingerprint table describes `72255922`; this follow-up changes only its
retry source, retry test, specification and this receipt.
