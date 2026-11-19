# Project creation cancellation and adoption recovery — 2026-11-19

## Scope

This slice starts at `046ad6e622d5c446889da8a9e44bd5bc2638395f` and
recovers ordinary-source creation cancellation and context-bound desktop
adoption through the current core. It does not restore the historical
database-replacement implementation. Current owned artifact rollback,
in-place empty-database retry validation and transactional GUI adoption
remain authoritative.

`ProjectService.create` accepts the existing neutral read checkpoint for
ordinary pathname inputs. It validates that policy before destination work,
forwards it through both artifact inspections and the first save, and does
not invoke it after a successful save. Held-input callers retain their
captured policy and cannot supply an independent replacement callback.

The New Project adapter captures the original service, complete project key
and worker cancellation event. Early cancellation uses existing owned
rollback. A committed result is adopted only into the same active context;
cancelled, closing or stale delivery retains the completed directory. The
worker closes its SQLite service before GUI-thread reopening. A busy or
closing window does not open another creation modal.

The absent explicit UI action for a verified incomplete project directory
is a separate recovery opportunity. This slice adds no retry parser,
database recycling or new on-disk schema.

## Meaningful verification

Before implementation, the new controls produced **13 failures and 2
passes in 6.56 seconds**: nine core controls showed the missing ordinary
checkpoint API, and four real Qt controls showed early cancellation,
different-project delivery, changed-revision delivery and busy-modal gaps.
Current successful adoption and retained postcommit cancellation were
positive baseline controls.

The focused implementation selection then passed **15 tests in 13.68
seconds**. The final adjacent regression selection passed **189 tests in
67.68 seconds** using real SQLite stores, self-made PE fixtures and actual
offscreen Qt worker lifecycles. It covered cancellation in copy and before
COMMIT for new, zero-byte and exact-empty databases; preservation of prior
bytes and foreign files; successful retry and reopening; no postcommit
callback; immutable held-operation policy; GUI responsiveness; stale
delivery; and existing schema, replacement, adoption and rollback controls.

```sh
QT_QPA_PLATFORM=offscreen PYTHONPATH=.:src:tests \
  /workspace/scratch/792fd5ca6555/.venv/bin/python -m pytest -q -p no:cacheprovider \
  tests/test_project_creation_checkpoint.py tests/test_ui_project_creation_lifecycle.py \
  tests/test_ingestion_held_inputs.py tests/test_creation_operation_checkpoint.py \
  tests/test_project_creation_identity.py tests/test_project_creation_stat_views.py \
  tests/test_audit116_create_rollback.py tests/test_gui_project_adoption.py \
  tests/test_gui_creation_retry.py tests/test_creation_schema_refusal.py \
  tests/test_creation_replacement_refusal.py tests/test_ui.py \
  --junitxml=/workspace/scratch/792fd5ca6555/project-lifecycle-final.xml
```

The command ran from `pt-adapters`; the corresponding task-root log is
`project-lifecycle-final.log`. Scoped Ruff and `git diff --check` passed.
No target program, native analysis engine or live transport ran. These
controls do not establish native Windows qualification or a new hostile
filesystem publication guarantee.

## Tested source fingerprints

| Path | SHA-256 |
| --- | --- |
| `src/patchtrace/service.py` | `680b938a4512bf67542140dadb3b20b2dea404904b6d01079333fb8ff6bd219e` |
| `src/patchtrace/ui.py` | `5c98b880ee390f1cda022a999b83079ce5629d1fd4b757095b8c12662caf1418` |
| `src/patchtrace/ui_new_project.py` | `c781e82576e02397269058c6df8468bf04b9eaa7271a4fe4e53fd3d09e938cae` |
| `tests/test_project_creation_checkpoint.py` | `dfd6537702e50e01153951d7e29b4e4c4a6f5528264ccd7b46e325354d0c6a9c` |
| `tests/test_ui_project_creation_lifecycle.py` | `943bb144ad474cffd0f4889674f299f9aef295f54fd7b4276bae59136a58546c` |

## Follow-up: retain the primary creation failure during cleanup

Independent review of the first frozen checkpoint `fbf95d94` approved the
new creation/adoption behavior and reran its 15 controls successfully. It
also reproduced an adjacent older defect: secondary `KeyboardInterrupt`
from store closure replaced an active `InputReadError('cancelled')`.

The follow-up explicitly passes the active primary exception into owned
creation cleanup. Secondary ordinary exceptions and process interruptions
produce bounded notes, uncertain database state keeps files, independent
recorded-file cleanup attempts continue after an interrupted deletion,
and store closure is always attempted. A first snapshot already committed
before the primary failure remains reopenable.

The new 15-case selection first failed on the original checkpoint. Cases
cover real SQLite rollback, connection close, store close and owned
artifact deletion, plus failures after the real first COMMIT, with
`RuntimeError`, `KeyboardInterrupt` and `SystemExit` as secondary faults.
The ordinary secondary-failure cases additionally verify the newly
required diagnostic notes; they do not all represent primary masking.

After the repair, **123 tests passed in 4.02 seconds**:

```sh
QT_QPA_PLATFORM=offscreen PYTHONPATH=.:src:tests \
  /workspace/scratch/792fd5ca6555/.venv/bin/python -m pytest -q -p no:cacheprovider \
  tests/test_project_creation_cleanup_primary.py tests/test_project_creation_checkpoint.py \
  tests/test_audit116_create_rollback.py tests/test_project_creation_identity.py \
  tests/test_project_creation_stat_views.py tests/test_creation_operation_checkpoint.py \
  tests/test_creation_schema_refusal.py tests/test_creation_replacement_refusal.py \
  --junitxml=/workspace/scratch/792fd5ca6555/project-creation-cleanup-final.xml
```

Logs are `project-creation-cleanup-red.log` and
`project-creation-cleanup-final.log` at the task root. Scoped Ruff and
`git diff --check` passed. The fingerprint table above describes the first
checkpoint; this follow-up intentionally changes `service.py` and adds
`tests/test_project_creation_cleanup_primary.py`.
