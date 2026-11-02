# Independent review: project creation staging and cleanup

No remaining blocking findings after the constructor cleanup and locked-descriptor follow-up.

- Final source: `86c5b23f9441d4f6d947fc4a59fe6e3ac53c06ac`
- Tree: `d5f565653fc884eade6da87d7390d140d846a157`
- Base: `ce6002ec36732f2d27e8e6233b8fbe305eeb6112`
- Required source commits: `0e049152` and `86c5b23`.
- QA-only descendant: `5b247c061c6faba5df2e42876d811807fae9d75f`

## Scope and reasoning

- Both input copies and the first validated snapshot are prepared in a private temporary project before opening the chosen destination. Malformed input on either side, partial staging, interruption and private snapshot validation failure leave the target absent or unchanged.
- Destination artifact publication uses exclusive creation. Existing artifact files are reused only after exact-content and PE validation with identity/content-version checks; they are not claimed for cleanup or overwritten. Only verified files created by this attempt enter its cleanup ledger.
- Failure cleanup runs while the kernel project lock remains held, checks root/lock/database identities and snapshotless state, and preserves committed snapshots, history, foreign tables, unknown files, replaced directories and changed artifacts. Recursive deletion is limited to private staging; the persistent user-root lock remains.
- Initial source0e049152 still delegated target-initialization errors to an unlock-then-unlink constructor path. A fresh real SQLite fault proved that a competing lock was acquirable during unlink. Follow-up86c5b23 closes SQLite, rechecks ownership and snapshotless state, unlinks before finally releasing the lock, and handles interruptions as well as ordinary failures.
- Constructor and publication lock identities now derive from the held file descriptor and must match the pathname. A real lock-file rename/replacement before publication is refused before artifacts appear, preserving the foreign pathname bytes.
- A successful first destination commit survives later exceptions, KeyboardInterrupt and private cleanup failure, with the lock released and the project reopenable. Existing abandoned-database service retry remains supported.

## Independent validation

- 111 passed in 4.76 seconds. Independent target CREATE TABLE history failure nevertheless exposed the lock-ordering blocker; initial result was not treated as final acceptance.
  Command: `Initial frozen0e049152 authored bounded selection`
- 123 passed in 5.10 seconds on frozen86c5b23. The retained control file contained the first three independent cases at collection: constructor lock ordering, same-inode/size/restored-mtime foreign artifact preservation, and postcommit KeyboardInterrupt preservation.
  Command: `QT_QPA_PLATFORM=offscreen PYTHONPATH=.:src:tests /workspace/scratch/142cb233d750/venv/bin/python -m pytest -q --tb=short /workspace/scratch/142cb233d750/reviews-resume/test_creation_independent.py tests/test_creation_116.py tests/test_service_storage_audit.py tests/test_core.py tests/test_ingestion_core10.py tests/test_acquisition_quarantine.py tests/test_acquisition_workflow.py tests/test_ui_kb_create_cancellation.py tests/test_ui_kb_current_project.py`
- 1 passed in 0.26 seconds, disjoint from the123 selection; actual Linux pathname replacement retained its foreign bytes and prevented artifact publication.
  Command: `QT_QPA_PLATFORM=offscreen PYTHONPATH=.:src:tests /workspace/scratch/142cb233d750/venv/bin/python -m pytest -q --tb=short /workspace/scratch/142cb233d750/reviews-resume/test_creation_independent.py::test_actual_precapture_lock_replacement_is_refused_without_artifact_publication`
- Passed; six changed paths over the two source commits, clean final worktree.
  Command: `Ruff changed Python files; git diff --check ce6002ec..86c5b23; source equality against QA-only5b247c0`

## Limits

- The fixed GUI journey is corrected-input retry after private validation failure. Later destination publication failures can leave a nonempty directory; its explicit GUI recovery route remains separate, with the existing nonempty-directory guard unchanged.
- No native Windows packaging/locking claim, power-loss durability, hostile filesystem writer immunity, full suite, or performance run. Native platforms that refuse open-directory or lock renames require their platform gates.
- Profile/stale-task changes preceding ce6002ec were already separately reviewed and are outside this receipt; this does not close all of issue116.
- No repository source edits, target execution, remote mutation, or GitHub approval performed.

The JSON sibling binds every changed file, the original finding, and both retained control-script versions by SHA-256.
