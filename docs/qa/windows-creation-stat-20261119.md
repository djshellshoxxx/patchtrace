# Windows project creation metadata repair

Reviewed source: `f2b6827fc6270b96fb241b0722f2878de5a17361` (PR #316).
Evidence captured 2026-11-19 UTC. This repair does not qualify a release.

## Reproduced failure

The Windows QA job
[135257238573](https://github.com/djshellshoxxx/patchtrace/actions/runs/44433724017/job/135257238573)
reported `PT-STORAGE: project database changed during creation admission` on
otherwise ordinary new project creation. The repeated Qt job
[135257238989](https://github.com/djshellshoxxx/patchtrace/actions/runs/44433724017/job/135257238989)
failed all five repetitions of `test_new_wizard_retries_after_real_failed_creation`.
The admission code captured `os.fstat(fd)` and compared its timestamp fields with
a later `Path.lstat()` observation. Windows can expose different change-time
meanings across those APIs.

`tests/test_project_creation_stat_views.py` reproduces the cross-observation
failure while creating actual authored PE inputs and a real SQLite project.
Only the observed descriptor change time is varied; no SQLite or ingestion
success is mocked. Before repair: **1 failed, 8 passed**. The failure is the same
creation-admission error as the hosted Windows failure.

## Repair and retained guards

Keep the exclusively opened descriptor until its pathname is admitted. Compare
their physical identity, size and modification time, and require descriptor
metadata to remain stable around that observation. The later pathname checks
use the captured pathname snapshot, retaining their own change-time checks.
Descriptor change time remains checked against the descriptor observation.
Regular-file/link-count checks, companion refusal, exclusive ownership,
transactional retry and replacement preservation remain in place.

## Local verification

Linux, Python 3.12.14, shared project development dependencies:

```sh
QT_QPA_PLATFORM=offscreen PYTHONPATH=src python -m pytest -q \
  tests/test_project_creation_stat_views.py \
  tests/test_audit116_create_rollback.py tests/test_service_storage_audit.py \
  tests/test_project_creation_identity.py tests/test_gui_creation_retry.py \
  tests/test_project_store_constructor_cleanup.py
python -m ruff check src/patchtrace/persistence.py tests/test_project_creation_stat_views.py
git diff --check
```

Result: **117 passed in 16.53 seconds**. Ruff and whitespace checks passed.
The controls include changed device/inode, size, modification time, nonregular
type, multiple links, descriptor change-time drift and pathname change-time
drift. Full suite and native Windows validation must run on the integrated
source. These local observation controls are not native Windows acceptance.

Other PR #316 Windows fixture, native-harness and security-scan failures remain
separate work; this patch does not claim to repair them.
