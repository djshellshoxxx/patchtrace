# Service and storage bug hunt (BH-svc, 2026-10-14)

Scope: `service.py`, `persistence.py` (store, snapshot, history, lock, backup), `models.py`, `ingestion.py`
(project files), read-only `artifact_bytes.py`. Method: code and spec reading, scratch probes outside the repo,
SIGKILL and random-operation fuzzing on Linux (Python 3.13, SQLite 3.45), then red/green regression tests in
`tests/test_service_storage_audit.py`. Nothing was run on Windows; Windows-only conclusions are marked
unverified. Out-of-scope modules (`enrichment/*`, `ui*.py`, `nway/*`, `backend.py`) were read only.

## Findings

| ID | Severity | Reproduction (minimal) | Root cause | Status |
|---|---|---|---|---|
| SS-01 | Medium | `os._exit` (or Ctrl+C, power loss) after both inputs were copied inside `ProjectService.create`. Then `create` fails with "project database already exists" and `open` with "project snapshot is missing". The window is the whole copy and hash of two inputs of up to 1 GiB. | `ProjectStore.__init__(create=True)` refused any existing `project.sqlite3`; `ProjectService.create` cleaned up on `Exception` only. | Fixed: `_abandoned_creation` recycles an empty or snapshot-less database (the caller holds the lock; a database with a snapshot, history row or foreign table is never recycled); `create` cleans up on `BaseException`. |
| SS-02 | High impact, low likelihood | `InterpretationRun.duration_seconds = inf` (passes `ge=0`) or `AnalysisRun(settings={'x': 10**5000})`: `save` succeeds, then `open` raises (`null` for a float field / "JSON integer exceeds the supported digit limit"). The project is unopenable; history keeps older rows but there is no repair path. | `save` never proved that `load` accepts what it wrote: `model_dump_json` writes non-finite floats as `null`, `strict_json` bounds integers. | Fixed: `ProjectStore._assert_reloadable` parses and validates the serialized payload before commit ("PT-SCHEMA: project snapshot would not reload (at field.path); prior snapshot retained"). Cost on a 44 MB snapshot: 0.50 s of a 1.74 s save. |
| SS-03 | Low | Input file name with invalid UTF-8 (POSIX) or an unpaired surrogate, or a project name containing one: `PydanticSerializationError` after both inputs were copied; untagged message. | Display strings were stored unsanitized. | Fixed: `ingestion.display_text` (`backslashreplace`) for artifact and project names. |
| SS-04 | Low | Prepare an import, change the revision (swap orientation), `apply_import`: rejected, but `runs/<id>/raw/result.ghidriff.json` (up to 100 MiB, read-only) stays forever and `discard_import` can no longer find it; backups copy it. | The stale branch only popped `_prepared`. | Fixed: stale branch calls `discard_import`. |
| SS-05 | Low | Root or backup parent that is a file: raw `FileExistsError`/`NotADirectoryError` from `ProjectStore(create=True)`, `ProjectService.create`, `backup`. `nway.series.prepare` only catches `ValueError`. | `mkdir` not translated. | Fixed: PT-STORAGE `ValueError`. |
| SS-06 | Low | Snapshot with `schema_version: 2` or an extra field: raw multi-line pydantic `ValidationError` echoing `input_value`, not the documented `PT-SCHEMA`. | `load` did not translate `ValidationError`. | Fixed: "PT-SCHEMA: stored project snapshot violates the v1 contract (at field)". |
| SS-07 | Low-Medium | In the UI, re-open the project that is already open (Open recent / Open): `ProjectService.open` runs before `set_service` closes the previous service, so the flock is still held and the user sees "locked by another writer". Code reading only; not run under Qt. | `ui.py` `set_service` ordering. | Reported (ui.py is out of fix scope). |
| SS-08 | Low | SIGKILL during `backup`: `.patchtrace-backup-*` staging directory (partial copy of artifacts) stays next to the destination, hidden, never swept (11 of 15 backup-mode kill runs). | Cleanup lives only in `finally`. | Reported. |
| SS-09 | Low | 300 `swap_orientation` calls leave 301 history rows; the byte budget cannot reclaim them. | By design (SPEC-07h H2): the newest snapshot of every revision is never pruned. | Reported (hazard, below). |
| SS-10 | Low | A second connection holding a read transaction makes `save` fail after the 5.0 s busy timeout ("project save failed; prior snapshot retained"); state is retained and a retry succeeds. Applies to `enrichment.storage.prepare_backups` on a large database and to any reader built later. | Rollback-journal mode, `timeout=5`. | Reported. |
| SS-11 | Low | `nway.pair_access.DiskPairReader` says it never writes, but `ProjectService.open` writes the lock payload and, with a queued/running run, a recovery snapshot and history row. | `load()` recovery on open. | Reported (nway is out of fix scope). |
| SS-12 | Unverified (Windows) | `os.replace` of the staged artifact (`ingestion.inspect_artifact`), staged raw JSON (`service._prepare_analysis`) and the backup directory have no bounded retry for sharing violations (OneDrive, antivirus). Not reproducible on Linux. | No retry helper. | Reported; recommend a short bounded retry on `PermissionError`. |
| SS-13 | Low | `backup` rejects `is_symlink()` entries only. A Windows junction in `runs/` or `exports/` would be followed by `copytree` (3.12 has `Path.is_junction`); a FIFO would hang it. The copy itself is not verified (a corrupt artifact in a backup is caught when the backup is opened, by hash). | Guard scope. | Reported. |
| SS-14 | Info | In-place adoption of the backend's raw file takes its fingerprint after normalization (seconds), but the digest from the earlier read. A write in that window is cached as verified and the project fails to open next time ("preserved raw output changed"). Needs a concurrent writer on a PatchTrace-owned file. | Fingerprint taken late. | Reported. |
| SS-15 | Info | A failed `create` leaves orphan `artifacts/<sha>.bin` (and `.input-*` after a kill); nothing garbage-collects them and backups copy them. | By design of content addressing. | Reported. |

## Attack ideas tried

| # | Idea | Outcome |
|---|---|---|
| 1 | Two processes open one project; create over a held project | Second gets "locked by another writer"; the first is unharmed. Held. |
| 2 | Stale lock file after `kill -9` of the holder | Reopens; the kernel lock is released, no stealing needed. Held. |
| 3 | Kill during create (after copies, before first save) | SS-01. |
| 4 | Ctrl+C during create | SS-01. |
| 5 | Second input invalid | First artifact orphaned (SS-15); retry works. |
| 6 | SIGKILL at random moments while annotating, swapping orientation, backing up (45 runs) | Always reopens; newest history row equals current snapshot; revision never decreases; no partial backup published (the one flagged run was the harness's own `rmtree` of a finished backup). Only SS-08. Held. |
| 7 | Truncated database (0, 100, 4096, 8192 bytes) | PT-STORAGE or PT-SCHEMA, fails closed. Held. |
| 8 | Flipped snapshot payload | "snapshot hash failed", fails closed; no repair from history exists. |
| 9 | inf, NaN, huge integers, colliding dict keys | SS-02; NaN inside `settings` silently becomes `null`; `{1:'a','1':'b'}` collapses. |
| 10 | Unusual root names on POSIX (`#`, `%`, `?`, unicode, trailing space, 200-char component, `CON`, `nul.txt`, backslash, colon) | create, backup and reopen all work. Windows reserved names, trailing dots and long paths are untestable here. |
| 11 | OneDrive-style input names (`Copy (2)`, `(1)`, leading dot, 250 characters) | Held. |
| 12 | Symlink and symlink loop inside `runs/` or `exports/` during backup | Refused, no staging leftovers. Junctions: SS-13. |
| 13 | Identical old and new files | One shared artifact path, `identical` run, swap, backup, reopen all work. |
| 14 | Swapped orientation: stale prepared import, old-orientation raw, swap back and import | Stale import rejected (SS-04 residue fixed); wrong-orientation raw rejected by hash identity; correct after swapping back. `enrichment` `diff_id` includes ordered hashes, so stored rankings go stale. Held. |
| 15 | Concurrent revision bumps, older revision or foreign project saved | Refused (existing test); 300 bumps fine (SS-09). |
| 16 | Backup not verified: corrupt an artifact inside a backup | Caught at open by hash; backup itself does not verify (SS-13). |
| 17 | File changes after hashing (source during copy, raw during import) | Source covered by existing tests; raw window SS-14. |
| 18 | Schema drift: `user_version` 2, `schema_version` 2, extra field, traversal path | Fails closed; messages untagged before SS-06. |
| 19 | 460 random sequences of 25 operations (swap, annotate, review, correct, restore, reopen, backup, import, record run, save) on the sample project | In-memory project always equals the committed snapshot; backups equal live; no problems. Held. |
| 20 | Read transaction on a second connection | SS-10. |
| 21 | Root or backup parent is a file | SS-05. |

## Hazards for code built on top of this

- **One writer.** `ProjectService.open` takes the exclusive lock and may write (recovery, lock payload). A second open in the same process fails with "locked". Open, use, close; do not rely on "read-only" opens (SS-11) or on reopening the project a window already holds (SS-07).
- **Thread confinement.** The SQLite connection and every service method belong to the creating thread. Workers use `prepare_*`; the owner thread calls `apply_*`. Close a service created on a worker before handing the root to the GUI thread (as `ui.new_project` does).
- **Free-form data must be JSON-native.** `AnalysisRun.settings`, `FunctionRecord.metadata` and annotation text round-trip through JSON: finite floats, integers under 4300 digits, string keys. Tuples become lists, NaN becomes `null`, integer keys become strings, silently. `save` now refuses what cannot reload, but not what changes shape.
- **Do not bloat the snapshot.** Cap is 256 MiB per snapshot; each save writes it twice (current plus history). Attach bulk KB/CVE records through the additive enrichment tables, not through annotations or `settings`.
- **Revision bumps are permanent.** `_invalidate` (import, correction, restore, swap) marks every context, finding and annotation stale and keeps one history snapshot per revision forever. Never bump per attached record; `annotate`, `review_*`, `add_interpretation` and enrichment publishes do not bump.
- **Other connections starve commits.** Keep read transactions on `project.sqlite3` short (5 s busy timeout); never open it read-write outside `ProjectStore`.
- **`create` is not atomic at directory level.** Failure leaves the root, lock file and orphan artifacts. Deterministic roots derived from KB identifiers must treat "already exists" (a real project) differently from a recycled snapshot-less leftover, which `create` now replaces silently.
- **Orientation is data.** After `swap_orientation` a run's `settings['older_sha256']`/`['newer_sha256']` and its preserved raw JSON keep the orientation of run time. Use `project.artifacts[*].side` and the `diff_id`; `apply_import` replaces all matches with the new run's matches.
- **Always `discard_import`** on every failure path; backups copy everything under `runs/`.
- **Windows.** Keep the root short (artifact paths add 77 characters); the root itself has no reserved-name check; directory renames and `os.replace` have no retry (SS-12).
- **Error contract.** Expect `ValueError` with a `PT-` prefix, but a lone surrogate in annotation text raises a serialization error at save (state retained, no tag).
