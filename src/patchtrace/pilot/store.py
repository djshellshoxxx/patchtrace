"""Stored patch-intent results: sidecar directories and tiny pointer rows (PIL-integration-plan.md s7 "Store and keys").

Layout: `intelligence/pilot/<result_id[:16]>/{manifest.json, assessment.json.gz}`; the part hashes and sizes describe the
DECOMPRESSED canonical JSON (gzip is written with mtime 0 and never hashed). The pointer row `pilot-result:<result_id>`
(kind `patch-intent`, reserved and not derived) certifies the manifest, the manifest the assessment and the assessment
its own `result_id`, so a copied, truncated or edited sidecar is a cache miss and never data. Writing is two steps: `stage`
writes a private directory (files only, any thread), `publish` renames it into place and then writes the row (owner
thread). A crash between the two leaves a directory without a row, which `sweep_orphans` removes later.

Retention keeps the newest `KEEP` results per (pair, advisory documents, configuration) after a verified backup that holds
the rows about to go (`pilot-retention`). Only `pilot-result:` rows are ever deleted: review events (`review.py`), rows
that do not validate and every other feature's rows are out of reach. Public attributes of `EnrichmentStore` only
(`store.connection`, `store.root`); no other feature's internals.
"""
from __future__ import annotations

import gzip
import hashlib
import json
import os
import re
import secrets
import shutil
import sqlite3
import stat
import time
import zlib
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from pydantic import ValidationError

from .. import verified_backup
from ..enrichment.contracts import EnrichmentError
from ..enrichment.storage import EnrichmentStore, Entry, Guard
from ..ingestion import safe_path
from . import keys
from .contracts import PilotAssessment, PilotConfig, PilotInputs, PilotManifest, PilotResultPointer
from .limits import DEFAULT_LIMITS, PilotError, PilotLimits

KIND = keys.KIND
BACKUP_LABEL = 'pilot-retention'
KEEP = 3  # results kept per (pair, advisory documents, configuration)
ORPHAN_RESULT_S = 300  # a result directory without a row is an orphan after 5 minutes
ORPHAN_STAGING_S = 3600  # staging writes files only, so a staging directory this old was abandoned
MANIFEST_MAX_BYTES = 1024 * 1024
_STAGING = re.compile(r'tmp-[0-9a-f]{16}')
_RESULT_DIR = re.compile(r'[0-9a-f]{16}')
_PILOT_ROWS = "SELECT id, body_sha256 FROM enrichment_entries WHERE kind='patch-intent' ORDER BY id"
_CHUNK = 400  # ids per SQL statement (SQLite's variable limit)


@dataclass(frozen=True, slots=True)
class Published:
    entry: Entry
    pointer: PilotResultPointer
    manifest: PilotManifest
    directory: Path
    deleted: int  # rows retention removed in this publish


@dataclass(frozen=True, slots=True)
class Loaded:
    """`current`, `stale` (shown for reference: the guard moved or `changed` names the inputs that differ), `none` or
    `invalid` (rows exist but none verifies; `reason` is the first failure). `skipped` are rows that do not validate."""
    state: str
    reason: str | None = None
    entry: Entry | None = None
    pointer: PilotResultPointer | None = None
    manifest: PilotManifest | None = None
    assessment: PilotAssessment | None = None
    changed: tuple[str, ...] = ()
    skipped: tuple[str, ...] = ()


def _error(code: str, message: str, reason: str) -> PilotError:
    return PilotError(code, message, reason=reason)


def _integrity(message: str, reason: str) -> PilotError:
    return _error('PT-PILOT-INTEGRITY', message, reason)


def _now() -> str:
    return datetime.now(UTC).strftime('%Y-%m-%dT%H:%M:%SZ')


def completed_run(project):
    """The newest completed run with raw output: the one `enrichment.views` serves, or None."""
    return next((r for r in reversed(project.runs) if r.status == 'completed' and r.raw_sha256), None)


def current_guard(project, result_id: str) -> Guard:
    """The guard recomputed from the live project: its newest completed run."""
    run = completed_run(project)
    return Guard(project.id, run.id if run else '', run.raw_sha256 if run else '', result_id)


# --- files (pure; any thread) -----------------------------------------------------------------------------------------

def _safe(root: Path, relative: str) -> Path:
    try:
        return safe_path(root, relative)
    except ValueError:
        raise _integrity('A sidecar path is not a plain path inside the project', 'unsafe-path') from None


def _replace(source: Path, target: Path) -> None:
    """os.replace with a bounded retry for antivirus and indexer locks on Windows (5 x 200 ms)."""
    for attempt in range(5):
        try:
            os.replace(source, target)
            return
        except PermissionError:
            if attempt == 4:
                raise _error('PT-PILOT-STORAGE', 'A sidecar could not be moved into place', 'replace-failed') from None
            time.sleep(0.2)


def _rmtree(path: Path) -> None:
    def retry(function, target, _exc):
        os.chmod(target, stat.S_IWRITE | stat.S_IREAD)
        function(target)
    shutil.rmtree(path, onexc=retry)


def _write(path: Path, data: bytes) -> None:
    part = path.with_name(path.name + '.part')
    part.write_bytes(data)
    _replace(part, path)


def stage(root: Path, assessment: PilotAssessment, config: PilotConfig, *, created_utc: str | None = None,
          limits: PilotLimits = DEFAULT_LIMITS) -> Path:
    """Write the sidecar into a new private directory beside the results and return it. Files only: safe on a worker
    thread. The caller (`publish`) verifies, renames and publishes the row; a directory nobody claims is swept."""
    data = keys.canonical_bytes(assessment)
    if len(data) > limits.p06_sidecar_bytes:
        raise _error('PT-PILOT-LIMIT', 'The result exceeds the sidecar limit', 'sidecar-size')
    manifest = keys.make_manifest(assessment, config, created_utc=created_utc or _now())
    staged = _safe(Path(root), f'{keys.RELATIVE_ROOT}/tmp-{secrets.token_hex(8)}')
    try:
        staged.mkdir(parents=True)
        _write(staged / keys.ASSESSMENT_NAME, gzip.compress(data, compresslevel=6, mtime=0))
        _write(staged / keys.MANIFEST_NAME, keys.canonical_bytes(manifest))
    except BaseException:
        shutil.rmtree(staged, ignore_errors=True)
        raise
    return staged


def read_manifest(directory: Path) -> PilotManifest:
    path = Path(directory) / keys.MANIFEST_NAME
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > MANIFEST_MAX_BYTES:
            raise _integrity('The manifest is missing or too large', 'manifest-missing')
        data = path.read_bytes()
    except OSError:
        raise _integrity('The manifest is unreadable', 'manifest-unreadable') from None
    try:
        manifest = PilotManifest.model_validate_json(data)
    except ValidationError:
        raise _integrity('The manifest failed validation', 'manifest-invalid') from None
    keys.verify_manifest(manifest)
    return manifest


def _gunzip(path: Path, size: int) -> bytes:
    """The decompressed part, never more than `size` bytes: a stream that grows past what the manifest declares is a
    decompression bomb, one that stops early is truncated."""
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > size + 4096:
            raise _integrity('The assessment part is missing or larger than declared', 'part-missing')
        stream = zlib.decompressobj(wbits=31)
        data = stream.decompress(path.read_bytes(), size + 1)
        if not stream.eof or stream.unconsumed_tail or stream.unused_data:
            raise _integrity('The assessment part is cut off or has trailing data', 'part-unreadable')
    except (OSError, zlib.error):
        raise _integrity('The assessment part is unreadable', 'part-unreadable') from None
    return data


def read_assessment(directory: Path, manifest: PilotManifest) -> PilotAssessment:
    part = next(p for p in manifest.parts if p.name == keys.ASSESSMENT_NAME)
    data = _gunzip(Path(directory) / part.name, part.bytes)
    if len(data) != part.bytes or hashlib.sha256(data).hexdigest() != part.sha256:
        raise _integrity('The assessment part does not match its digest', 'part-digest')
    try:
        assessment = PilotAssessment.model_validate_json(data)
    except ValidationError:
        raise _integrity('The assessment failed validation', 'assessment-invalid') from None
    keys.verify_manifest(manifest, assessment)
    keys.verify_assessment(assessment)
    return assessment


def read_sidecar(directory: Path) -> tuple[PilotManifest, PilotAssessment]:
    """A verified result from its directory: every digest, the manifest and the identity (any thread)."""
    manifest = read_manifest(directory)
    return manifest, read_assessment(directory, manifest)


# --- rows (owner thread) ----------------------------------------------------------------------------------------------

def _owner(enrichment: EnrichmentStore) -> None:
    if enrichment.store.closed:
        raise _error('PT-PILOT-STORAGE', 'The project is closed', 'project-closed')
    try:
        enrichment.store.connection.execute('SELECT 1').fetchone()
        enrichment.ensure()
    except sqlite3.ProgrammingError:
        raise _error('PT-PILOT-STORAGE', 'Results are read and written only on the project owner thread',
                     'wrong-thread') from None
    except (sqlite3.Error, EnrichmentError):
        raise _error('PT-PILOT-STORAGE', 'The project enrichment data could not be opened', 'enrichment-unreadable') \
            from None


def project_facts(enrichment: EnrichmentStore) -> tuple[str | None, dict[str, str | None], set[str]]:
    """(project id, {run id: raw sha256}, artifact hashes) of the saved project snapshot."""
    row = enrichment.store.connection.execute(
        "SELECT json_extract(payload, '$.id'), json_extract(payload, '$.runs'), "
        "json_extract(payload, '$.artifacts') FROM current_snapshot WHERE singleton=1").fetchone()
    if row is None or not isinstance(row[0], str):
        return None, {}, set()
    runs = {r.get('id'): r.get('raw_sha256') for r in json.loads(row[1] or '[]') if isinstance(r, dict)}
    shas = {a.get('sha256') for a in json.loads(row[2] or '[]') if isinstance(a, dict)}
    return row[0], runs, shas


def _mismatch(message: str, reason: str) -> PilotError:
    return _error('PT-PILOT-MISMATCH', message, reason)


def require_project(enrichment: EnrichmentStore, project_id: str) -> None:
    if project_facts(enrichment)[0] != project_id:
        raise _mismatch('The record belongs to another project', 'foreign-project')


def _require_owned(enrichment: EnrichmentStore, assessment: PilotAssessment) -> None:
    """The project owns the result: it is this project, the Ghidriff run exists here with this raw output, and the two
    hashes are the project's artifacts. Either orientation is accepted (a swapped result is stored stale)."""
    project_id, runs, shas = project_facts(enrichment)
    inputs = assessment.inputs
    if project_id is None or assessment.project_id != project_id:
        raise _mismatch('The result belongs to another project', 'foreign-project')
    if inputs.ghidriff_run_id not in runs:
        raise _mismatch('The result names a Ghidriff run that the project does not have', 'run-unknown')
    if runs[inputs.ghidriff_run_id] != inputs.raw_sha256:
        raise _mismatch('The result names another raw output than the Ghidriff run holds', 'raw-mismatch')
    if {inputs.older_sha256, inputs.newer_sha256} != shas:
        raise _mismatch('The result compares files that are not the project artifacts', 'artifact-foreign')


def _pointers(enrichment: EnrichmentStore) -> tuple[list[tuple[Entry, PilotResultPointer]], list[str]]:
    """Valid pointer rows, newest first, and the ids of the pointer rows that are corrupt or not this contract."""
    skipped: list[str] = []
    found = []
    for entry in enrichment.entries(KIND, on_corrupt=skipped.append):
        if not entry.id.startswith(keys.POINTER_PREFIX):
            continue
        try:
            pointer = PilotResultPointer.model_validate_json(json.dumps(entry.body))
            if entry.id != keys.pointer_entry_id(pointer.result_id):
                raise ValueError('a pointer row is named after its result')
        except (ValidationError, ValueError):
            skipped.append(entry.id)
            continue
        found.append((entry, pointer))
    return found, sorted(i for i in set(skipped) if i.startswith(keys.POINTER_PREFIX))


def _manifest_of(root: Path, pointer: PilotResultPointer) -> PilotManifest:
    manifest = read_manifest(_safe(root, pointer.relative_dir))
    keys.verify_pointer(pointer, manifest)
    return manifest


def _changed(inputs: PilotInputs, known: Mapping[str, object] | None) -> tuple[str, ...]:
    """Names of the stored inputs that differ from what is known now (state L6 names them)."""
    stored = inputs.model_dump(mode='json')
    return tuple(name for name in PilotInputs.model_fields if known and name in known and stored[name] != known[name])


def load(enrichment: EnrichmentStore, known: Mapping[str, object] | None = None) -> Loaded:
    """The newest result that verifies, current results first. `known` holds what is known now about the `PilotInputs`
    names (a project can name its pair, run and raw output without computing anything; the Leads dock names them all):
    a stored result that differs in any of them is `stale` and says which. A damaged sidecar is skipped, so it never
    hides an intact older result; nothing verifying at all is `invalid`, never a crash."""
    _owner(enrichment)
    rows, skipped = _pointers(enrichment)
    if not rows:
        return Loaded('none', 'no-result', skipped=tuple(skipped))
    root, failure, candidates = enrichment.store.root, None, []
    for entry, pointer in rows:  # newest first
        try:
            manifest = _manifest_of(root, pointer)
        except PilotError as exc:
            failure = failure or exc.reason or 'unreadable'
            continue
        changed = _changed(manifest.inputs, known)
        candidates.append((bool(entry.stale or changed), entry, pointer, manifest, changed))
    for stale, entry, pointer, manifest, changed in sorted(candidates, key=lambda item: item[0]):
        try:
            assessment = read_assessment(root / pointer.relative_dir, manifest)
        except PilotError as exc:
            failure = failure or exc.reason or 'unreadable'
            continue
        reason = None if not stale else 'inputs-changed' if changed else 'guard-moved'
        return Loaded('stale' if stale else 'current', reason, entry, pointer, manifest, assessment, changed,
                      tuple(skipped))
    return Loaded('invalid', failure or 'unreadable', skipped=tuple(skipped))


def _install(root: Path, staged: Path, result: str) -> tuple[Path, PilotManifest, bool]:
    """Move the staged directory to its final place. A verified copy with the same content is kept (idempotent); other
    content under the same id, or a damaged copy, is replaced: the result is derived and the newest copy counts.
    Returns the directory, its manifest and whether `staged` was moved in."""
    final = _safe(root, keys.relative_dir(result))
    fresh = read_manifest(staged)
    if final.exists():
        try:
            kept = read_sidecar(final)[0]
        except PilotError:
            kept = None
        if kept is not None and kept.model_copy(update={'created_utc': fresh.created_utc}) == fresh:
            _rmtree(staged)
            return final, kept, False
        trash = final.with_name(f'tmp-{secrets.token_hex(8)}')
        _replace(final, trash)
        _rmtree(trash)
    _replace(staged, final)
    return final, fresh, True


def publish(enrichment: EnrichmentStore, assessment: PilotAssessment, config: PilotConfig, *, current: Guard,
            created_utc: str | None = None, limits: PilotLimits = DEFAULT_LIMITS) -> Published:
    """Verify that the project owns the result, stage and install its directory, then write the pointer row (stored
    stale when `current`, the guard recomputed from the live project, no longer equals the result's). Any failure before
    the row leaves the previous rows as they were. Retention and the orphan sweep follow, best effort: they never fail a
    publish."""
    _owner(enrichment)
    if enrichment.read_only:
        raise _error('PT-PILOT-STALE', 'Project enrichment data was written by a newer PatchTrace', 'read-only-store')
    keys.verify_assessment(assessment)
    _require_owned(enrichment, assessment)
    root = enrichment.store.root
    staged = stage(root, assessment, config, created_utc=created_utc, limits=limits)
    try:
        final, manifest, installed = _install(root, staged, assessment.result_id)
    except BaseException:
        shutil.rmtree(staged, ignore_errors=True)
        raise
    pointer = keys.make_pointer(manifest)
    guard = Guard(*keys.guard_parts(assessment.project_id, assessment.inputs))
    try:
        entry = enrichment.publish(KIND, guard, current, assessment.revision, assessment.status,
                                   pointer.model_dump(mode='json'), keys.pointer_entry_id(assessment.result_id))
    except EnrichmentError as exc:
        if installed:
            shutil.rmtree(final, ignore_errors=True)
        raise _error('PT-PILOT-STORAGE', 'The result row could not be stored',
                     'enrichment-limit' if exc.code == 'PT-ENRICH-LIMIT' else 'pointer-publish') from None
    deleted = 0
    try:
        deleted = apply_retention(enrichment, protect=(entry.id,))
    except (PilotError, EnrichmentError, sqlite3.Error, OSError):
        pass  # best effort
    try:
        sweep_orphans(enrichment)
    except (PilotError, EnrichmentError, sqlite3.Error, OSError):
        pass
    return Published(entry, pointer, manifest, final, deleted)


# --- retention (the only deletion in this feature) ---------------------------------------------------------------

def _holds(path: Path, ids: list[str]) -> bool:
    try:
        copy = sqlite3.connect(f'{path.resolve().as_uri()}?mode=ro', uri=True, timeout=5)
        try:
            return all(copy.execute(f'SELECT COUNT(*) FROM enrichment_entries WHERE id IN ({",".join("?" * len(c))})',
                                    c).fetchone()[0] == len(c) for c in (ids[i:i + _CHUNK]
                                                                         for i in range(0, len(ids), _CHUNK)))
        finally:
            copy.close()
    except (sqlite3.Error, OSError, ValueError):
        return False


def _backup(enrichment: EnrichmentStore, ids: list[str]) -> Path:
    """A trusted backup of this project that holds every row about to go: the newest verified copy when it does, else a
    new one (compared with the live database before it is trusted). Without one, nothing is deleted."""
    root, connection = enrichment.store.root, enrichment.store.connection
    try:
        found = verified_backup.find_verified_backup(root, BACKUP_LABEL, project_id=verified_backup.live_project_id(
            connection), require_tables=('enrichment_entries',))
        if found is not None and _holds(found, ids):
            return found
        return verified_backup.write_verified_backup(root, connection, BACKUP_LABEL, compare=(_PILOT_ROWS,))
    except verified_backup.BackupError:
        raise _error('PT-PILOT-STORAGE', 'The pre-retention backup failed verification; nothing was deleted',
                     'backup-failed') from None


def delete_results(enrichment: EnrichmentStore, ids: Iterable[str]) -> int:
    """Delete `pilot-result:` rows of kind `patch-intent` in one transaction, after a backup that holds them. Any other
    id (a review event, another kind) is ignored: this is the only deletion of the feature and it cannot reach them."""
    doomed = sorted(i for i in set(ids) if i.startswith(keys.POINTER_PREFIX))
    _owner(enrichment)
    if not doomed or enrichment.read_only:
        return 0
    _backup(enrichment, doomed)
    db = enrichment.store.connection
    if db.in_transaction:
        raise _error('PT-PILOT-STORAGE', 'Another transaction is open on the project database', 'transaction-open')
    deleted = 0
    db.execute('BEGIN IMMEDIATE')
    try:
        for start in range(0, len(doomed), _CHUNK):
            chunk = doomed[start:start + _CHUNK]
            deleted += db.execute(f'DELETE FROM enrichment_entries WHERE id IN ({",".join("?" * len(chunk))}) '
                                  'AND kind=? AND id LIKE ?', (*chunk, KIND, f'{keys.POINTER_PREFIX}%')).rowcount
    except BaseException:
        db.execute('ROLLBACK')
        raise
    db.execute('COMMIT')
    return deleted


def _family(manifest: PilotManifest) -> tuple:
    """What a result answers: the pair and its orientation, the advisory documents (the manifest has no CVE list, the
    documents it was computed from name the CVE set) and the configuration. Newer inputs of the same question replace
    older results; another pair, orientation, advisory set or configuration never evicts one."""
    i = manifest.inputs
    return i.older_sha256, i.newer_sha256, i.advisory_facts_ids, i.config_digest


def apply_retention(enrichment: EnrichmentStore, *, protect: Iterable[str] = ()) -> int:
    """Keep the newest `KEEP` results of every family (plus `protect`) and delete the rest, rows first and then their
    directories. A row that does not validate or whose sidecar does not verify is never deleted here. Returns the number
    of rows deleted."""
    _owner(enrichment)
    if enrichment.read_only:
        return 0
    root, rows = enrichment.store.root, []
    for entry, pointer in _pointers(enrichment)[0]:
        try:
            rows.append((entry, pointer, _manifest_of(root, pointer)))
        except PilotError:
            continue
    rows.sort(key=lambda row: (row[0].created, row[2].created_utc, row[0].id), reverse=True)  # newest first
    seen: dict[tuple, int] = {}
    doomed = []
    for entry, pointer, manifest in rows:
        family = _family(manifest)
        seen[family] = seen.get(family, 0) + 1
        if seen[family] > KEEP and entry.id not in set(protect):
            doomed.append((entry.id, pointer.relative_dir))
    deleted = delete_results(enrichment, [row_id for row_id, _ in doomed])
    kept = {pointer.relative_dir for _entry, pointer in _pointers(enrichment)[0]}
    for _row_id, relative in doomed:
        if relative not in kept:
            path = _safe(root, relative)
            if path.is_dir() and not path.is_symlink():
                _rmtree(path)
    return deleted


def sweep_orphans(enrichment: EnrichmentStore) -> int:
    """Remove what a crash left beside the results: a result directory without a row once it is 5 minutes old, and a
    staging directory abandoned for an hour. A directory a damaged row names is never swept. Returns the number removed."""
    _owner(enrichment)
    parent = _safe(enrichment.store.root, keys.RELATIVE_ROOT)
    if not parent.is_dir() or parent.is_symlink():
        return 0
    rows, skipped = _pointers(enrichment)
    named = {pointer.relative_dir.rsplit('/', 1)[1] for _entry, pointer in rows}
    named |= {row_id.removeprefix(keys.POINTER_PREFIX)[:16] for row_id in skipped}
    now, removed = time.time(), 0
    for child in sorted(parent.iterdir()):
        staging = _STAGING.fullmatch(child.name) is not None
        if not staging and (_RESULT_DIR.fullmatch(child.name) is None or child.name in named):
            continue
        try:
            age = now - child.stat().st_mtime
            if child.is_symlink() or not child.is_dir() or age < (ORPHAN_STAGING_S if staging else ORPHAN_RESULT_S):
                continue
            _rmtree(child)
        except OSError:
            continue
        removed += 1
    return removed
