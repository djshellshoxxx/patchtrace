"""SPEC-31 result sidecars and pointer rows (02 s4, s7, s9). Never edits enrichment/storage.py.

Layout: `runs/<run_id>/unified/results/<result_id[:16]>/{manifest.json, rows.jsonl.gz, facts.jsonl.gz}`. Parts are
gzip JSON Lines; `Part.sha256/bytes/records` describe the DECOMPRESSED content (gzip bytes differ between zlib
builds). Writers stage a directory, the owner verifies every hash, renames it into place and only then publishes
the tiny pointer row (`unified-result`, KINDS only, never DERIVED_KINDS) through the public EnrichmentStore API.
Readers trust a directory only when the row exists and every hash matches; anything else is a cache miss.
`backup_once`/`delete_own` live here (phase D coordination): they use only public attributes
(`EnrichmentStore.store.connection`, `.root`) and delete nothing but `unified-*` kinds after a verified backup.
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
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel, ValidationError

from ..enrichment.contracts import EnrichmentError
from ..enrichment.storage import EnrichmentStore, Entry, Guard
from ..ingestion import safe_path
from ..persistence import strict_json
from . import keys
from .contracts import (
    ChangeFacts,
    Counts,
    IrRef,
    Part,
    ResultKeyInputs,
    SourceRef,
    UnifiedMatch,
    UnifiedResultManifest,
    UnifiedResultPointer,
    UnifiedRun,
)
from .limits import DEFAULT_LIMITS, UnifiedError, UnifiedLimits

RESULT_KIND = 'unified-result'
RUN_KIND = 'unified-run'
UNIFIED_KINDS = (RUN_KIND, RESULT_KIND)
RUN_KEEP = 8
BACKUP_LABEL = 'unified-retention'
MANIFEST = 'manifest.json'
MANIFEST_MAX_BYTES = 1024 * 1024
LINE_MAX_BYTES = 4 * 1024 * 1024
_RUN_ID_OK = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$')
_TRUSTED: dict[tuple[str, int, int], str] = {}


def _err(message: str, reason: str, code: str = 'PT-UNIFIED-STORE') -> UnifiedError:
    return UnifiedError(code, message, reason=reason)


# --- paths --------------------------------------------------------------------------------------------------------

def result_relative_dir(run_id: str, result_id: str) -> str:
    if not _RUN_ID_OK.match(run_id or '') or len(result_id) != 64:
        raise _err('Invalid run or result identity for a sidecar path', 'bad-identity', 'PT-UNIFIED-INPUT')
    return f'runs/{run_id}/unified/results/{result_id[:16]}'


def result_dir(root: Path, run_id: str, result_id: str) -> Path:
    return safe_path(root, result_relative_dir(run_id, result_id))


def new_staging_dir(root: Path, run_id: str) -> Path:
    """A private staging directory on the project volume (so the owner's rename stays atomic)."""
    parent = safe_path(root, result_relative_dir(run_id, '0' * 64).rsplit('/', 1)[0])
    parent.mkdir(parents=True, exist_ok=True)
    path = parent / f'tmp-{secrets.token_hex(8)}'
    path.mkdir()
    return path


# --- writing (pure file I/O; worker side) -------------------------------------------------------------------------

def dump_line(record: BaseModel | dict) -> bytes:
    data = record.model_dump(mode='json') if isinstance(record, BaseModel) else record
    return json.dumps(data, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                      allow_nan=False).encode('utf-8') + b'\n'


def _replace(source: Path, target: Path) -> None:
    """os.replace with a bounded retry for antivirus/indexer locks on Windows (T-08: 5 x 200 ms)."""
    for attempt in range(5):
        try:
            os.replace(source, target)
            return
        except PermissionError:
            if attempt == 4:
                raise _err('A unified sidecar could not be moved into place', 'replace-failed') from None
            time.sleep(0.2)


def write_part(directory: Path, name: str, records: Iterable[BaseModel | dict],
               limits: UnifiedLimits = DEFAULT_LIMITS) -> Part:
    digest, size, count = hashlib.sha256(), 0, 0
    part = directory / f'{name}.part'
    with open(part, 'wb') as raw, gzip.GzipFile(filename='', mode='wb', fileobj=raw, mtime=0, compresslevel=6) as gz:
        for record in records:
            line = dump_line(record)
            size += len(line)
            if size > limits.l30_part_bytes:
                raise _err('A unified result part exceeds L-30', 'part-too-large', 'PT-UNIFIED-LIMIT')
            digest.update(line)
            gz.write(line)
            count += 1
    _replace(part, directory / name)
    return Part(name=name, sha256=digest.hexdigest(), bytes=size, records=count)


def write_result(directory: Path, *, older_sha256: str, newer_sha256: str, ghidriff_run_id: str,
                 ghidriff_raw_sha256: str, ir_older: IrRef | None, ir_newer: IrRef | None,
                 sources: Iterable[SourceRef], manual_digest: str, config_digest: str, status: str,
                 limitations: Iterable[str], rows: Iterable[UnifiedMatch], facts: Iterable[ChangeFacts],
                 created_utc: str | None = None, limits: UnifiedLimits = DEFAULT_LIMITS) -> UnifiedResultManifest:
    """Write parts and the manifest into an existing private directory; `result_id` is computed from the inputs."""
    directory = Path(directory)
    rows, facts = list(rows), list(facts)
    sources = tuple(sorted(sources, key=lambda s: (s.source, s.entry_id, s.file_sha256 or '', s.version)))
    inputs = ResultKeyInputs(older_sha256=older_sha256, newer_sha256=newer_sha256,
                             ghidriff_raw_sha256=ghidriff_raw_sha256,
                             ir_older_digest=ir_older.content_digest if ir_older else None,
                             ir_newer_digest=ir_newer.content_digest if ir_newer else None, sources=sources,
                             manual_digest=manual_digest, config_digest=config_digest)
    by_id: dict[str, UnifiedMatch] = {}
    for row in rows:
        expected = keys.row_id(older_sha256, newer_sha256, [s.rva for s in row.older], [s.rva for s in row.newer])
        if row.row_id != expected or row.row_id in by_id:
            raise _err('A unified row has a wrong or duplicate row id', 'row-id', 'PT-UNIFIED-INTERNAL')
        by_id[row.row_id] = row
    seen: set[str] = set()
    for fact in facts:
        row = by_id.get(fact.row_id)
        if row is None or fact.row_id in seen or row.materiality != fact.verdict:
            raise _err('Change facts do not match their row', 'facts-row', 'PT-UNIFIED-INTERNAL')
        seen.add(fact.row_id)
    parts = (write_part(directory, 'facts.jsonl.gz', facts, limits), write_part(directory, 'rows.jsonl.gz', rows, limits))
    manifest = UnifiedResultManifest(
        result_id=keys.result_key(inputs), older_sha256=older_sha256, newer_sha256=newer_sha256,
        orientation='older->newer', ghidriff_run_id=ghidriff_run_id, ghidriff_raw_sha256=ghidriff_raw_sha256,
        ir_older=ir_older, ir_newer=ir_newer, sources=sources, manual_digest=manual_digest,
        config_digest=config_digest, engine_version='ude/1', status=status, limitations=tuple(limitations),
        counts=Counts.of(rows), parts=parts,
        created_utc=created_utc or datetime.now(UTC).isoformat(timespec='seconds'))
    part = directory / f'{MANIFEST}.part'
    part.write_bytes(dump_line(manifest))
    _replace(part, directory / MANIFEST)
    return manifest


# --- verification and reading (pure file I/O; any thread) ---------------------------------------------------------

def read_manifest(directory: Path) -> tuple[UnifiedResultManifest, str]:
    path = Path(directory) / MANIFEST
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > MANIFEST_MAX_BYTES:
            raise _err('The unified result manifest is missing or too large', 'manifest-missing')
        data = path.read_bytes()
        doc = strict_json(data.decode('utf-8'))
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        if isinstance(exc, UnifiedError):
            raise
        raise _err('The unified result manifest is unreadable', 'manifest-unreadable') from None
    if isinstance(doc, dict) and doc.get('contract') != 'unified-result/1' and str(doc.get('contract', '')).startswith(
            'unified-result/'):
        raise _err('The unified result was produced by a newer PatchTrace', 'newer-contract', 'PT-UNIFIED-STALE')
    try:
        manifest = UnifiedResultManifest.model_validate_json(data)
    except ValidationError:
        raise _err('The unified result manifest failed validation', 'manifest-invalid') from None
    return manifest, hashlib.sha256(data).hexdigest()


def _lines(path: Path, limits: UnifiedLimits) -> Iterator[bytes]:
    try:
        with open(path, 'rb') as raw, gzip.GzipFile(fileobj=raw, mode='rb') as gz:
            total, buffer = 0, b''
            while chunk := gz.read(1 << 20):
                total += len(chunk)
                if total > limits.l30_part_bytes:
                    raise _err('A unified result part exceeds L-30', 'part-too-large')
                buffer += chunk
                *complete, buffer = buffer.split(b'\n')
                for line in complete:
                    yield line + b'\n'
                if len(buffer) > LINE_MAX_BYTES:
                    raise _err('A unified result line is too long', 'line-too-long')
            if buffer:
                raise _err('A unified result part is truncated', 'part-truncated')
    except (OSError, EOFError) as exc:
        raise _err('A unified result part is unreadable', 'part-unreadable') from exc


def verify_result_dir(directory: Path, *, expected_result_id: str | None = None,
                      expected_manifest_sha256: str | None = None,
                      limits: UnifiedLimits = DEFAULT_LIMITS) -> UnifiedResultManifest:
    """Re-hash every part; the manifest must certify its own result_id (02 s5). Raises UnifiedError(STORE)."""
    directory = Path(directory)
    if directory.is_symlink() or not directory.is_dir():
        raise _err('The unified result directory is missing', 'dir-missing')
    manifest, manifest_sha = read_manifest(directory)
    if expected_manifest_sha256 is not None and manifest_sha != expected_manifest_sha256:
        raise _err('The unified result manifest changed', 'manifest-hash-mismatch')
    if expected_result_id is not None and manifest.result_id != expected_result_id:
        raise _err('The unified result belongs to another result id', 'result-id-mismatch')
    if keys.result_key(keys.result_key_inputs(manifest)) != manifest.result_id:
        raise _err('The unified result manifest does not certify its result id', 'result-id-inputs')
    names = {MANIFEST, *(p.name for p in manifest.parts)}
    if {p.name for p in directory.iterdir()} != names:
        raise _err('The unified result directory holds unexpected files', 'unexpected-files')
    for part in manifest.parts:
        path = directory / part.name
        if path.is_symlink() or not path.is_file():
            raise _err('A unified result part is missing', 'part-missing')
        digest, size, count = hashlib.sha256(), 0, 0
        for line in _lines(path, limits):
            digest.update(line)
            size += len(line)
            count += 1
        if (digest.hexdigest(), size, count) != (part.sha256, part.bytes, part.records):
            raise _err('A unified result part does not match its manifest', 'part-hash-mismatch')
    return manifest


def _read(directory: Path, manifest: UnifiedResultManifest, name: str, model, limits: UnifiedLimits):
    part = next(p for p in manifest.parts if p.name == name)
    for line in _lines(Path(directory) / part.name, limits):
        try:
            yield model.model_validate_json(line)
        except ValidationError:
            raise _err('A unified result record failed validation', 'record-invalid') from None


def read_rows(directory: Path, manifest: UnifiedResultManifest,
              limits: UnifiedLimits = DEFAULT_LIMITS) -> Iterator[UnifiedMatch]:
    for row in _read(directory, manifest, 'rows.jsonl.gz', UnifiedMatch, limits):
        if row.row_id != keys.row_id(manifest.older_sha256, manifest.newer_sha256, [s.rva for s in row.older],
                                     [s.rva for s in row.newer]):
            raise _err('A unified row id does not match its pairing', 'row-id')
        yield row


def read_facts(directory: Path, manifest: UnifiedResultManifest,
               limits: UnifiedLimits = DEFAULT_LIMITS) -> Iterator[ChangeFacts]:
    yield from _read(directory, manifest, 'facts.jsonl.gz', ChangeFacts, limits)


# --- owner-thread operations --------------------------------------------------------------------------------------

def _require_owner(enrichment: EnrichmentStore) -> None:
    if enrichment.store.closed:
        raise _err('The project is closed', 'project-closed')
    try:
        enrichment.store.connection.execute('SELECT 1').fetchone()
    except sqlite3.ProgrammingError:
        raise _err('Unified rows are read and published only on the project owner thread', 'wrong-thread') from None
    enrichment.ensure()


def _body(model: BaseModel, limits: UnifiedLimits) -> dict:
    body = model.model_dump(mode='json')
    size = len(json.dumps(body, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8'))
    if size > limits.l31_pointer_body_bytes:
        raise _err('A unified pointer row exceeds L-31', 'pointer-row-cap', 'PT-UNIFIED-LIMIT')
    return body


def _rmtree(path: Path) -> None:
    def retry(function, target, _exc):
        os.chmod(target, stat.S_IWRITE | stat.S_IREAD)
        function(target)
    shutil.rmtree(path, onexc=retry)


@dataclass(frozen=True)
class PublishedResult:
    entry: Entry
    pointer: UnifiedResultPointer
    manifest: UnifiedResultManifest
    directory: Path
    deleted_rows: int


def publish_result(enrichment: EnrichmentStore, staged: Path, *, guard: Guard, current: Guard, revision: int,
                   limits: UnifiedLimits = DEFAULT_LIMITS) -> PublishedResult:
    """Verify a staged result, rename it into place, then publish its pointer row. Any failure before the row
    leaves the previous pointer row current; a crash after the rename leaves a directory without a row."""
    _require_owner(enrichment)
    if enrichment.read_only:
        raise _err('Project enrichment data was written by a newer PatchTrace', 'read-only-store',
                   'PT-UNIFIED-STALE')
    manifest = verify_result_dir(staged, limits=limits)
    if (guard.input_digest, guard.run_id, guard.raw_sha256) != (manifest.result_id, manifest.ghidriff_run_id,
                                                               manifest.ghidriff_raw_sha256):
        raise _err('The result does not belong to this guard', 'guard-mismatch', 'PT-UNIFIED-INPUT')
    root = enrichment.store.root
    relative = result_relative_dir(manifest.ghidriff_run_id, manifest.result_id)
    final = safe_path(root, relative)
    staged = Path(staged)
    if final.exists() and staged.resolve() != final.resolve():
        try:
            existing = verify_result_dir(final, limits=limits)
        except UnifiedError:
            existing = None
        if existing is not None and existing.result_id != manifest.result_id:
            raise _err('Another result already uses this sidecar directory', 'dir-collision')
        if existing is None:  # corrupt leftover: move aside, then replace
            trash = final.with_name(f'tmp-{secrets.token_hex(8)}')
            _replace(final, trash)
            _rmtree(trash)
    if not final.exists():
        final.parent.mkdir(parents=True, exist_ok=True)
        _replace(staged, final)
    elif staged.resolve() != final.resolve():
        _rmtree(staged)  # idempotent re-publish: the verified directory is already in place
    manifest_sha = hashlib.sha256((final / MANIFEST).read_bytes()).hexdigest()
    pointer = UnifiedResultPointer(result_id=manifest.result_id, relative_dir=relative, manifest_sha256=manifest_sha,
                                   status=manifest.status, counts=manifest.counts,
                                   config_digest=manifest.config_digest)
    try:
        entry = enrichment.publish(RESULT_KIND, guard, current, revision, manifest.status, _body(pointer, limits),
                                   manifest.result_id)
    except EnrichmentError as exc:
        raise _err('The unified pointer row could not be stored', 'enrichment-limit'
                   if exc.code == 'PT-ENRICH-LIMIT' else 'pointer-publish') from None
    try:
        deleted = apply_unified_retention(enrichment, protect=(manifest.result_id,), limits=limits)
    except (UnifiedError, sqlite3.Error, OSError):
        deleted = 0  # best effort: retention never fails a publish
    return PublishedResult(entry, pointer, manifest, final, deleted)


def publish_run(enrichment: EnrichmentStore, run: UnifiedRun, *, guard: Guard, current: Guard, revision: int,
                limits: UnifiedLimits = DEFAULT_LIMITS) -> Entry:
    _require_owner(enrichment)
    if enrichment.read_only:
        raise _err('Project enrichment data was written by a newer PatchTrace', 'read-only-store',
                   'PT-UNIFIED-STALE')
    try:
        return enrichment.publish(RUN_KIND, guard, current, revision, run.status, _body(run, limits), run.run_id)
    except EnrichmentError as exc:
        raise _err('The unified run row could not be stored', 'enrichment-limit'
                   if exc.code == 'PT-ENRICH-LIMIT' else 'run-publish') from None


def _pointers(enrichment: EnrichmentStore, current: Guard | None = None):
    """Valid pointer rows newest first, plus the ids skipped as corrupt or invalid (cache misses)."""
    skipped: list[str] = []
    out = []
    for entry in enrichment.entries(RESULT_KIND, current, on_corrupt=skipped.append):
        try:
            out.append((entry, UnifiedResultPointer.model_validate_json(json.dumps(entry.body))))
        except ValidationError:
            skipped.append(entry.id)
    return out, skipped


@dataclass(frozen=True)
class LoadedResult:
    state: str                      # 'current' | 'stale' | 'none' | 'invalid'
    reason: str | None
    entry: Entry | None = None
    pointer: UnifiedResultPointer | None = None
    manifest: UnifiedResultManifest | None = None
    directory: Path | None = None
    skipped: tuple[str, ...] = ()


def load_result(enrichment: EnrichmentStore, current: Guard,
                limits: UnifiedLimits = DEFAULT_LIMITS) -> LoadedResult:
    """The current result if one verifies, else the newest stale one (shown for reference), never a crash."""
    _require_owner(enrichment)
    rows, skipped = _pointers(enrichment, current)
    if not rows:
        return LoadedResult('none', 'no-result', skipped=tuple(skipped))
    entry, pointer = next(((e, p) for e, p in rows if not e.stale), rows[0])
    try:
        directory = safe_path(enrichment.store.root, pointer.relative_dir)
        manifest = verify_result_dir(directory, expected_result_id=pointer.result_id,
                                     expected_manifest_sha256=pointer.manifest_sha256, limits=limits)
    except (UnifiedError, ValueError) as exc:
        return LoadedResult('invalid', getattr(exc, 'reason', None) or 'dir-invalid', entry, pointer,
                            skipped=tuple(skipped))
    return LoadedResult('stale' if entry.stale else 'current', 'guard-moved' if entry.stale else None, entry,
                        pointer, manifest, directory, tuple(skipped))


def cached_result(enrichment: EnrichmentStore, result_id: str,
                  limits: UnifiedLimits = DEFAULT_LIMITS) -> LoadedResult | None:
    """A verified result with this id, or None (corrupt rows and directories are cache misses)."""
    _require_owner(enrichment)
    rows, _ = _pointers(enrichment)
    for entry, pointer in rows:
        if pointer.result_id == result_id:
            try:
                directory = safe_path(enrichment.store.root, pointer.relative_dir)
                manifest = verify_result_dir(directory, expected_result_id=result_id,
                                             expected_manifest_sha256=pointer.manifest_sha256, limits=limits)
            except (UnifiedError, ValueError):
                return None
            return LoadedResult('current', None, entry, pointer, manifest, directory)
    return None


# --- backup and own deletion (A-04 wrappers, public API only) ---------------------------------------------------

def _snapshot(db: sqlite3.Connection) -> tuple:
    row = db.execute("SELECT sha256, json_extract(payload, '$.id') FROM current_snapshot WHERE singleton=1").fetchone()
    return tuple(row) if row else (None, None)


def _unified_rows(db: sqlite3.Connection) -> list[tuple]:
    return db.execute('SELECT id, body_sha256 FROM enrichment_entries WHERE kind IN (?, ?) ORDER BY id',
                      UNIFIED_KINDS).fetchall()


def _trusted(path: Path, project_id: str | None) -> bool:
    try:
        info = path.stat()
        key = (str(path), info.st_size, info.st_mtime_ns)
        if key in _TRUSTED:
            return _TRUSTED[key] == project_id
        copy = sqlite3.connect(f'{path.resolve().as_uri()}?mode=ro', uri=True, timeout=5)
        try:
            ok = copy.execute('PRAGMA quick_check').fetchone()[0] == 'ok'
            tables = {r[0] for r in copy.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            pid = _snapshot(copy)[1] if ok and 'enrichment_entries' in tables else None
        finally:
            copy.close()
    except (sqlite3.Error, OSError, ValueError):
        return False
    if pid is None:
        return False
    _TRUSTED[key] = pid
    return pid == project_id


def backup_once(enrichment: EnrichmentStore, label: str = BACKUP_LABEL) -> Path:
    """Reuse a trusted `backups/project-pre-<label>-*.sqlite3` of this project or write and verify a new one:
    `.part` copy through the SQLite backup API, closed, re-opened read-only, `integrity_check`, snapshot and
    unified rows compared with the live database, then renamed. Raises UnifiedError(STORE) on failure."""
    _require_owner(enrichment)
    if not label.replace('-', '').isalnum() or not label.islower() or len(label) > 32:
        raise _err('Invalid backup label', 'bad-label', 'PT-UNIFIED-INPUT')
    root, db = enrichment.store.root, enrichment.store.connection
    live_sha, project_id = _snapshot(db)
    directory = safe_path(root, 'backups')
    directory.mkdir(exist_ok=True)
    for candidate in sorted(directory.glob(f'project-pre-{label}-*.sqlite3'), reverse=True):
        if not candidate.is_symlink() and _trusted(candidate, project_id):
            return candidate
    stamp = datetime.now(UTC).strftime('%Y%m%dT%H%M%S%fZ')
    target = safe_path(root, f'backups/project-pre-{label}-{stamp}.sqlite3')
    part = safe_path(root, f'backups/project-pre-{label}-{stamp}.sqlite3.part')
    try:
        copy = sqlite3.connect(part)
        try:
            db.backup(copy)
        finally:
            copy.close()
        check = sqlite3.connect(f'{part.resolve().as_uri()}?mode=ro', uri=True, timeout=5)
        try:
            ok = (check.execute('PRAGMA integrity_check').fetchone()[0] == 'ok'
                  and _snapshot(check) == (live_sha, project_id) and _unified_rows(check) == _unified_rows(db))
        finally:
            check.close()
        if not ok:
            raise _err('The pre-deletion backup failed verification', 'backup-failed')
        _replace(part, target)
    except (sqlite3.Error, OSError) as exc:
        part.unlink(missing_ok=True)
        raise _err('The pre-deletion backup could not be written', 'backup-failed') from exc
    except UnifiedError:
        part.unlink(missing_ok=True)
        raise
    return target


def delete_own(enrichment: EnrichmentStore, ids: Iterable[str], kinds: Iterable[str] = UNIFIED_KINDS) -> int:
    """Delete `unified-*` rows only, in one transaction, after `backup_once`. Other kinds are refused."""
    kinds = tuple(sorted(set(kinds)))
    if not kinds or not set(kinds) <= set(UNIFIED_KINDS):
        raise _err('Only unified kinds can be deleted here', 'foreign-kind', 'PT-UNIFIED-INPUT')
    ids = sorted(set(ids))
    _require_owner(enrichment)
    if not ids or enrichment.read_only:
        return 0
    backup_once(enrichment)
    db = enrichment.store.connection
    if db.in_transaction:
        raise _err('Another transaction is open on the project database', 'transaction-open')
    deleted = 0
    db.execute('BEGIN IMMEDIATE')
    try:
        marks = ','.join('?' * len(kinds))
        for start in range(0, len(ids), 400):
            chunk = ids[start:start + 400]
            deleted += db.execute(f'DELETE FROM enrichment_entries WHERE id IN ({",".join("?" * len(chunk))}) '
                                  f'AND kind IN ({marks})', (*chunk, *kinds)).rowcount
    except BaseException:
        db.execute('ROLLBACK')
        raise
    db.execute('COMMIT')
    return deleted


def apply_unified_retention(enrichment: EnrichmentStore, *, protect: Iterable[str] = (),
                            limits: UnifiedLimits = DEFAULT_LIMITS) -> int:
    """Keep the newest L-32 results per config_digest (plus `protect`) and the newest RUN_KEEP run rows; delete
    the rest (rows first, then their directories). Rows that do not validate are never deleted here."""
    _require_owner(enrichment)
    if enrichment.read_only:
        return 0
    rows, _ = _pointers(enrichment)
    keep = set(protect)
    per_config: dict[str, int] = {}
    doomed = []
    for entry, pointer in rows:  # newest first
        per_config[pointer.config_digest] = per_config.get(pointer.config_digest, 0) + 1
        if entry.id not in keep and per_config[pointer.config_digest] > limits.l32_results_kept:
            doomed.append((entry.id, pointer.relative_dir))
    runs = enrichment.entries(RUN_KIND, on_corrupt=lambda _id: None)
    doomed_runs = [e.id for e in runs[RUN_KEEP:]]
    if not doomed and not doomed_runs:
        return 0
    deleted = delete_own(enrichment, [i for i, _ in doomed] + doomed_runs)
    referenced = {p.relative_dir for e, p in _pointers(enrichment)[0]}
    for _id, relative in doomed:
        if relative not in referenced:
            path = safe_path(enrichment.store.root, relative)
            if path.is_dir() and not path.is_symlink():
                _rmtree(path)
    return deleted
