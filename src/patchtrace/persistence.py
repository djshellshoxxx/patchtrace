"""Validated SQLite snapshots, bounded history, writer ownership and backups.

History is append-only per save but pruned in the same transaction (SPEC-07h H2): the newest
HISTORY_KEEP rows and at most HISTORY_MAX_BYTES of payload are kept; the current snapshot and the
newest snapshot of every revision (revision-bump snapshots) are never pruned. No history row is
deleted before a re-opened, integrity-checked `backups/project-pre-history-prune-*` backup exists
(`verified_backup.py`); when it cannot be made, the save still commits and every row is kept.
"""
from __future__ import annotations

import json
import logging
import math
import os
import shutil
import socket
import sqlite3
import stat
import tempfile
import unicodedata
from pathlib import Path
from uuid import uuid4

from pydantic import ValidationError

from . import verified_backup
from .ingestion import file_fingerprint, safe_path, sha256_file, verify_artifact
from .models import ComparisonProject, now

SCHEMA_VERSION = 1
MAX_SNAPSHOT_BYTES = 256 * 1024 * 1024
HISTORY_KEEP = 100
HISTORY_MAX_BYTES = 512 * 1024 * 1024
HISTORY_BACKUP_LABEL = 'history-prune'
_HISTORY_STATS = 'SELECT COUNT(*), MAX(sequence) FROM history'


def strict_json(text: str) -> dict:
    def pairs(items):
        value, seen = {}, set()
        for key, item in items:
            folded = unicodedata.normalize('NFC', key)  # NFC and NFD spellings are one key, as for archive member names
            if folded in seen:
                raise ValueError(f'PT-SCHEMA: duplicate JSON key {key}')
            seen.add(folded)
            value[key] = item
        return value
    def invalid_constant(value):
        raise ValueError(f'PT-SCHEMA: invalid JSON number {value}')
    def finite_float(value):
        # Overflowing literals such as 1e999 parse to inf without reaching parse_constant.
        number = float(value)
        if not math.isfinite(number):
            invalid_constant(value[:40])
        return number
    def bounded_int(value):
        try:
            return int(value)
        except ValueError as exc:
            raise ValueError('PT-SCHEMA: JSON integer exceeds the supported digit limit') from exc
    try:
        value = json.loads(text, object_pairs_hook=pairs, parse_constant=invalid_constant,
                           parse_float=finite_float, parse_int=bounded_int)
        # A lone surrogate escape (\\ud800) parses but cannot be stored or hashed as UTF-8.
        json.dumps(value, ensure_ascii=False).encode('utf-8')
        return value
    except UnicodeEncodeError as exc:
        raise ValueError('PT-SCHEMA: JSON contains an unpaired surrogate escape') from exc
    except RecursionError as exc:
        raise ValueError('PT-SCHEMA: JSON nesting limit exceeded') from exc


def validate_project(project: ComparisonProject) -> ComparisonProject:
    """Validate the complete aggregate, including references beyond model ownership."""
    project = ComparisonProject.model_validate(project.model_dump(mode='json'))
    seen = {}
    def register(record, reusable=False):
        if record.id in seen:
            if reusable and seen[record.id] == record:
                return
            raise ValueError('PT-SCHEMA: duplicate or conflicting entity identifier')
        seen[record.id] = record
    register(project)
    artifacts = {item.id: item for item in project.artifacts}
    runs = {item.id: item for item in project.runs}
    matches = {item.id: item for item in project.matches}
    functions = {}
    for item in [*project.artifacts, *project.runs, *project.matches, *project.annotations]:
        register(item)
    for match in project.matches:
        for func in match.older + match.newer:
            if func.id in functions:
                raise ValueError('PT-SCHEMA: one function cannot belong to multiple active matches')
            register(func)
            functions[func.id] = func
        if match.category in {'modified', 'unchanged', 'split', 'merged'} and not (match.older and match.newer):
            raise ValueError('PT-SCHEMA: paired match category requires both sides')
        if match.category == 'split' and (len(match.older) != 1 or len(match.newer) < 2):
            raise ValueError('PT-SCHEMA: split requires one older and multiple newer functions')
        if match.category == 'merged' and (len(match.older) < 2 or len(match.newer) != 1):
            raise ValueError('PT-SCHEMA: merged requires multiple older and one newer function')
    for interpretation in project.interpretations:
        register(interpretation)
        context = interpretation.context
        register(context, reusable=True)
        from .interpretation import validate_context
        data = validate_context(context.model_copy(update={'stale': False}))
        if context.project_id != project.id or context.revision > project.revision:
            raise ValueError('PT-SCHEMA: interpretation context belongs to a different project/revision')
        if not context.stale and context.revision != project.revision:
            raise ValueError('PT-SCHEMA: outdated interpretation context must be marked stale')
        if len(context.match_ids) != len(set(context.match_ids)):
            raise ValueError('PT-SCHEMA: duplicate selected match identifiers')
        if not context.stale and not set(context.match_ids) <= matches.keys():
            raise ValueError('PT-SCHEMA: context refers to an absent active match')
        from .evidence import _related
        declared = {item['id']: item for item in data['matches']}
        declared_artifacts = {item['id']: item for item in data['artifacts']}
        if set(declared_artifacts) != set(artifacts) or any(
                declared_artifacts[aid]['sha256'] != artifact.sha256 for aid, artifact in artifacts.items()):
            raise ValueError('PT-SCHEMA: context payload input hashes do not match project')
        if any(item['run_id'] not in runs for item in declared.values()):
            raise ValueError('PT-SCHEMA: context declares an unknown analysis run')
        allowed = set()
        if not context.stale:
            for mid in context.match_ids:
                match = matches[mid]
                roots = match.older + match.newer
                scope = {func.id for func in roots}
                for func in roots:
                    for reference in func.callers + func.callees:
                        neighbor = _related(functions, func, reference)
                        if neighbor is not None:
                            scope.add(neighbor.id)
                declaration = declared[mid]
                if (declaration['run_id'] != match.run_id or declaration['category'] != match.category
                        or set(declaration['function_ids']) != {func.id for func in roots}
                        or set(declaration['context_function_ids']) != scope):
                    raise ValueError('PT-SCHEMA: context payload function scope differs from project')
                allowed.update(scope)
        evidence_ids = set()
        for evidence in context.evidence:
            register(evidence, reusable=True)
            evidence_ids.add(evidence.id)
            if evidence.artifact_id not in artifacts or evidence.run_id not in runs:
                raise ValueError('PT-SCHEMA: evidence has unknown artifact or analysis run')
            # Historical orientation is retained in stale contexts.
            if not context.stale:
                func = functions.get(evidence.function_id)
                if (func is None or func.artifact_id != evidence.artifact_id or func.run_id != evidence.run_id
                        or artifacts[evidence.artifact_id].side != evidence.side):
                    raise ValueError('PT-SCHEMA: evidence function ownership mismatch')
                if evidence.function_id not in allowed:
                    raise ValueError('PT-SCHEMA: evidence is unrelated to selected functions')
                lines = (func.code or '').splitlines()
                if evidence.end_line > len(lines) or evidence.text != '\n'.join(
                        lines[evidence.start_line - 1:evidence.end_line]):
                    raise ValueError('PT-SCHEMA: evidence does not match exact decompilation lines')
        for finding in interpretation.findings:
            register(finding)
            if finding.context_id != context.id or not set(finding.match_ids) <= set(context.match_ids):
                raise ValueError('PT-SCHEMA: finding context/match ownership mismatch')
            finding_scope = {(declared[mid]['run_id'], fid) for mid in finding.match_ids
                             for fid in declared[mid]['context_function_ids']}
            finding_evidence = {ref.id for ref in context.evidence
                                if (ref.run_id, ref.function_id) in finding_scope}
            for hypothesis in [finding.hypothesis, *finding.alternatives]:
                register(hypothesis)
                if not set(hypothesis.supporting + hypothesis.contradicting) <= evidence_ids.intersection(finding_evidence):
                    raise ValueError('PT-SCHEMA: finding cites unknown evidence')
            if context.stale and not finding.stale:
                raise ValueError('PT-SCHEMA: stale context requires stale findings')
    # An annotation may target historical IDs after invalidation, but never a foreign active object.
    for annotation in project.annotations:
        if not annotation.stale and annotation.target_id not in seen:
            raise ValueError('PT-SCHEMA: annotation target is not owned by project')
    return project


def _clear_readonly_and_retry(function, path, _exc):
    # Copied artifacts/raw outputs are read-only; Windows refuses to delete them otherwise.
    os.chmod(path, stat.S_IWRITE | stat.S_IREAD)
    function(path)


def _publish_no_replace(stage: Path, destination: Path) -> None:
    """Move stage to an absent destination. POSIX os.replace would replace an empty dir."""
    if os.name == 'nt':
        os.replace(stage, destination)  # Windows refuses to replace an existing directory.
        return
    os.mkdir(destination)  # reservation: fails if anything appeared at destination
    try:
        os.rename(stage, destination)
    except OSError:
        os.rmdir(destination)
        raise


def _error_location(exc: ValidationError) -> str:
    """Field path of the first contract violation; never the offending value."""
    return '.'.join(str(part) for part in exc.errors()[0]['loc']) or 'root'


def _abandoned_creation(path: Path) -> bool:
    """True for the database a creation leaves when it died before committing its first snapshot.

    The caller holds the exclusive project lock, so no live creator owns the file. A database that holds
    a snapshot, a history row or any foreign table is never treated as abandoned."""
    try:
        if path.stat().st_size == 0:
            return True
        probe = sqlite3.connect(path, timeout=5)
        try:
            if probe.execute('PRAGMA user_version').fetchone()[0] not in (0, SCHEMA_VERSION):
                return False
            tables = {row[0] for row in probe.execute("SELECT name FROM sqlite_master WHERE type='table'")
                      if not row[0].startswith('sqlite_')}
            if not tables:
                return True
            return tables == {'current_snapshot', 'history'} and not probe.execute(
                'SELECT EXISTS(SELECT 1 FROM current_snapshot) OR EXISTS(SELECT 1 FROM history)').fetchone()[0]
        finally:
            probe.close()
    except (sqlite3.Error, OSError):
        return False


class ProjectLock:
    """Kernel-owned advisory lock; crashes release it without stealing a live lock file."""
    def __init__(self, root: Path):
        self.path = safe_path(root, '.patchtrace.lock')
        self.stream = None
        try:
            flags = os.O_RDWR | os.O_CREAT | getattr(os, 'O_NOFOLLOW', 0)
            fd = os.open(self.path, flags, 0o600)
            self.stream = os.fdopen(fd, 'r+b')
            if os.name == 'nt':
                import msvcrt
                if os.fstat(fd).st_size == 0:
                    self.stream.write(b' ')
                    self.stream.flush()
                self.stream.seek(0)
                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            payload = json.dumps({'pid': os.getpid(), 'host': socket.gethostname(),
                                  'token': str(uuid4()), 'opened': now()}).encode()
            self.stream.seek(0)
            self.stream.write(payload.ljust(4096, b' '))
            self.stream.flush()
        except OSError as exc:
            if self.stream:
                self.stream.close()
                self.stream = None
            raise ValueError('PT-STORAGE: project is locked by another writer or lock is inaccessible') from exc

    def close(self):
        if self.stream is not None:
            if os.name == 'nt':
                import msvcrt
                self.stream.seek(0)
                msvcrt.locking(self.stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.stream.fileno(), fcntl.LOCK_UN)
            self.stream.close()
            self.stream = None


class ProjectStore:
    def __init__(self, root: Path, create: bool = False):
        self.root = Path(root).resolve()
        self.closed = False
        self.connection = None
        self.lock = None
        self._verified = {}
        self.project_id: str | None = None  # known after the first load/save; never changes for a database
        self._prune_deferred = False
        self._prune_blocked = False  # a pre-prune backup failed in this session: keep every row
        if create:
            try:
                self.root.mkdir(parents=True, exist_ok=True)
            except OSError as exc:
                raise ValueError(f'PT-STORAGE: project directory cannot be created: {exc.strerror or exc}') from exc
        if not self.root.is_dir():
            raise ValueError('PT-STORAGE: project directory does not exist')
        self.lock = ProjectLock(self.root)
        created_database = False
        try:
            path = safe_path(self.root, 'project.sqlite3')
            if create and path.exists():
                if not _abandoned_creation(path):
                    raise ValueError('PT-STORAGE: project database already exists')
                for suffix in ('', '-journal', '-wal', '-shm'):  # a killed creation left no snapshot to lose
                    Path(f'{path}{suffix}').unlink(missing_ok=True)
            if not create and not path.is_file():
                raise ValueError('PT-STORAGE: project database is missing')
            self.connection = sqlite3.connect(path, timeout=5)
            created_database = create
            self.connection.execute('PRAGMA foreign_keys=ON')
            if create:
                with self.connection:
                    # Legacy sqlite3 mode does not BEGIN before PRAGMA/DDL; make initialization atomic.
                    self.connection.execute('BEGIN IMMEDIATE')
                    self.connection.execute(f'PRAGMA user_version={SCHEMA_VERSION}')
                    self.connection.execute('CREATE TABLE current_snapshot (singleton INTEGER PRIMARY KEY '
                                            'CHECK(singleton=1), payload TEXT NOT NULL, sha256 TEXT NOT NULL)')
                    self.connection.execute('CREATE TABLE history (sequence INTEGER PRIMARY KEY AUTOINCREMENT, '
                                            'revision INTEGER NOT NULL, created TEXT NOT NULL, payload TEXT '
                                            'NOT NULL, sha256 TEXT NOT NULL)')
            else:
                version = self.connection.execute('PRAGMA user_version').fetchone()[0]
                if version != SCHEMA_VERSION:
                    raise ValueError(f'PT-SCHEMA: unsupported database version {version}')
                if self.connection.execute('PRAGMA quick_check').fetchone()[0] != 'ok':
                    raise ValueError('PT-STORAGE: database integrity check failed')
        except Exception as exc:
            self.close()
            if created_database:
                # Never leave a half-initialized database that blocks retry yet cannot be opened.
                path.unlink(missing_ok=True)
            if isinstance(exc, sqlite3.Error):
                raise ValueError('PT-STORAGE: project database cannot be opened') from exc
            raise

    def _check_open(self):
        if self.closed:
            raise ValueError('PT-STORAGE: project is closed')

    @staticmethod
    def file_fingerprint(path: Path) -> tuple:
        return file_fingerprint(path)

    def remember_verified(self, path: Path, sha256: str, fingerprint: tuple) -> None:
        if self.file_fingerprint(path) != fingerprint:
            raise ValueError('PT-STORAGE: immutable file changed during verification')
        self._verified[str(path)] = (fingerprint, sha256)

    def _verify_files(self, project: ComparisonProject) -> None:
        for artifact in project.artifacts:
            path = safe_path(self.root, artifact.relative_path)
            try:
                fingerprint = self.file_fingerprint(path)
            except OSError as exc:
                raise ValueError('PT-STORAGE: immutable input is missing') from exc
            if self._verified.get(str(path)) != (fingerprint, artifact.sha256):
                verify_artifact(artifact, self.root)
                self.remember_verified(path, artifact.sha256, fingerprint)
            elif artifact.relative_path != f'artifacts/{artifact.sha256}.bin' or fingerprint[2] != artifact.size:
                raise ValueError('PT-STORAGE: artifact path/size does not match its hash')
        for run in project.runs:
            if (run.raw_path is None) != (run.raw_sha256 is None):
                raise ValueError('PT-SCHEMA: raw path and hash must be present together')
            if run.raw_path:
                raw = safe_path(self.root, run.raw_path)
                try:
                    fingerprint = self.file_fingerprint(raw)
                    if self._verified.get(str(raw)) != (fingerprint, run.raw_sha256):
                        if not raw.is_file() or sha256_file(raw) != run.raw_sha256:
                            raise ValueError('PT-STORAGE: preserved raw output changed or is missing')
                        self.remember_verified(raw, run.raw_sha256, fingerprint)
                except OSError as exc:
                    raise ValueError('PT-STORAGE: preserved raw output is unreadable') from exc

    def save(self, project: ComparisonProject) -> ComparisonProject:
        import hashlib
        self._check_open()
        validated = validate_project(project)
        self._verify_files(validated)
        payload = validated.model_dump_json()
        if len(payload.encode()) > MAX_SNAPSHOT_BYTES:
            raise ValueError('PT-STORAGE: project snapshot exceeds 256 MiB')
        self._assert_reloadable(payload)
        sha = hashlib.sha256(payload.encode()).hexdigest()
        self._prune_deferred = False
        try:
            with self.connection:
                self.connection.execute('BEGIN IMMEDIATE')
                current = self.connection.execute(
                    "SELECT json_extract(payload,'$.id'), json_extract(payload,'$.revision') "
                    'FROM current_snapshot WHERE singleton=1').fetchone()
                if current is not None and (current[0] != validated.id or current[1] > validated.revision):
                    raise ValueError('PT-STORAGE: snapshot belongs to another project or is older than the '
                                     'stored revision; reopen the project')
                newest = self.connection.execute(
                    'SELECT sha256 FROM history ORDER BY sequence DESC LIMIT 1').fetchone()
                if newest is None or newest[0] != sha:
                    self.connection.execute('INSERT INTO history(revision,created,payload,sha256) VALUES(?,?,?,?)',
                                            (validated.revision, now(), payload, sha))
                self.connection.execute('INSERT INTO current_snapshot(singleton,payload,sha256) VALUES(1,?,?) '
                                        'ON CONFLICT(singleton) DO UPDATE SET payload=excluded.payload, '
                                        'sha256=excluded.sha256', (payload, sha))
                self._prune_history(sha, validated.id)
        except sqlite3.Error as exc:
            raise ValueError('PT-STORAGE: project save failed; prior snapshot retained') from exc
        self.project_id = validated.id
        if self._prune_deferred:
            self._deferred_prune(sha, validated.id)
        return validated

    @staticmethod
    def _assert_reloadable(payload: str) -> None:
        """Commit only what load() accepts. Non-finite floats serialise as null and oversized integers exceed
        the parse limit; without this check such a save succeeds and the project can no longer be opened."""
        try:
            ComparisonProject.model_validate(strict_json(payload))
        except ValidationError as exc:
            raise ValueError(f'PT-SCHEMA: project snapshot would not reload (at {_error_location(exc)}); '
                             'prior snapshot retained') from None
        except ValueError as exc:
            raise ValueError(f'{exc}; prior snapshot retained') from None

    def _deferred_prune(self, current_sha: str, project_id: str) -> None:
        """First prune of a session without a trusted backup (SPEC-07h H2): the save is committed; take and
        verify the backup outside any transaction, then prune in a second transaction. Any failure keeps
        every history row; a failed backup is not retried in this session (it copies the whole database)."""
        try:
            verified_backup.ensure_verified_backup(
                self.root, self.connection, HISTORY_BACKUP_LABEL, project_id=project_id,
                compare=(_HISTORY_STATS,), require_tables=('history',))
        except verified_backup.BackupError as exc:
            self._prune_blocked = True
            logging.getLogger(__name__).warning('History not pruned; every row kept (pre-prune backup: %s)', exc)
            return
        try:
            with self.connection:
                self.connection.execute('BEGIN IMMEDIATE')
                self._prune_history(current_sha, project_id)
        except sqlite3.Error as exc:
            logging.getLogger(__name__).warning('History prune failed; every row kept (%s)', type(exc).__name__)

    def _prune_history(self, current_sha: str, project_id: str | None = None) -> None:
        """Bound the history table inside the caller's transaction (oldest rows first). Deletes only while
        a verified pre-prune backup is trusted; otherwise flags the prune as deferred and deletes nothing."""
        rows = self.connection.execute(
            'SELECT sequence,revision,sha256,length(CAST(payload AS BLOB)) FROM history '
            'ORDER BY sequence DESC').fetchall()
        total = sum(row[3] for row in rows)
        if len(rows) <= HISTORY_KEEP and total <= HISTORY_MAX_BYTES:
            return
        hard: set[int] = set()
        seen_revisions: set[int] = set()
        current_seen = False
        for sequence, revision, sha, _size in rows:  # newest first
            if revision not in seen_revisions:
                seen_revisions.add(revision)
                hard.add(sequence)
            if sha == current_sha and not current_seen:
                current_seen = True
                hard.add(sequence)
        delete: list[int] = []
        for index, (sequence, _revision, _sha, size) in enumerate(rows):
            if index >= HISTORY_KEEP and sequence not in hard:
                delete.append(sequence)
                total -= size
        if total > HISTORY_MAX_BYTES:
            gone = set(delete)
            for sequence, _revision, _sha, size in reversed(rows):  # oldest first
                if total <= HISTORY_MAX_BYTES:
                    break
                if sequence not in hard and sequence not in gone:
                    delete.append(sequence)
                    total -= size
        if not delete or self._prune_blocked:
            return
        if verified_backup.trusted_backup(self.root, HISTORY_BACKUP_LABEL, project_id=project_id,
                                          require_tables=('history',)) is None:
            self._prune_deferred = True
            return
        for start in range(0, len(delete), 500):
            chunk = delete[start:start + 500]
            self.connection.execute(f'DELETE FROM history WHERE sequence IN ({",".join("?" * len(chunk))})', chunk)

    def load(self) -> ComparisonProject:
        import hashlib
        self._check_open()
        try:
            row = self.connection.execute('SELECT payload,sha256 FROM current_snapshot WHERE singleton=1').fetchone()
            if row is None:
                raise ValueError('PT-STORAGE: project snapshot is missing')
            payload, sha = row
            if len(payload.encode()) > MAX_SNAPSHOT_BYTES or hashlib.sha256(payload.encode()).hexdigest() != sha:
                raise ValueError('PT-STORAGE: project snapshot hash failed')
            try:
                project = validate_project(ComparisonProject.model_validate(strict_json(payload)))
            except ValidationError as exc:
                raise ValueError('PT-SCHEMA: stored project snapshot violates the v1 contract '
                                 f'(at {_error_location(exc)})') from None
            self._verify_files(project)
            self.project_id = project.id
            interrupted = [run for run in project.runs if run.status in {'queued', 'running'}]
            for run in interrupted:
                run.status = 'failed'
                run.error = 'Analysis was interrupted before a terminal result was saved'
            if interrupted:
                project = self.save(project)
            return project
        except sqlite3.Error as exc:
            raise ValueError('PT-STORAGE: project snapshot cannot be read') from exc

    def history(self) -> list[dict]:
        self._check_open()
        return [dict(sequence=row[0], revision=row[1], created=row[2], sha256=row[3]) for row in
                self.connection.execute('SELECT sequence,revision,created,sha256 FROM history ORDER BY sequence')]

    def backup(self, destination: Path) -> Path:
        """Publish a complete new project copy only after SQLite backup and immutable files succeed."""
        self._check_open()
        self.load()
        destination = Path(destination).resolve()
        if destination.exists() or destination.is_relative_to(self.root):
            raise ValueError('PT-STORAGE: backup destination must be new and outside project')
        try:
            destination.parent.mkdir(parents=True, exist_ok=True)
            stage = Path(tempfile.mkdtemp(prefix='.patchtrace-backup-', dir=destination.parent))
        except OSError as exc:
            raise ValueError(f'PT-STORAGE: backup destination is not writable: {exc.strerror or exc}') from exc
        try:
            backup_connection = sqlite3.connect(stage / 'project.sqlite3')
            try:
                self.connection.backup(backup_connection)
            finally:
                backup_connection.close()
            # Unified, secondary and raw sidecars live under runs/ and enrichment rows in the database;
            # `kb/` and `intelligence/` (CSAF advisories) are top-level sidecars (KB plan A-6).
            for name in ('artifacts', 'runs', 'exports', 'kb', 'intelligence'):
                source = safe_path(self.root, name)
                if source.exists():
                    # Refuse arbitrary worker-created symlinks; backup cannot escape the case.
                    for candidate in source.rglob('*'):
                        if candidate.is_symlink():
                            raise ValueError('PT-STORAGE: backup contains a symlink')
                    shutil.copytree(source, stage / name)
            _publish_no_replace(stage, destination)
            return destination
        finally:
            if stage.exists():
                shutil.rmtree(stage, onexc=_clear_readonly_and_retry)

    def close(self):
        if self.connection is not None:
            self.connection.close()
            self.connection = None
        if self.lock is not None:
            self.lock.close()
            self.lock = None
        self.closed = True

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
