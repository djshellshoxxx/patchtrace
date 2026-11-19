"""Companion workspace store and project attachment (KB-integration-plan 7.3; slice K2).

``WorkspaceStore`` is one SQLite file (``kbc.sqlite3``, ``user_version=1``) plus content-addressed gzip objects
(``objects/<sha[:2]>/<sha>.gz``) in a local, never roaming, directory. A store written by a newer client opens
read-only and every write fails closed with ``PT-KBC-STORAGE``. Writes use ``BEGIN IMMEDIATE`` and a busy timeout;
revisions advance by compare-and-swap; revisions, attempts and decisions are append-only (triggers reject UPDATE and
DELETE). The edges table is compact (dictionary ids for KB, CVE and product scope); full records are rebuilt by
parsing the stored object again (``load_index``), so the table is a lookup path, not a second source of truth.

``ProjectAttachment`` is the two-phase attach: verify both files, journal the intent, create the project through
``ProjectPort``, journal its id, write sidecars, write enrichment rows, mark done. Every step is idempotent and
resumable from the journal, so a hard kill at any point leaves a valid project and ``CONTEXT_PENDING`` at worst.
Nothing here deletes a project or a user file. ``fault`` is a test seam: a callable invoked with a crash-point name
(``index_after_doc``, ``index_before_commit``, ``attach_before_row``, ``after_project_create``,
``after_sidecar_write``, ``before_cas``).
"""
from __future__ import annotations

import base64
import gzip
import hashlib
import json
import os
import sqlite3
import tempfile
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from ..input_readers import HeldInput, InputReadError, PairInputReaders
from ..owned_publication import (
    OwnedPublicationError,
    directory_anchor,
    publish_bytes,
    read_bytes,
    verify_anchor,
)
from ..persistence import creation_directory_available
from .contracts import (
    AnalystDecision,
    Attempt,
    Contract,
    Coverage,
    InvestigationRevision,
    ProductScope,
    ProjectLink,
    SourceDoc,
    domain_id,
)
from .errors import KbcIssue, OperationResult
from .limits import DEFAULT_LIMITS, KbcLimits
from .ports import AdvisoryPort, ClockPort, ProjectPort
from .sources.importer import ImportedDocument, gunzip_bounded, import_bytes
from .workflow import Event, reduce

SCHEMA_VERSION = 1
DB_NAME = 'kbc.sqlite3'
Fault = Callable[[str], None]

_DDL = (
    'CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)',
    'CREATE TABLE docs (doc_id TEXT PRIMARY KEY, kind TEXT NOT NULL, sha256 TEXT NOT NULL, release_id TEXT, '
    'current_release_date TEXT, retrieved_at TEXT NOT NULL, size INTEGER NOT NULL, body TEXT NOT NULL)',
    'CREATE TABLE segments (doc_id TEXT NOT NULL, name TEXT NOT NULL, rows INTEGER NOT NULL, '
    'PRIMARY KEY (doc_id, name)) WITHOUT ROWID',
    'CREATE TABLE coverage (coverage_id TEXT PRIMARY KEY, body TEXT NOT NULL)',
    'CREATE TABLE kbs (id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE)',
    'CREATE TABLE cves (id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE)',
    'CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE)',
    'CREATE TABLE edges (kb INTEGER NOT NULL, cve INTEGER NOT NULL, product INTEGER NOT NULL, doc TEXT NOT NULL, '
    'ptr TEXT NOT NULL, rel TEXT NOT NULL, fixed_build TEXT, PRIMARY KEY (kb, cve, product, doc, ptr, rel)) '
    'WITHOUT ROWID',
    'CREATE INDEX edges_cve ON edges (cve, kb)',
    'CREATE TABLE investigations (investigation_id TEXT PRIMARY KEY, created TEXT NOT NULL, '
    'current_revision INTEGER NOT NULL)',
    'CREATE TABLE revisions (investigation_id TEXT NOT NULL, revision INTEGER NOT NULL, body TEXT NOT NULL, '
    'body_sha256 TEXT NOT NULL, created TEXT NOT NULL, PRIMARY KEY (investigation_id, revision)) WITHOUT ROWID',
    'CREATE TABLE attempts (seq INTEGER PRIMARY KEY AUTOINCREMENT, investigation_id TEXT NOT NULL, '
    'body TEXT NOT NULL)',
    'CREATE TABLE decisions (seq INTEGER PRIMARY KEY AUTOINCREMENT, investigation_id TEXT NOT NULL, '
    'body TEXT NOT NULL)',
    'CREATE TABLE journal (op_id TEXT PRIMARY KEY, state TEXT NOT NULL, body TEXT NOT NULL, updated TEXT NOT NULL)',
    *(f'CREATE TRIGGER {t}_{op.lower()} BEFORE {op} ON {t} BEGIN SELECT RAISE(ABORT, \'append-only\'); END'
      for t in ('revisions', 'attempts', 'decisions') for op in ('UPDATE', 'DELETE')),
)

# Supported v1 base format: WITHOUT ROWID flag and full table_xinfo columns
# (name, declared type, NOT NULL, primary-key ordinal, hidden/generated flag).
# This is format admission, not a certification of constraints, triggers or rows.
_BASE_LAYOUT = {
    'meta': (0, (('key', 'TEXT', 0, 1, 0), ('value', 'TEXT', 1, 0, 0))),
    'docs': (0, (('doc_id', 'TEXT', 0, 1, 0), ('kind', 'TEXT', 1, 0, 0),
                 ('sha256', 'TEXT', 1, 0, 0), ('release_id', 'TEXT', 0, 0, 0),
                 ('current_release_date', 'TEXT', 0, 0, 0), ('retrieved_at', 'TEXT', 1, 0, 0),
                 ('size', 'INTEGER', 1, 0, 0), ('body', 'TEXT', 1, 0, 0))),
    'segments': (1, (('doc_id', 'TEXT', 1, 1, 0), ('name', 'TEXT', 1, 2, 0),
                     ('rows', 'INTEGER', 1, 0, 0))),
    'coverage': (0, (('coverage_id', 'TEXT', 0, 1, 0), ('body', 'TEXT', 1, 0, 0))),
    'kbs': (0, (('id', 'INTEGER', 0, 1, 0), ('name', 'TEXT', 1, 0, 0))),
    'cves': (0, (('id', 'INTEGER', 0, 1, 0), ('name', 'TEXT', 1, 0, 0))),
    'products': (0, (('id', 'INTEGER', 0, 1, 0), ('name', 'TEXT', 1, 0, 0))),
    'edges': (1, (('kb', 'INTEGER', 1, 1, 0), ('cve', 'INTEGER', 1, 2, 0),
                  ('product', 'INTEGER', 1, 3, 0), ('doc', 'TEXT', 1, 4, 0),
                  ('ptr', 'TEXT', 1, 5, 0), ('rel', 'TEXT', 1, 6, 0), ('fixed_build', 'TEXT', 0, 0, 0))),
    'investigations': (0, (('investigation_id', 'TEXT', 0, 1, 0), ('created', 'TEXT', 1, 0, 0),
                          ('current_revision', 'INTEGER', 1, 0, 0))),
    'revisions': (1, (('investigation_id', 'TEXT', 1, 1, 0), ('revision', 'INTEGER', 1, 2, 0),
                      ('body', 'TEXT', 1, 0, 0), ('body_sha256', 'TEXT', 1, 0, 0),
                      ('created', 'TEXT', 1, 0, 0))),
    'attempts': (0, (('seq', 'INTEGER', 0, 1, 0), ('investigation_id', 'TEXT', 1, 0, 0),
                     ('body', 'TEXT', 1, 0, 0))),
    'decisions': (0, (('seq', 'INTEGER', 0, 1, 0), ('investigation_id', 'TEXT', 1, 0, 0),
                      ('body', 'TEXT', 1, 0, 0))),
    'journal': (0, (('op_id', 'TEXT', 0, 1, 0), ('state', 'TEXT', 1, 0, 0),
                    ('body', 'TEXT', 1, 0, 0), ('updated', 'TEXT', 1, 0, 0))),
}


class KbcStoreError(Exception):
    """A storage, state or verification failure; ``issue()`` is the contract form. Messages are fixed templates."""

    def __init__(self, code: str, message: str, *, recoverable: bool = True, details: dict | None = None):
        super().__init__(message)
        self.code, self.message, self.recoverable, self.details = code, message, recoverable, details

    def issue(self) -> KbcIssue:
        return KbcIssue(code=self.code, message=self.message[:500], recoverable=self.recoverable,
                        details=self.details)


class SystemClock:
    def now_utc(self) -> str:
        return datetime.now(UTC).strftime('%Y-%m-%dT%H:%M:%SZ')


def default_workspace(environ: Mapping[str, str] | None = None, home: Path | None = None) -> Path:
    """``%LOCALAPPDATA%\\PatchTrace\\kb``, else ``$XDG_DATA_HOME/PatchTrace/kb``, else ``~/.local/share/...``."""
    env = os.environ if environ is None else environ
    for name in ('LOCALAPPDATA', 'XDG_DATA_HOME'):
        if env.get(name):
            return Path(env[name]) / 'PatchTrace' / 'kb'
    return (home or Path.home()) / '.local' / 'share' / 'PatchTrace' / 'kb'


def atomic_write(path: Path, data: bytes) -> None:
    """Write beside the target, fsync, then replace: a reader sees the old file or the whole new one."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix='.kbc-', suffix='.tmp', dir=path.parent)
    try:
        handle = os.fdopen(fd, 'wb')
        fd = None  # ownership transferred only after buffering succeeds
        with handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            if fd is not None:
                os.close(fd)
        finally:
            Path(tmp).unlink(missing_ok=True)
        raise


def _gz(data: bytes) -> bytes:
    return gzip.compress(data, compresslevel=6, mtime=0)


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(model: Contract) -> str:
    return model.model_dump_json()


def _check_existing_layout(db: sqlite3.Connection) -> None:
    for name, (without_rowid, columns) in _BASE_LAYOUT.items():
        table = db.execute("SELECT type,ncol,wr,strict FROM pragma_table_list(?) "
                           "WHERE schema='main' LIMIT 2", (name,)).fetchall()
        actual = db.execute('SELECT name,type,"notnull",pk,hidden FROM pragma_table_xinfo(?, \'main\') '
                            'ORDER BY cid LIMIT ?', (name, len(columns) + 1)).fetchall()
        if table != [('table', len(columns), without_rowid, 0)] or actual != list(columns):
            raise KbcStoreError('PT-KBC-STORAGE', 'the workspace database has an unsupported base layout',
                                recoverable=False)


class WorkspaceStore:
    def __init__(self, root: Path, *, create: bool = True, limits: KbcLimits = DEFAULT_LIMITS,
                 fault: Fault | None = None, clock: ClockPort | None = None,
                 open_mode: Literal['normal', 'existing'] = 'normal'):
        if type(open_mode) is not str or open_mode not in ('normal', 'existing'):
            raise KbcStoreError('PT-KBC-INPUT', 'the workspace open mode is invalid', recoverable=False)
        self.root = Path(root)
        self.limits = limits
        self.fault = fault or (lambda point: None)
        self.clock: ClockPort = clock or SystemClock()
        self.read_only = False
        if open_mode == 'existing':
            self._open_existing()
            return
        path = self.root / DB_NAME
        if not path.is_file():
            if not create:
                raise KbcStoreError('PT-KBC-STORAGE', 'the workspace has no kbc.sqlite3')
            self.root.mkdir(parents=True, exist_ok=True)
        # Resolve the caller's selected root once. Object children are opened
        # relative to held ordinary directories, never resolved through links.
        self._object_root = self.root.resolve(strict=True)
        path = self._object_root / DB_NAME
        try:
            self._object_anchor = directory_anchor(self._object_root)
        except (OSError, OwnedPublicationError) as exc:
            raise KbcStoreError('PT-KBC-STORAGE', 'the workspace root cannot be held and verified') from exc
        self.db = None
        try:
            self.db = sqlite3.connect(path, timeout=5, isolation_level=None)
            self.db.execute('PRAGMA busy_timeout=5000')
            version = self.db.execute('PRAGMA user_version').fetchone()[0]
            if version > SCHEMA_VERSION:
                self.db.close()
                self.db = None
                self.db = sqlite3.connect(f'{path.resolve().as_uri()}?mode=ro', uri=True, timeout=5,
                                          isolation_level=None)   # resolve: a relative root has no file URI (#105)
                self.read_only = True
            elif version == 0:
                self._create()
            if not self.read_only:
                self.db.execute('PRAGMA journal_mode=WAL')
            try:
                verify_anchor(self._object_anchor)
            except (OSError, OwnedPublicationError) as exc:
                raise KbcStoreError('PT-KBC-STORAGE',
                                    'the workspace root changed while opening its database') from exc
        except BaseException as exc:
            failure = exc
            if isinstance(exc, sqlite3.Error):
                failure = KbcStoreError('PT-KBC-STORAGE', 'the workspace database cannot be opened',
                                        details={'sqlite': type(exc).__name__})
            if self.db is not None:
                try:
                    self.db.close()
                except BaseException:
                    failure.add_note('Workspace connection cleanup failed; resources may remain.')
            if failure is not exc:
                raise failure from exc
            raise

    def _open_existing(self) -> None:
        try:
            self._object_root = self.root.resolve(strict=True)
            self._object_anchor = directory_anchor(self._object_root)
        except (OSError, OwnedPublicationError) as exc:
            raise KbcStoreError('PT-KBC-STORAGE', 'the workspace root cannot be held and verified') from exc
        db = None
        try:
            # The first connection cannot create a replacement after a path check.
            uri = (self._object_root / DB_NAME).as_uri() + '?mode=rw'
            db = sqlite3.connect(uri, uri=True, timeout=5, isolation_level=None)
            db.execute('PRAGMA busy_timeout=5000')
            version = db.execute('PRAGMA user_version').fetchone()[0]
            if version > SCHEMA_VERSION:
                raise KbcStoreError('PT-KBC-UNSUPPORTED', 'the workspace database version is unsupported',
                                    recoverable=False)
            if version != SCHEMA_VERSION:
                raise KbcStoreError('PT-KBC-STORAGE', 'the workspace database is not initialized',
                                    recoverable=False)
            _check_existing_layout(db)
            try:
                verify_anchor(self._object_anchor)
            except (OSError, OwnedPublicationError) as exc:
                raise KbcStoreError('PT-KBC-STORAGE',
                                    'the workspace root changed while opening its database') from exc
            self.db = db
        except BaseException as exc:
            failure = exc
            if isinstance(exc, sqlite3.Error):
                failure = KbcStoreError('PT-KBC-STORAGE', 'the workspace database cannot be opened',
                                        details={'sqlite': type(exc).__name__})
            if db is not None:
                try:
                    db.close()
                except BaseException:
                    failure.add_note('Workspace connection cleanup failed; resources may remain.')
            if failure is not exc:
                raise failure from exc
            raise

    def _create(self) -> None:
        self.db.execute('BEGIN IMMEDIATE')
        try:
            if self.db.execute('PRAGMA user_version').fetchone()[0] == 0:  # another process may have won the race
                for statement in _DDL:
                    self.db.execute(statement)
                self.db.execute(f'PRAGMA user_version={SCHEMA_VERSION}')
            self.db.execute('COMMIT')
        except BaseException as exc:
            try:
                if self.db.in_transaction:
                    self.db.execute('ROLLBACK')
            except BaseException:
                exc.add_note('Workspace initialization rollback failed; resources may remain.')
            raise

    def close(self) -> None:
        self.db.close()

    def __enter__(self) -> WorkspaceStore:
        return self

    def __exit__(self, *_exc) -> None:
        self.close()

    # ------------------------------------------------------------------------------------------ transactions

    def _writable(self) -> None:
        if self.read_only:
            raise KbcStoreError('PT-KBC-STORAGE', 'the workspace was written by a newer PatchTrace and is read-only',
                                recoverable=False)
        try:
            verify_anchor(self._object_anchor)
        except (OSError, OwnedPublicationError) as exc:
            raise KbcStoreError('PT-KBC-VERIFY', 'the open workspace root identity changed') from exc

    def _transaction(self, work: Callable[[sqlite3.Connection], Any]) -> Any:
        self._writable()
        try:
            self.db.execute('BEGIN IMMEDIATE')
        except sqlite3.OperationalError as exc:
            raise KbcStoreError('PT-KBC-STORAGE', 'the workspace is busy; try again') from exc
        try:
            result = work(self.db)
            self.db.execute('COMMIT')
            return result
        except BaseException as exc:
            try:
                if self.db.in_transaction:
                    self.db.execute('ROLLBACK')
            except BaseException:
                exc.add_note('Workspace transaction rollback failed; close the workspace before reuse.')
            raise

    # ------------------------------------------------------------------------------------------ objects

    def object_path(self, sha: str) -> Path:
        return self._object_root / 'objects' / sha[:2] / f'{sha}.gz'

    def write_object(self, sha: str, raw: bytes, *, require_existing: bool = False) -> None:
        self._writable()
        if _sha(raw) != sha:
            raise KbcStoreError('PT-KBC-VERIFY', 'the document bytes do not match their SHA-256')

        def validate(compressed: bytes) -> None:
            self._decode_object(compressed, sha, maximum=len(raw), expected_size=len(raw))

        try:
            publish_bytes(self.object_path(sha), _gz(raw), validate_existing=validate,
                          maximum=len(raw) + 65_536, require_existing=require_existing, anchor=self._object_anchor)
        except OwnedPublicationError as exc:
            raise KbcStoreError('PT-KBC-VERIFY', 'workspace object ownership or bytes cannot be verified') from exc
        except (OSError, NotImplementedError, AttributeError) as exc:
            raise KbcStoreError('PT-KBC-STORAGE', 'a workspace object cannot be written',
                                details={'errno': getattr(exc, 'errno', None)}) from exc

    @staticmethod
    def _decode_object(compressed: bytes, sha: str, *, maximum: int, expected_size: int | None = None) -> bytes:
        try:
            raw = gunzip_bounded(compressed, maximum)
        except Exception as exc:
            raise KbcStoreError('PT-KBC-VERIFY', 'a workspace object is damaged') from exc
        if _sha(raw) != sha or (expected_size is not None and len(raw) != expected_size):
            raise KbcStoreError('PT-KBC-VERIFY', 'a workspace object does not match its recorded bytes')
        return raw

    def read_object(self, sha: str, *, maximum: int | None = None, expected_size: int | None = None) -> bytes:
        limit = self.limits.cvrf_doc_bytes if maximum is None else maximum
        decoded: list[bytes] = []

        def validate(compressed: bytes) -> None:
            decoded.append(self._decode_object(compressed, sha, maximum=limit, expected_size=expected_size))

        try:
            read_bytes(self.object_path(sha), maximum=limit + 65_536, validate=validate,
                       anchor=self._object_anchor)
        except OwnedPublicationError as exc:
            raise KbcStoreError('PT-KBC-VERIFY', 'workspace object ownership or bytes cannot be verified') from exc
        except (OSError, NotImplementedError, AttributeError) as exc:
            raise KbcStoreError('PT-KBC-STORAGE', 'a workspace object is missing or unreadable') from exc
        return decoded[0]

    def unreferenced_objects(self) -> tuple[str, ...]:
        """SHA-256 of objects no document row refers to (crash leftovers); eviction is the caller's choice."""
        from .inventory_store import referenced_raw_hashes

        known = {r[0] for r in self.db.execute('SELECT sha256 FROM docs')}
        known.update(referenced_raw_hashes(self))
        base = self._object_root / 'objects'
        found = {p.stem for p in base.glob('*/*.gz')} if base.is_dir() else set()
        return tuple(sorted(found - known))

    # ------------------------------------------------------------------------------------------ documents

    def add_document(self, doc: ImportedDocument, raw: bytes) -> bool:
        """Store one imported document atomically; False when this exact document is already present.

        The object is written first (idempotent, content addressed), then one transaction adds the document,
        dictionary and edge rows. A kill in between leaves at most an unreferenced object."""
        self._writable()
        if raw[:2] == b'\x1f\x8b':
            raw = gunzip_bounded(raw, self.limits.cvrf_doc_bytes)
        source = doc.source
        used = self.db.execute('SELECT COALESCE(SUM(size),0) FROM docs').fetchone()[0]
        if used + source.size > self.limits.workspace_objects_bytes:
            raise KbcStoreError('PT-KBC-LIMIT', 'the workspace object budget is exhausted')
        if self.db.execute('SELECT 1 FROM docs WHERE doc_id=?', (source.doc_id,)).fetchone():
            return False
        self.write_object(source.sha256, raw)

        def work(db: sqlite3.Connection) -> bool:
            if db.execute('SELECT 1 FROM docs WHERE doc_id=?', (source.doc_id,)).fetchone():
                return False
            db.execute('INSERT INTO docs VALUES (?,?,?,?,?,?,?,?)',
                       (source.doc_id, source.kind, source.sha256, source.release_id, source.current_release_date,
                        source.retrieved_at, source.size, _json(source)))
            ids = {table: self._dictionary(db, table, names) for table, names in (
                ('kbs', {e.kb for e in doc.edges}), ('cves', {e.cve for e in doc.edges}),
                ('products', {e.scope_id for e in doc.edges}))}
            db.executemany(
                'INSERT OR IGNORE INTO edges VALUES (?,?,?,?,?,?,?)',
                [(ids['kbs'][e.kb], ids['cves'][e.cve], ids['products'][e.scope_id], source.doc_id, e.ref.pointer,
                  e.relation, e.fixed_build) for e in doc.edges])
            counts: dict[str, int] = {}
            for edge in doc.edges:
                counts[edge.relation] = counts.get(edge.relation, 0) + 1
            counts['vulnerabilities'] = doc.vulnerabilities
            db.executemany('INSERT INTO segments VALUES (?,?,?)',
                           [(source.doc_id, name, rows) for name, rows in sorted(counts.items())])
            self.fault('index_before_commit')
            return True

        added = self._transaction(work)
        if added:
            self.fault('index_after_doc')
        return added

    @staticmethod
    def _dictionary(db: sqlite3.Connection, table: str, names: Iterable[str]) -> dict[str, int]:
        db.executemany(f'INSERT OR IGNORE INTO {table}(name) VALUES (?)', [(n,) for n in sorted(names)])
        return {n: i for i, n in db.execute(f'SELECT id, name FROM {table}')}  # noqa: S608 (fixed table names)

    def sources(self) -> tuple[SourceDoc, ...]:
        rows = self.db.execute('SELECT body FROM docs ORDER BY doc_id').fetchall()
        return tuple(SourceDoc.model_validate_json(r[0]) for r in rows)

    def segments(self, doc_id: str) -> dict[str, int]:
        return dict(self.db.execute('SELECT name, rows FROM segments WHERE doc_id=? ORDER BY name', (doc_id,)))

    def edges_for_kb(self, kb: str) -> tuple[dict[str, str | None], ...]:
        return self._edges('kbs.name=?', kb)

    def edges_for_cve(self, cve: str) -> tuple[dict[str, str | None], ...]:
        return self._edges('cves.name=?', cve)

    def _edges(self, where: str, value: str) -> tuple[dict[str, str | None], ...]:
        rows = self.db.execute(
            'SELECT kbs.name, cves.name, products.name, edges.doc, edges.ptr, edges.rel, edges.fixed_build '
            'FROM edges JOIN kbs ON kbs.id=edges.kb JOIN cves ON cves.id=edges.cve '  # noqa: S608
            f'JOIN products ON products.id=edges.product WHERE {where} '
            'ORDER BY cves.name, kbs.name, products.name, edges.doc, edges.ptr, edges.rel', (value,)).fetchall()
        keys = ('kb', 'cve', 'scope_id', 'doc_id', 'pointer', 'relation', 'fixed_build')
        return tuple(dict(zip(keys, row, strict=True)) for row in rows)

    def load_index(self, advisory: AdvisoryPort | None = None):
        """Rebuild the in-memory reverse index by parsing each stored object again and checking its row counts."""
        from .index import ReverseIndex
        index = ReverseIndex()
        for source in self.sources():
            raw = self.read_object(source.sha256)
            doc = import_bytes(raw, now=source.retrieved_at, advisory=advisory, limits=self.limits)
            stored = self.segments(source.doc_id)
            if doc.doc_id != source.doc_id or sum(1 for _ in doc.edges) != sum(
                    n for k, n in stored.items() if k != 'vulnerabilities'):
                raise KbcStoreError('PT-KBC-VERIFY', 'a stored document no longer parses to its recorded rows')
            index.add(doc)
        return index

    def put_coverage(self, coverage: Coverage) -> None:
        self._transaction(lambda db: db.execute('INSERT OR IGNORE INTO coverage VALUES (?,?)',
                                                (coverage.coverage_id, _json(coverage))))

    def get_coverage(self, coverage_id: str) -> Coverage | None:
        row = self.db.execute('SELECT body FROM coverage WHERE coverage_id=?', (coverage_id,)).fetchone()
        return Coverage.model_validate_json(row[0]) if row else None

    # ------------------------------------------------------------------------------------------ investigations

    def create_investigation(self, first: InvestigationRevision) -> None:
        if first.revision != 1:
            raise KbcStoreError('PT-KBC-STATE', 'an investigation starts at revision 1')

        def work(db: sqlite3.Connection) -> None:
            if db.execute('SELECT COUNT(*) FROM investigations').fetchone()[0] >= self.limits.investigations:
                raise KbcStoreError('PT-KBC-LIMIT', 'the workspace holds the maximum number of investigations')
            if db.execute('SELECT 1 FROM investigations WHERE investigation_id=?',
                          (first.investigation_id,)).fetchone():
                raise KbcStoreError('PT-KBC-STATE', 'the investigation already exists')
            now = self.clock.now_utc()
            db.execute('INSERT INTO investigations VALUES (?,?,1)', (first.investigation_id, now))
            self._insert_revision(db, first, now)

        self._transaction(work)

    @staticmethod
    def _insert_revision(db: sqlite3.Connection, rev: InvestigationRevision, now: str) -> None:
        body = _json(rev)
        db.execute('INSERT INTO revisions VALUES (?,?,?,?,?)',
                   (rev.investigation_id, rev.revision, body, _sha(body.encode()), now))

    def append_revision(self, rev: InvestigationRevision, *, expected_current: int,
                        journal: tuple[str, str, dict] | None = None,
                        decisions: tuple[AnalystDecision, ...] = (),
                        guard: Callable[[], None] | None = None) -> None:
        """Compare-and-swap: commits only if the current revision is ``expected_current``. An optional journal
        update (op_id, state, body) lands in the same transaction, so the step and its record cannot diverge."""
        if rev.revision != expected_current + 1 or rev.parent != expected_current:
            raise KbcStoreError('PT-KBC-STATE', 'a revision must follow the current one')
        self._writable()
        self.fault('before_cas')

        def work(db: sqlite3.Connection) -> None:
            if guard is not None:
                guard()
            now = self.clock.now_utc()
            changed = db.execute('UPDATE investigations SET current_revision=? WHERE investigation_id=? '
                                 'AND current_revision=?', (rev.revision, rev.investigation_id, expected_current))
            if changed.rowcount != 1:
                raise KbcStoreError('PT-KBC-STALE', 'the investigation moved on; reload it')
            self._insert_revision(db, rev, now)
            for decision in decisions:
                db.execute('INSERT INTO decisions(investigation_id, body) VALUES (?,?)',
                           (rev.investigation_id, _json(decision)))
            if decisions:
                self.fault('after_revision_decisions')
            if journal is not None:
                self._journal_write(db, *journal, now=now)
            if guard is not None:
                guard()

        self._transaction(work)

    def current_revision(self, investigation_id: str) -> InvestigationRevision | None:
        row = self.db.execute('SELECT current_revision FROM investigations WHERE investigation_id=?',
                              (investigation_id,)).fetchone()
        return self.revision(investigation_id, row[0]) if row else None

    def revision(self, investigation_id: str, revision: int) -> InvestigationRevision | None:
        row = self.db.execute('SELECT body, body_sha256 FROM revisions WHERE investigation_id=? AND revision=?',
                              (investigation_id, revision)).fetchone()
        if row is None:
            return None
        if _sha(row[0].encode()) != row[1]:
            raise KbcStoreError('PT-KBC-VERIFY', 'a stored revision failed its integrity hash')
        return InvestigationRevision.model_validate_json(row[0])

    def revisions(self, investigation_id: str) -> tuple[InvestigationRevision, ...]:
        numbers = [r[0] for r in self.db.execute(
            'SELECT revision FROM revisions WHERE investigation_id=? ORDER BY revision', (investigation_id,))]
        return tuple(self.revision(investigation_id, n) for n in numbers)  # type: ignore[misc]

    def apply(self, snapshot: InvestigationRevision, event: Event) -> InvestigationRevision:
        """Reduce one event against the *current* revision and commit it; a rejected event raises."""
        current = self.current_revision(snapshot.investigation_id)
        if current is None or current.revision != snapshot.revision:
            raise KbcStoreError('PT-KBC-STALE', 'the investigation moved on; reload it')
        result = reduce(current, event)
        if isinstance(result, KbcIssue):
            raise KbcStoreError(result.code, result.message)
        self.append_revision(result, expected_current=current.revision)
        return result

    def append_attempt(self, investigation_id: str, attempt: Attempt) -> None:
        self._transaction(lambda db: db.execute('INSERT INTO attempts(investigation_id, body) VALUES (?,?)',
                                                (investigation_id, _json(attempt))))

    def attempts(self, investigation_id: str) -> tuple[Attempt, ...]:
        return tuple(Attempt.model_validate_json(r[0]) for r in self.db.execute(
            'SELECT body FROM attempts WHERE investigation_id=? ORDER BY seq', (investigation_id,)))

    def append_decision(self, investigation_id: str, decision: AnalystDecision) -> None:
        self._transaction(lambda db: db.execute('INSERT INTO decisions(investigation_id, body) VALUES (?,?)',
                                                (investigation_id, _json(decision))))

    def decisions(self, investigation_id: str) -> tuple[AnalystDecision, ...]:
        return tuple(AnalystDecision.model_validate_json(r[0]) for r in self.db.execute(
            'SELECT body FROM decisions WHERE investigation_id=? ORDER BY seq', (investigation_id,)))

    # ------------------------------------------------------------------------------------------ journal

    @staticmethod
    def _journal_write(db: sqlite3.Connection, op_id: str, state: str, body: dict, *, now: str) -> None:
        db.execute('INSERT INTO journal VALUES (?,?,?,?) ON CONFLICT(op_id) DO UPDATE SET state=excluded.state, '
                   'body=excluded.body, updated=excluded.updated',
                   (op_id, state, json.dumps(body, sort_keys=True, separators=(',', ':')), now))

    def journal_put(self, op_id: str, state: str, body: dict) -> None:
        now = self.clock.now_utc()
        self._transaction(lambda db: self._journal_write(db, op_id, state, body, now=now))

    def journal_get(self, op_id: str) -> tuple[str, dict] | None:
        row = self.db.execute('SELECT state, body FROM journal WHERE op_id=?', (op_id,)).fetchone()
        return (row[0], json.loads(row[1])) if row else None

    def journal_ops(self) -> tuple[tuple[str, str, dict], ...]:
        rows = self.db.execute('SELECT op_id, state, body FROM journal ORDER BY op_id').fetchall()
        return tuple((op, state, json.loads(body)) for op, state, body in rows)


# ================================================================================================ attachment

@dataclass(frozen=True)
class AttachRequest:
    """Everything an attach needs. Paths are the final files; ``source_shas`` name workspace objects to copy."""
    revision: InvestigationRevision  # in BYTES_VERIFIED
    pair_id: str
    older_path: str
    newer_path: str
    older_sha: str
    newer_sha: str
    directory: str
    source_shas: tuple[str, ...] = ()
    plan_sha: str | None = None
    selected_product: ProductScope | None = None


def _check_input_readers(readers: PairInputReaders | None, older: str, newer: str) -> None:
    if readers is not None:
        readers.checkpoint(0)
        readers.older.check(Path(older))
        readers.newer.check(Path(newer))
        readers.checkpoint(0)


def _reader_options(readers: PairInputReaders | None) -> tuple[dict, dict]:
    return ({}, {}) if readers is None else ({'reader': readers.older}, {'reader': readers.newer})


def _input_block(handle, *, held: bool) -> bytes:
    block = handle.read(1 << 20)
    if held and (type(block) is not bytes or len(block) > 1 << 20):
        raise InputReadError('invalid')
    return block


def _file_sha(path: str, *, reader: HeldInput | None = None) -> str:
    digest = hashlib.sha256()
    target = Path(path)
    try:
        if reader is not None:
            reader.check(target)
        with (open(path, 'rb') if reader is None else reader.open_reader(target)) as handle:
            for block in iter(lambda: _input_block(handle, held=reader is not None), b''):
                digest.update(block)
        if reader is not None:
            reader.check(target)
    except OSError as exc:
        raise KbcStoreError('PT-KBC-VERIFY', 'an input file cannot be read', details={'errno': exc.errno}) from exc
    return digest.hexdigest()


def _revision_of(body: dict) -> InvestigationRevision:
    return InvestigationRevision.model_validate_json(json.dumps(body['revision']))  # strict models parse JSON


class ProjectAttachment:
    """Two-phase, journalled attach of an investigation to a new project; ``attach`` and ``resume`` share one path."""

    def __init__(self, workspace: WorkspaceStore, project: ProjectPort, *,
                 input_readers: PairInputReaders | None = None):
        self.ws = workspace
        self.project = project
        self._input_readers = input_readers
        self.fault = workspace.fault
        self.clock = workspace.clock

    # -------------------------------------------------------------------------------------------- public

    def attach(self, request: AttachRequest,
               context: tuple[tuple[str, bytes], ...] = ()) -> OperationResult[ProjectLink]:
        """Attach; an already journalled identical request resumes instead of starting over (idempotent)."""
        try:
            op_id = self._op_id(request)
            if self.ws.journal_get(op_id) is None:
                self._begin(op_id, request)
            return self.resume(op_id, context)
        except KbcStoreError as exc:
            return OperationResult(status='error', issues=(exc.issue(),))

    def resume(self, op_id: str, context: tuple[tuple[str, bytes], ...] = ()) -> OperationResult[ProjectLink]:
        found = self.ws.journal_get(op_id)
        if found is None:
            return OperationResult(status='error', issues=(KbcIssue(
                code='PT-KBC-STATE', message='there is no such attach operation'),))
        state, body = found
        try:
            if state == 'done':
                if body['link_state'] == 'context-pending' and context:
                    body = self._attach_context(op_id, body, context)
                return self._result(body)
            if state == 'intent':
                body = self._create(op_id, body)
            body, failure = self._after_create(op_id, body, context)
            return self._result(body, failure)
        except KbcStoreError as exc:
            return OperationResult(status='error', issues=(exc.issue(),))

    # -------------------------------------------------------------------------------------------- phase one

    @staticmethod
    def _op_id(request: AttachRequest) -> str:
        r = request.revision
        return domain_id('kbc.attach', 1, {
            'inv': r.investigation_id, 'revision': r.revision, 'pair': request.pair_id, 'older': request.older_sha,
            'newer': request.newer_sha, 'directory': Path(request.directory).resolve().as_posix()})

    def _begin(self, op_id: str, request: AttachRequest) -> None:
        _check_input_readers(self._input_readers, request.older_path, request.newer_path)
        current = self.ws.current_revision(request.revision.investigation_id)
        if current is None or current.revision != request.revision.revision or current.state != 'BYTES_VERIFIED':
            raise KbcStoreError('PT-KBC-STALE', 'attach needs the current BYTES_VERIFIED revision')
        if request.selected_product is not None and (
                request.revision.lead.kind not in {'pair', 'file'} or
                request.selected_product.scope_id != request.revision.selected_scope_id):
            raise KbcStoreError('PT-KBC-INPUT', 'the captured product must match the product-only investigation')
        if request.older_sha == request.newer_sha:
            raise KbcStoreError('PT-KBC-VERIFY', 'the two sides are the same bytes')
        files = ((request.older_path, request.older_sha), (request.newer_path, request.newer_sha))
        for (path, sha), options in zip(files, _reader_options(self._input_readers), strict=True):
            if _file_sha(path, **options) != sha:
                raise KbcStoreError('PT-KBC-VERIFY', 'an input file does not match its verified SHA-256')
        directory = Path(request.directory)
        if not creation_directory_available(directory):
            raise KbcStoreError('PT-KBC-STORAGE', 'the project directory exists and is not empty')
        for sha in request.source_shas:
            self.ws.read_object(sha)  # fail before any side effect if a source object is damaged
        _check_input_readers(self._input_readers, request.older_path, request.newer_path)
        self.ws.journal_put(op_id, 'intent', {
            'state': 'intent', 'directory': directory.resolve().as_posix(), 'older_path': request.older_path,
            'newer_path': request.newer_path, 'older_sha': request.older_sha, 'newer_sha': request.newer_sha,
            'pair_id': request.pair_id, 'plan_sha': request.plan_sha, 'source_shas': list(request.source_shas),
            **({'selected_product': request.selected_product.model_dump(mode='json')}
               if request.selected_product is not None else {}),
            'revision': request.revision.model_dump(mode='json'), 'base': request.revision.revision,
            'cas_created': False, 'cas_final': False, 'project_id': None, 'project_revision': None,
            'link_state': None, 'interrupted': False})

    def _create(self, op_id: str, body: dict) -> dict:
        # Re-verify: a resume may run long after the intent was written.
        _check_input_readers(self._input_readers, body['older_path'], body['newer_path'])
        files = ((body['older_path'], body['older_sha']), (body['newer_path'], body['newer_sha']))
        for (path, sha), options in zip(files, _reader_options(self._input_readers), strict=True):
            if _file_sha(path, **options) != sha:
                raise KbcStoreError('PT-KBC-VERIFY', 'an input file changed since it was verified')
        _check_input_readers(self._input_readers, body['older_path'], body['newer_path'])
        try:
            made = self.project.create_project(body['older_path'], body['newer_path'], directory=body['directory'])
        except (KbcStoreError, InputReadError):
            raise
        except Exception as exc:
            raise KbcStoreError('PT-KBC-STORAGE', 'the project could not be created',
                                details={'cause': type(exc).__name__}) from exc
        for key, sha in (('older_sha256', body['older_sha']), ('newer_sha256', body['newer_sha'])):
            if made.get(key, sha) != sha:
                raise KbcStoreError('PT-KBC-VERIFY', 'the created project holds different bytes than verified')
        self.fault('after_project_create')
        body = {**body, 'state': 'created', 'project_id': str(made['project_id']),
                'project_revision': int(made['revision'])}
        self.ws.journal_put(op_id, 'created', body)
        return body

    # -------------------------------------------------------------------------------------------- phase two

    def _after_create(self, op_id: str, body: dict,
                      context: tuple[tuple[str, bytes], ...]) -> tuple[dict, KbcStoreError | None]:
        if not body['cas_created']:
            body = self._cas(op_id, body, 'project_created', both_sides=True, flag='cas_created')
        failure: KbcStoreError | None = None
        try:
            self._sidecars(body)
            self.fault('after_sidecar_write')
            self._rows(body, context)
        except KbcStoreError as exc:  # a failure after PROJECT_CREATED keeps the project: CONTEXT_PENDING
            failure = exc
        attached = failure is None and bool(context)
        link_state = 'attached' if attached else 'context-pending'
        body = self._cas(op_id, {**body, 'link_state': link_state}, 'context_attached' if attached
                         else 'context_pending', flag='cas_final', final=True)
        self._record(body, attached)
        return body, failure

    def _attach_context(self, op_id: str, body: dict, context: tuple[tuple[str, bytes], ...]) -> dict:
        """`kb attach --repair` with a rebuilt context: add the missing sidecars and rows to an already created
        project. The sidecars are written here too: a first attach can fail before them (issue #105 BUG-KBC-4)."""
        self._sidecars(body)
        self._rows(body, context)
        body = self._cas(op_id, {**body, 'link_state': 'attached'}, 'context_attached', flag='cas_final', final=True)
        self._record(body, True)
        return body

    def _record(self, body: dict, attached: bool) -> None:
        self.ws.append_attempt(body['revision']['investigation_id'], Attempt(
            op='attach', plan_sha=body['plan_sha'], stage='done' if attached else 'context-pending',
            result='ok' if attached else 'partial', created_at=self.clock.now_utc()))

    def _cas(self, op_id: str, body: dict, kind: str, *, flag: str, both_sides: bool = False,
             final: bool = False) -> dict:
        base = _revision_of(body)
        current = self.ws.current_revision(base.investigation_id)
        assert current is not None  # created by the caller before attach
        result = reduce(current, Event(kind, current.revision, both_sides=both_sides))
        if isinstance(result, KbcIssue):
            raise KbcStoreError(result.code, result.message)
        new_body = {**body, flag: True, **({'state': 'done'} if final else {})}
        if kind == 'project_created':  # sidecars, rows and the link name the revision the project was made from
            new_body['revision'] = result.model_dump(mode='json')
        self.ws.append_revision(result, expected_current=current.revision,
                                journal=(op_id, 'done' if final else 'created', new_body))
        return new_body

    def _confined(self, directory: Path, *parts: str) -> Path:
        path = directory.joinpath(*parts)
        probe = directory
        for part in parts[:-1]:
            probe = probe / part
            if probe.is_symlink():
                raise KbcStoreError('PT-KBC-STORAGE', 'a project sidecar directory is a symbolic link')
        if not path.resolve().is_relative_to(directory.resolve()):
            raise KbcStoreError('PT-KBC-STORAGE', 'a sidecar path escapes the project')
        return path

    def _sidecars(self, body: dict) -> None:
        try:
            self._write_sidecars(body)
        except OSError as exc:                      # disk full, permissions, a file in the way (issue #105 KBC-5)
            raise KbcStoreError('PT-KBC-STORAGE', 'a project sidecar could not be written',
                                details={'cause': type(exc).__name__}) from exc

    def _write_sidecars(self, body: dict) -> None:
        directory = Path(body['directory'])
        rev = _revision_of(body)
        budget = self.ws.limits.project_sources_bytes
        sources = directory / 'kb' / 'sources'
        used = sum(p.stat().st_size for p in sources.glob('*.json.gz')) if sources.is_dir() else 0
        by_sha = {s.sha256: s for s in self.ws.sources()}
        for sha in body['source_shas']:
            path = self._confined(directory, 'kb', 'sources', f'{sha}.json.gz')
            source = by_sha.get(sha)
            if source is None:
                raise KbcStoreError('PT-KBC-STATE', 'a source document is not in the workspace')
            envelope = {'contract': 'kbcorrelation/1', 'source': json.loads(_json(source)), 'encoding': 'base64',
                        'bytes': base64.b64encode(self.ws.read_object(sha)).decode('ascii')}
            data = _gz(json.dumps(envelope, sort_keys=True, separators=(',', ':')).encode())
            if not path.is_file():
                if used + len(data) > budget:
                    raise KbcStoreError('PT-KBC-LIMIT', 'the project source budget is exhausted')
                used += len(data)
            atomic_write(path, data)
        name = f'{rev.investigation_id}-{rev.revision}.json'
        path = self._confined(directory, 'kb', 'investigations', name)
        text = _json(rev).encode()
        if path.is_file() and path.read_bytes() != text:
            raise KbcStoreError('PT-KBC-STATE', 'an investigation sidecar already holds a different revision')
        atomic_write(path, text)

    def _rows(self, body: dict, context: tuple[tuple[str, bytes], ...]) -> None:
        rev = _revision_of(body)
        try:
            self.fault('attach_before_row')
            self.project.put_row(body['project_id'], 'kb-investigation', f'{rev.investigation_id}:{rev.revision}',
                                 _json(rev).encode())
            for key, data in context:
                self.fault('attach_before_row')
                self.project.put_row(body['project_id'], 'kb-context', key, data)
        except KbcStoreError:
            raise
        except Exception as exc:
            raise KbcStoreError('PT-KBC-STORAGE', 'a project row could not be written',
                                details={'cause': type(exc).__name__}) from exc

    @staticmethod
    def _result(body: dict, failure: KbcStoreError | None = None) -> OperationResult[ProjectLink]:
        rev = body['revision']
        state = body['link_state'] or 'context-pending'
        link = ProjectLink(project_id=body['project_id'], project_revision=body['project_revision'],
                           older_sha=body['older_sha'], newer_sha=body['newer_sha'],
                           investigation_id=rev['investigation_id'], revision=rev['revision'],
                           pair_id=body['pair_id'], state=state)
        if state == 'attached':
            return OperationResult(status='ok', value=link)
        return OperationResult(status='partial', value=link, issues=(failure.issue(),) if failure else (),
                               warnings=('CONTEXT_PENDING: the project exists; run `kb attach --repair` to add '
                                         'the documentary context',))
