"""Additive enrichment tables in project.sqlite3 (SPEC-07 §10).

`user_version` stays 1: v1 code only reads `current_snapshot`/`history`, so extra
tables are invisible to it (covered by tests that open/save/backup with them present).
Before the tables are first created, a SQLite backup of the database is written
inside the case and verified, so the pre-extension state is recoverable.

Thread ownership: every method uses the ProjectStore connection and must run on
the thread that created it (the service/GUI owner thread). Workers compute results
and hand immutable bodies to `publish`, which rechecks currency immediately before
the commit; a result whose guard no longer matches is stored as stale, never current.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime

from ..persistence import ProjectStore, safe_path
from .contracts import EnrichmentError

EXTENSION_VERSION = 1
MAX_ROW = 32 * 1024 * 1024
MAX_TOTAL = 128 * 1024 * 1024
KINDS = frozenset({'signals', 'ranking', 'wil', 'cve-snapshot', 'contextual', 'pipeline', 'secondary-matches'})


@dataclass(frozen=True)
class Guard:
    """What a derived result was computed from; all must still hold at publication."""
    project_id: str
    run_id: str
    raw_sha256: str
    input_digest: str


@dataclass(frozen=True)
class Entry:
    id: str
    kind: str
    guard: Guard
    project_revision: int
    status: str
    stale: bool
    created: str
    body: dict


class EnrichmentStore:
    def __init__(self, store: ProjectStore):
        self.store = store
        self.read_only = False
        self._ready = False

    @property
    def _db(self) -> sqlite3.Connection:
        self.store._check_open()
        return self.store.connection

    def _ddl_transaction(self, statements: list[tuple[str, tuple]]) -> None:
        """Run schema changes atomically. The legacy sqlite3 isolation mode does not
        begin a transaction before DDL, so `with connection:` alone would autocommit
        each CREATE and a mid-way failure would leave a partial schema."""
        db = self._db
        db.execute('BEGIN IMMEDIATE')
        try:
            for sql, args in statements:
                db.execute(sql, args)
        except BaseException:
            db.execute('ROLLBACK')
            raise
        db.execute('COMMIT')

    def _tables(self) -> set[str]:
        return {row[0] for row in self._db.execute("SELECT name FROM sqlite_master WHERE type='table'")}

    def _backup_before_create(self) -> None:
        directory = safe_path(self.store.root, 'backups')
        directory.mkdir(exist_ok=True)
        stamp = datetime.now(UTC).strftime('%Y%m%dT%H%M%S%fZ')
        target = safe_path(self.store.root, f'backups/project-pre-enrichment-{stamp}.sqlite3')
        expected = self._db.execute('SELECT sha256 FROM current_snapshot WHERE singleton=1').fetchone()
        copy = sqlite3.connect(target)
        try:
            self._db.backup(copy)
            ok = copy.execute('PRAGMA quick_check').fetchone()[0] == 'ok'
            got = copy.execute('SELECT sha256 FROM current_snapshot WHERE singleton=1').fetchone()
        finally:
            copy.close()
        if not ok or got != expected:
            target.unlink(missing_ok=True)
            raise EnrichmentError('PT-ENRICH-INPUT', 'pre-extension database backup failed verification')

    def ensure(self) -> None:
        """Create tables on first use; detect newer extension versions (read-only)."""
        if self._ready:
            return
        tables = self._tables()
        if 'enrichment_meta' not in tables:
            self._backup_before_create()
            self._ddl_transaction([
                ('CREATE TABLE enrichment_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)', ()),
                ('CREATE TABLE enrichment_entries (id TEXT PRIMARY KEY, kind TEXT NOT NULL, '
                 'project_id TEXT NOT NULL, project_revision INTEGER NOT NULL, run_id TEXT NOT NULL, '
                 'raw_sha256 TEXT NOT NULL, input_digest TEXT NOT NULL, status TEXT NOT NULL, '
                 'stale INTEGER NOT NULL CHECK(stale IN (0,1)), created TEXT NOT NULL, body TEXT NOT NULL, '
                 'body_sha256 TEXT NOT NULL)', ()),
                ('CREATE INDEX enrichment_entries_lookup ON enrichment_entries(kind, run_id)', ()),
                ("INSERT INTO enrichment_meta(key, value) VALUES('extension_version', ?)",
                 (str(EXTENSION_VERSION),)),
            ])
        row = self._db.execute("SELECT value FROM enrichment_meta WHERE key='extension_version'").fetchone()
        version = int(row[0]) if row and row[0].isdigit() else 0
        if version < 1:
            raise EnrichmentError('PT-ENRICH-INPUT', 'enrichment metadata is malformed')
        # A newer client's rows are kept verbatim; this client only reads its own kinds.
        self.read_only = version > EXTENSION_VERSION
        self._ready = True

    def publish(self, kind: str, guard: Guard, current: Guard, revision: int, status: str,
                body: dict, entry_id: str) -> Entry:
        """Store a result; `current` is the guard recomputed from the live project right now."""
        if kind not in KINDS:
            raise EnrichmentError('PT-ENRICH-INPUT', f'unknown enrichment kind {kind!r}')
        self.ensure()
        if self.read_only:
            raise EnrichmentError('PT-ENRICH-STALE', 'project enrichment data was written by a newer PatchTrace')
        text = json.dumps(body, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False)
        size = len(text.encode('utf-8'))
        if size > MAX_ROW:
            raise EnrichmentError('PT-ENRICH-LIMIT', 'enrichment result exceeds 32 MiB row limit')
        used = self._db.execute('SELECT COALESCE(SUM(LENGTH(CAST(body AS BLOB))),0) FROM enrichment_entries '
                                'WHERE id != ?', (entry_id,)).fetchone()[0]
        if used + size > MAX_TOTAL:
            raise EnrichmentError('PT-ENRICH-LIMIT', 'project enrichment data would exceed 128 MiB',
                                  recoverable=True)
        stale = guard != current
        created = datetime.now(UTC).isoformat()
        with self._db:
            self._db.execute(
                'INSERT INTO enrichment_entries(id,kind,project_id,project_revision,run_id,raw_sha256,input_digest,'
                'status,stale,created,body,body_sha256) VALUES(?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET '
                'project_revision=excluded.project_revision,status=excluded.status,stale=excluded.stale,'
                'created=excluded.created,body=excluded.body,body_sha256=excluded.body_sha256',
                (entry_id, kind, guard.project_id, revision, guard.run_id, guard.raw_sha256, guard.input_digest,
                 status, int(stale), created, text, hashlib.sha256(text.encode()).hexdigest()))
        return Entry(entry_id, kind, guard, revision, status, stale, created, body)

    def entries(self, kind: str, current: Guard | None = None) -> list[Entry]:
        """All rows of a kind, newest first; staleness is evaluated against `current` when given."""
        if 'enrichment_entries' not in self._tables():
            return []
        rows = self._db.execute(
            'SELECT id,kind,project_id,project_revision,run_id,raw_sha256,input_digest,status,stale,created,body,'
            'body_sha256 FROM enrichment_entries WHERE kind=? ORDER BY created DESC, id', (kind,)).fetchall()
        out = []
        for row in rows:
            if hashlib.sha256(row[10].encode()).hexdigest() != row[11]:
                raise EnrichmentError('PT-ENRICH-INPUT', 'stored enrichment row failed its integrity hash')
            guard = Guard(row[2], row[4], row[5], row[6])
            stale = bool(row[8]) or (current is not None and guard != current)
            out.append(Entry(row[0], row[1], guard, row[3], row[7], stale, row[9], json.loads(row[10])))
        return out

    def current(self, kind: str, guard: Guard) -> Entry | None:
        return next((e for e in self.entries(kind, guard) if not e.stale), None)
