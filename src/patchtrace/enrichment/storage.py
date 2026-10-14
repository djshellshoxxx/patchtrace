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
from collections.abc import Callable, Collection, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from ..persistence import ProjectStore, safe_path
from .contracts import EnrichmentError

# Highest extension version this client understands. New stores are stamped BASE_EXTENSION_VERSION and
# are raised to 2 only when a v2-only row (`engine-run`, `secondary/2` sets) is first written, so a v1
# client keeps full access to every project that never used SPEC-28 and reads older stores unchanged.
EXTENSION_VERSION = 2
BASE_EXTENSION_VERSION = 1
RUN_KIND = 'engine-run'
RUN_KEEP = 8  # newest engine-run rows kept per (engine, older, newer) group
MAX_ROW = 32 * 1024 * 1024
MAX_TOTAL = 128 * 1024 * 1024
KINDS = frozenset({'signals', 'ranking', 'wil', 'cve-snapshot', 'contextual', 'pipeline', 'secondary-matches',
                   'engine-run'})

# Retention (SPEC-07h H1). Only recomputable derived kinds are ever deleted; imported evidence
# (`secondary-matches`), `cve-snapshot` and unknown kinds are never evicted.
DERIVED_KINDS = ('signals', 'ranking', 'wil', 'contextual', 'pipeline')
KEEP_CURRENT = 8
KEEP_STALE = 2
ORPHAN_GRACE = timedelta(minutes=5)
_RETENTION_META_SQL = "INSERT OR IGNORE INTO enrichment_meta(key, value) VALUES('retention_version', '1')"


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

    def _backup_before_create(self, label: str = 'enrichment') -> None:
        directory = safe_path(self.store.root, 'backups')
        directory.mkdir(exist_ok=True)
        stamp = datetime.now(UTC).strftime('%Y%m%dT%H%M%S%fZ')
        target = safe_path(self.store.root, f'backups/project-pre-{label}-{stamp}.sqlite3')
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
            raise EnrichmentError('PT-ENRICH-INPUT', f'pre-{label} database backup failed verification')

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
                 (str(BASE_EXTENSION_VERSION),)),
            ])
        row = self._db.execute("SELECT value FROM enrichment_meta WHERE key='extension_version'").fetchone()
        version = int(row[0]) if row and row[0].isdigit() else 0
        if version < 1:
            raise EnrichmentError('PT-ENRICH-INPUT', 'enrichment metadata is malformed')
        # A newer client's rows are kept verbatim; this client only reads its own kinds.
        self.read_only = version > EXTENSION_VERSION
        self._ready = True

    def publish(self, kind: str, guard: Guard, current: Guard, revision: int, status: str,
                body: dict, entry_id: str, protect: Collection[str] = ()) -> Entry:
        """Store a result; `current` is the guard recomputed from the live project right now.
        `protect` lists the row ids of the generation being written; the cap fallback never evicts them."""
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
            self.make_room(used + size - MAX_TOTAL, current, {entry_id, *protect})
            used = self._db.execute('SELECT COALESCE(SUM(LENGTH(CAST(body AS BLOB))),0) FROM enrichment_entries '
                                    'WHERE id != ?', (entry_id,)).fetchone()[0]
            if used + size > MAX_TOTAL:
                raise EnrichmentError('PT-ENRICH-LIMIT', 'project enrichment data would exceed 128 MiB',
                                      recoverable=True)
        stale = guard != current
        created = datetime.now(UTC).isoformat()
        v2_only = kind == RUN_KIND or (isinstance(body, dict) and body.get('contract') == 'secondary/2')
        with self._db:
            if v2_only:  # additive stamp in the same transaction as the first v2-only row
                self._db.execute("UPDATE enrichment_meta SET value='2' WHERE key='extension_version' "
                                 "AND CAST(value AS INTEGER) < 2")
            self._db.execute(
                'INSERT INTO enrichment_entries(id,kind,project_id,project_revision,run_id,raw_sha256,input_digest,'
                'status,stale,created,body,body_sha256) VALUES(?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET '
                'project_revision=excluded.project_revision,status=excluded.status,stale=excluded.stale,'
                'created=excluded.created,body=excluded.body,body_sha256=excluded.body_sha256',
                (entry_id, kind, guard.project_id, revision, guard.run_id, guard.raw_sha256, guard.input_digest,
                 status, int(stale), created, text, hashlib.sha256(text.encode()).hexdigest()))
        return Entry(entry_id, kind, guard, revision, status, stale, created, body)

    def entries(self, kind: str, current: Guard | None = None,
                on_corrupt: Callable[[str], None] | None = None) -> list[Entry]:
        """All rows of a kind, newest first; staleness is evaluated against `current` when given.
        A row failing its integrity hash raises, unless `on_corrupt` is given: it is then skipped and
        reported by id so one bad row cannot hide the others."""
        if 'enrichment_entries' not in self._tables():
            return []
        rows = self._db.execute(
            'SELECT id,kind,project_id,project_revision,run_id,raw_sha256,input_digest,status,stale,created,body,'
            'body_sha256 FROM enrichment_entries WHERE kind=? ORDER BY created DESC, id', (kind,)).fetchall()
        out = []
        for row in rows:
            if hashlib.sha256(row[10].encode()).hexdigest() != row[11]:
                if on_corrupt is not None:
                    on_corrupt(row[0])
                    continue
                raise EnrichmentError('PT-ENRICH-INPUT', 'stored enrichment row failed its integrity hash')
            guard = Guard(row[2], row[4], row[5], row[6])
            stale = bool(row[8]) or (current is not None and guard != current)
            out.append(Entry(row[0], row[1], guard, row[3], row[7], stale, row[9], json.loads(row[10])))
        return out

    def current(self, kind: str, guard: Guard) -> Entry | None:
        return next((e for e in self.entries(kind, guard) if not e.stale), None)

    # --- retention (SPEC-07h H1) -------------------------------------------------

    @staticmethod
    def _refs(entry: Entry) -> set[str]:
        """Row ids of one generation: the pipeline row plus the rows its body references."""
        stage_ids = entry.body.get('stage_ids') if isinstance(entry.body, dict) else None
        refs = {entry.id}
        if isinstance(stage_ids, dict):
            rid = stage_ids.get('ranking')
            for kind, key in (('signals', rid), ('ranking', rid), ('wil', stage_ids.get('wil')),
                              ('contextual', stage_ids.get('contextual'))):
                if isinstance(key, str) and key:
                    refs.add(f'{kind}:{key}')
        return refs

    def _derived_rows(self) -> dict[str, tuple[str, int]]:
        marks = ','.join('?' * len(DERIVED_KINDS))
        rows = self._db.execute(
            f'SELECT id, created, LENGTH(CAST(body AS BLOB)) FROM enrichment_entries WHERE kind IN ({marks})',
            DERIVED_KINDS).fetchall()
        return {r[0]: (r[1], r[2]) for r in rows}

    def _generations(self, current: Guard) -> tuple[list[Entry], list[Entry]]:
        """(current generations, stale generations), each newest first."""
        pipes = self.entries('pipeline')
        live = [p for p in pipes if not p.stale and p.guard == current]
        return live, [p for p in pipes if p not in live]

    def _retained(self, live: list[Entry], stale: list[Entry]) -> list[Entry]:
        kept_stale: list[Entry] = []
        per_config: dict[object, int] = {}
        for p in stale:
            digest = p.body.get('config_digest') if isinstance(p.body, dict) else None
            if per_config.get(digest, 0) < KEEP_STALE:
                per_config[digest] = per_config.get(digest, 0) + 1
                kept_stale.append(p)
        keep = live[:KEEP_CURRENT]
        # The newest live default-profile generation is what `load_default` serves: never evicted.
        default = next((p for p in live if p.body.get('default_profile') is True), None)
        if default is not None and default not in keep:
            keep.append(default)
        return keep + kept_stale

    def _orphans(self, rows: dict[str, tuple[str, int]], pipes: Iterable[Entry], older_than: str) -> set[str]:
        referenced = {i for p in pipes for i in self._refs(p)}
        return {i for i, (created, _) in rows.items() if i not in referenced and created < older_than}

    def _has_retention_backup(self) -> bool:
        directory = safe_path(self.store.root, 'backups')
        return directory.exists() and any(directory.glob('project-pre-retention-*.sqlite3'))

    def _delete(self, ids: Collection[str], kinds: tuple[str, ...] = DERIVED_KINDS) -> int:
        """Delete rows and record `retention_version` in one transaction, after a verified backup."""
        ids = sorted(ids)
        if not ids:
            return 0
        if not self._has_retention_backup():
            self._backup_before_create('retention')
        db = self._db
        marks = ','.join('?' * len(kinds))
        db.execute('BEGIN IMMEDIATE')
        try:
            for start in range(0, len(ids), 400):
                chunk = ids[start:start + 400]
                db.execute(f'DELETE FROM enrichment_entries WHERE id IN ({",".join("?" * len(chunk))}) '
                           f'AND kind IN ({marks})', (*chunk, *kinds))
            db.execute(_RETENTION_META_SQL)
        except BaseException:
            db.execute('ROLLBACK')
            raise
        db.execute('COMMIT')
        return len(ids)

    def _run_rows(self) -> list[tuple[str, str, int, tuple, bool]]:
        """(id, created, size, group, referenced) for every engine-run row, newest first. A run is
        referenced when a stored secondary set names it (`run_id`) or it names a stored set."""
        rows = self._db.execute(
            'SELECT id, created, LENGTH(CAST(body AS BLOB)), body FROM enrichment_entries WHERE kind=? '
            'ORDER BY created DESC, id DESC', (RUN_KIND,)).fetchall()
        sets = {r[0] for r in self._db.execute('SELECT id FROM enrichment_entries WHERE kind=?',
                                               ('secondary-matches',))}
        named = set()
        for (body,) in self._db.execute('SELECT body FROM enrichment_entries WHERE kind=?', ('secondary-matches',)):
            try:
                run_id = json.loads(body).get('run_id')
            except ValueError:
                continue
            if isinstance(run_id, str):
                named.add(run_id)
        out = []
        for row_id, created, size, body in rows:
            try:
                doc = json.loads(body)
                group = (doc.get('engine'), doc.get('older_sha256'), doc.get('newer_sha256'))
                referenced = row_id in named or doc.get('match_set_id') in sets
            except (ValueError, AttributeError):
                group, referenced = (None, None, None), False
            out.append((row_id, created, size, group, referenced))
        return out

    def _evictable_runs(self, keep: int) -> list[tuple[str, int]]:
        """(id, size) of engine-run rows beyond the newest `keep` per group, oldest first; rows tied to a
        stored secondary set are never offered."""
        seen: dict[tuple, int] = {}
        doomed = []
        for row_id, _created, size, group, referenced in self._run_rows():
            seen[group] = seen.get(group, 0) + 1
            if seen[group] > keep and not referenced:
                doomed.append((row_id, size))
        return doomed[::-1]

    def prune_runs(self, keep: int | None = None) -> int:
        """Best-effort: delete engine-run history beyond the newest RUN_KEEP per (engine, pair). Imported
        `secondary-matches` rows are never touched. Returns the number of rows deleted."""
        try:
            self.ensure()
            if self.read_only:
                return 0
            return self._delete([i for i, _ in self._evictable_runs(RUN_KEEP if keep is None else keep)],
                                (RUN_KIND,))
        except (EnrichmentError, sqlite3.Error):
            return 0

    def apply_retention(self, current: Guard, protect: Collection[str] = (), started: str | None = None) -> int:
        """Best-effort garbage collection after a publish; returns the number of rows deleted.

        Keeps the newest KEEP_CURRENT current generations and KEEP_STALE stale generations per
        `config_digest`; shared `wil`/`contextual` rows are reference counted through the retained
        pipeline rows. Orphans (no pipeline row references them) are deleted only when created
        before `started`. Never touches a read-only (newer extension) store, `secondary-matches`,
        `cve-snapshot` or unknown kinds. Any failure rolls back and leaves every row in place."""
        try:
            self.ensure()
            if self.read_only:
                return 0
            rows = self._derived_rows()
            live, stale = self._generations(current)
            keep_ids = {i for p in self._retained(live, stale) for i in self._refs(p)} | set(protect)
            pipes = live + stale
            referenced = {i for p in pipes for i in self._refs(p)}
            orphans = self._orphans(rows, pipes, started) if started else set()
            doomed = {i for i in rows if i not in keep_ids and (i in referenced or i in orphans)}
            return self._delete(doomed)
        except (EnrichmentError, sqlite3.Error):
            return 0

    def make_room(self, need_bytes: int, current: Guard, protect: Collection[str] = ()) -> int:
        """Cap fallback: free at least `need_bytes` by deleting stale generations (oldest first), then
        current generations beyond the newest one per `config_digest`. Never touches `protect` or the
        newest live default-profile generation. Nothing is deleted unless the need can be met;
        otherwise raises the recoverable PT-ENRICH-LIMIT."""
        mib = 1024 * 1024

        def limit(freed: int) -> EnrichmentError:
            return EnrichmentError(
                'PT-ENRICH-LIMIT', f'project enrichment data would exceed 128 MiB '
                f'({freed // mib} MiB freed, {max(need_bytes - freed, 0) // mib + 1} MiB still needed)',
                recoverable=True)
        if self.read_only:
            raise limit(0)
        try:
            rows = self._derived_rows()
            live, stale = self._generations(current)
            pipes = live + stale
            newest_default = next((p for p in live if p.body.get('default_profile') is True), None)
            protected = set(protect) | (self._refs(newest_default) if newest_default else set())
            seen: set[object] = set()
            newest_per_config: set[str] = set()
            for p in live:  # newest first: the first live generation of each config stays
                if p.body.get('config_digest') not in seen:
                    seen.add(p.body.get('config_digest'))
                    newest_per_config.add(p.id)
            order = list(reversed(stale)) + [p for p in reversed(live) if p.id not in newest_per_config]
            cutoff = (datetime.now(UTC) - ORPHAN_GRACE).isoformat()
            doomed = self._orphans(rows, pipes, cutoff) - protected
            freed = sum(rows[i][1] for i in doomed)
            runs: set[str] = set()
            for row_id, size in self._evictable_runs(1):  # run history is cheap to lose; sets are never offered
                if freed >= need_bytes:
                    break
                runs.add(row_id)
                freed += size
            remaining = list(pipes)
            for gen in order:
                if freed >= need_bytes:
                    break
                if gen.id in protected:
                    continue
                remaining = [p for p in remaining if p.id != gen.id]
                still = {i for p in remaining for i in self._refs(p)} | protected
                for row_id in self._refs(gen):
                    if row_id not in still and row_id in rows and row_id not in doomed:
                        doomed.add(row_id)
                        freed += rows[row_id][1]
            if freed < need_bytes:
                raise limit(0)
            self._delete(doomed | runs, (*DERIVED_KINDS, RUN_KIND))
            return freed
        except sqlite3.Error as exc:
            raise EnrichmentError('PT-ENRICH-LIMIT', 'project enrichment data would exceed 128 MiB '
                                  f'(retention failed: {exc.__class__.__name__})', recoverable=True) from None
