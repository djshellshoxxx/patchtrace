"""Hostile-input guard around a Diaphora result database (SPEC-DA-01 "SQLite and external process safety").

The source is copied once into a private directory while hashing (no symlinks, regular file only, size cap),
then opened read-only with `query_only`, `trusted_schema=OFF`, an authorizer that allows only SELECT/READ of the
fixed tables, a progress-handler deadline and a cancel flag. No caller SQL is accepted: `fetch_rows` takes a table
and column names from fixed allowlists. `ATTACH` and extension loading are impossible by construction.
"""
from __future__ import annotations

import hashlib
import os
import shutil
import sqlite3
import stat
import tempfile
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from .contracts import DiaphoraError

MAX_DB_BYTES = 256 * 1024 * 1024
MAX_MATCH_ROWS = 500_000
MAX_UNMATCHED_ROWS = 200_000
DEADLINE_SECONDS = 60.0
HEADER = b'SQLite format 3\x00'
CHUNK = 1024 * 1024
# table -> columns read. A missing table or column is an explicit PT-DIAPHORA-DB error, never a guess.
SCHEMA = {
    'config': ('main_db', 'diff_db', 'version', 'date'),
    'results': ('type', 'line', 'address', 'name', 'address2', 'name2', 'ratio', 'nodes1', 'nodes2', 'description'),
    'unmatched': ('type', 'line', 'address', 'name'),
}
OPTIONAL_TABLES = frozenset({'config'})
_ALLOWED_FUNCTIONS = frozenset({'count', 'length', 'typeof'})


@dataclass(frozen=True)
class Snapshot:
    sha256: str
    size: int
    tables: dict[str, tuple[str, ...]]
    conn: sqlite3.Connection
    _deadline: list

    def count(self, table: str) -> int:
        _check(table, SCHEMA[table])
        self._deadline[0] = time.monotonic() + DEADLINE_SECONDS
        try:
            return self.conn.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0]
        except sqlite3.Error as exc:
            raise _db(exc) from None

    def rows(self, table: str, limit: int) -> Iterator[tuple]:
        """Fixed-shape rows in rowid order: (rowid, *SCHEMA[table]); at most `limit`."""
        _check(table, SCHEMA[table])
        columns = ', '.join(f'"{c}"' for c in SCHEMA[table])
        self._deadline[0] = time.monotonic() + DEADLINE_SECONDS
        try:
            cursor = self.conn.execute(f'SELECT rowid, {columns} FROM "{table}" ORDER BY rowid LIMIT ?', (limit,))
            for row in cursor:
                self._deadline[0] = time.monotonic() + DEADLINE_SECONDS
                yield row
        except sqlite3.Error as exc:
            raise _db(exc) from None


def _check(table: str, columns: tuple[str, ...]) -> None:
    if SCHEMA.get(table) != columns:
        raise DiaphoraError('PT-DIAPHORA-DB', 'internal: table access is limited to the fixed allowlist')


def _db(exc: BaseException) -> DiaphoraError:
    text = str(exc)
    if 'interrupted' in text:
        return DiaphoraError('PT-DIAPHORA-LIMIT', 'reading the result database exceeded its time budget or was cancelled')
    return DiaphoraError('PT-DIAPHORA-DB', 'the file is not a readable SQLite database of the expected shape')


def _authorizer(action, arg1, arg2, dbname, source):
    if action in (sqlite3.SQLITE_SELECT, sqlite3.SQLITE_READ):
        return sqlite3.SQLITE_OK
    if action == sqlite3.SQLITE_FUNCTION and arg2 in _ALLOWED_FUNCTIONS:
        return sqlite3.SQLITE_OK
    return sqlite3.SQLITE_DENY


def _copy_private(path: Path, target: Path, cancel: threading.Event | None) -> tuple[str, int]:
    try:
        before = os.lstat(path)
        if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
            raise DiaphoraError('PT-DIAPHORA-INPUT', 'the result must be a regular file, not a link')
        if before.st_size > MAX_DB_BYTES:
            raise DiaphoraError('PT-DIAPHORA-LIMIT', f'the result database exceeds {MAX_DB_BYTES >> 20} MiB')
        flags = os.O_RDONLY | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NOFOLLOW', 0)
        digest, total = hashlib.sha256(), 0
        with os.fdopen(os.open(path, flags), 'rb') as src, open(target, 'xb') as dst:
            first = True
            while True:
                if cancel is not None and cancel.is_set():
                    raise DiaphoraError('PT-DIAPHORA-CANCEL', 'import cancelled')
                chunk = src.read(CHUNK)
                if not chunk:
                    break
                if first and not chunk.startswith(HEADER):
                    raise DiaphoraError('PT-DIAPHORA-DB', 'the file is not a SQLite database')
                first = False
                total += len(chunk)
                if total > MAX_DB_BYTES:
                    raise DiaphoraError('PT-DIAPHORA-LIMIT', f'the result database exceeds {MAX_DB_BYTES >> 20} MiB')
                digest.update(chunk)
                dst.write(chunk)
        if first:
            raise DiaphoraError('PT-DIAPHORA-DB', 'the file is not a SQLite database')
        return digest.hexdigest(), total
    except OSError as exc:
        raise DiaphoraError('PT-DIAPHORA-INPUT', f'cannot read the result ({exc.strerror or "I/O error"})') from None


@contextmanager
def open_snapshot(path: Path, cancel: threading.Event | None = None) -> Iterator[Snapshot]:
    """Hash and copy `path` to a private directory, validate it, and yield a locked-down read-only connection."""
    private = Path(tempfile.mkdtemp(prefix='patchtrace-diaphora-'))
    conn = None
    try:
        copy = private / 'result.sqlite'
        digest, size = _copy_private(Path(path), copy, cancel)
        deadline = [time.monotonic() + DEADLINE_SECONDS]

        def progress():
            return 1 if (time.monotonic() > deadline[0] or (cancel is not None and cancel.is_set())) else 0

        try:
            conn = sqlite3.connect(f'{copy.as_uri()}?mode=ro&immutable=1', uri=True, isolation_level=None)
            conn.set_progress_handler(progress, 10_000)
            conn.execute('PRAGMA query_only=ON')
            conn.execute('PRAGMA trusted_schema=OFF')
            if conn.execute('PRAGMA quick_check(1)').fetchone() != ('ok',):
                raise DiaphoraError('PT-DIAPHORA-DB', 'the SQLite integrity check failed')
            tables = {}
            for name in SCHEMA:
                info = conn.execute(f'PRAGMA table_info("{name}")').fetchall()
                if info:
                    tables[name] = tuple(row[1] for row in info)
            conn.set_authorizer(_authorizer)
        except sqlite3.Error as exc:
            raise _db(exc) from None
        for name, columns in SCHEMA.items():
            if name not in tables:
                if name in OPTIONAL_TABLES:
                    continue
                raise DiaphoraError('PT-DIAPHORA-DB', f'table {name!r} is missing')
            missing = [c for c in columns if c not in tables[name]]
            if missing:
                raise DiaphoraError('PT-DIAPHORA-DB', f'table {name!r} lacks column(s) {", ".join(missing)}')
        yield Snapshot(digest, size, tables, conn, deadline)
    finally:
        if conn is not None:
            conn.close()
        shutil.rmtree(private, ignore_errors=True)
