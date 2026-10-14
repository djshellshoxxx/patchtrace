"""`program-ir/1` sidecar: DDL, code tables, hardened read-only open, canonical JSON and the content digest.

The digest (02 s3, 03 s12.5) is computed from the rows, never from the file bytes (SQLite and zlib output are not
deterministic across builds); blobs enter it as the SHA-256 of their DECOMPRESSED payload.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import zlib
from collections.abc import Iterator
from pathlib import Path

from ..limits import UnifiedError

CONTRACT = 'program-ir/1'
INGEST_VERSION = 'ir-ingest/1'
NORM_VERSION = 'norm/1'
INS_VERSION = 'ins/1'
DB_NAME = 'ir.sqlite3'
MANIFEST_NAME = 'manifest.json'
TABLES = ('mnem', 'fn', 'bb', 'call', 'str', 'cst', 'ref', 'ins')   # digest order (meta is excluded)
MAX_BLOB = 64 * 1024 * 1024                                          # decompressed `ins` blob cap

KIND_CODES = {'normal': 0, 'thunk': 1, 'external': 2}
NAME_SRC_CODES = {'DEFAULT': 0, 'ANALYSIS': 1, 'IMPORTED': 2, 'USER_DEFINED': 3, 'AI': 4}
FN_FLAGS = {'tiny': 1, 'thunk': 2, 'import': 4, 'oversize': 8, 'truncated': 16, 'pdata-confirmed': 32,
            'library': 64, 'mask-missing': 128, 'mask-unlocated': 256}
EDGE_KIND_CODES = {'fall': 0, 'jump': 1, 'cond': 2, 'switch': 3, 'call-return': 4}
CALL_KIND_CODES = {'call': 0, 'jump': 1}
REF_KIND_CODES = {'code': 0, 'data': 1, 'import': 2, 'stack': 3}

DDL = (
    'CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)',
    'CREATE TABLE mnem (id INTEGER PRIMARY KEY, text TEXT NOT NULL UNIQUE)',
    '''CREATE TABLE fn (fid INTEGER PRIMARY KEY, rva INTEGER NOT NULL UNIQUE, size INTEGER NOT NULL,
  kind INTEGER NOT NULL, name TEXT, name_src INTEGER NOT NULL, aliases TEXT, import_key TEXT, thunk_target INTEGER,
  n_bb INTEGER NOT NULL, n_edge INTEGER NOT NULL, n_insn INTEGER NOT NULL, n_call INTEGER NOT NULL,
  loops INTEGER NOT NULL, h0 INTEGER, h1 INTEGER, h2 INTEGER, h3 INTEGER, hm INTEGER, hms INTEGER,
  md_td INTEGER, md_bu INTEGER, extent_src INTEGER NOT NULL, flags INTEGER NOT NULL, eh TEXT)''',
    '''CREATE TABLE bb (fid INTEGER NOT NULL, ord INTEGER NOT NULL, rva INTEGER NOT NULL, size INTEGER NOT NULL,
  n_insn INTEGER NOT NULL, h1 INTEGER, hms INTEGER, succ TEXT NOT NULL, PRIMARY KEY (fid, ord))''',
    '''CREATE TABLE call (fid INTEGER NOT NULL, site INTEGER NOT NULL, callee INTEGER, import_key TEXT,
  kind INTEGER NOT NULL)''',
    'CREATE TABLE str (fid INTEGER NOT NULL, site INTEGER NOT NULL, sha TEXT NOT NULL, len INTEGER NOT NULL, prefix TEXT)',
    'CREATE TABLE cst (fid INTEGER NOT NULL, site INTEGER NOT NULL, value INTEGER NOT NULL, ctx INTEGER NOT NULL)',
    '''CREATE TABLE ref (fid INTEGER NOT NULL, ord INTEGER NOT NULL, opi INTEGER NOT NULL, kind INTEGER NOT NULL,
  target INTEGER, import_key TEXT, PRIMARY KEY (fid, ord, opi, kind, target))''',
    'CREATE TABLE ins (fid INTEGER PRIMARY KEY, blob BLOB NOT NULL, txt BLOB)',
    'CREATE INDEX call_fid ON call (fid)',
    'CREATE INDEX str_fid ON str (fid)',
    'CREATE INDEX cst_fid ON cst (fid)',
)
COLUMNS = {
    'mnem': ('id', 'text'),
    'fn': ('fid', 'rva', 'size', 'kind', 'name', 'name_src', 'aliases', 'import_key', 'thunk_target', 'n_bb',
           'n_edge', 'n_insn', 'n_call', 'loops', 'h0', 'h1', 'h2', 'h3', 'hm', 'hms', 'md_td', 'md_bu', 'extent_src',
           'flags', 'eh'),
    'bb': ('fid', 'ord', 'rva', 'size', 'n_insn', 'h1', 'hms', 'succ'),
    'call': ('fid', 'site', 'callee', 'import_key', 'kind'),
    'str': ('fid', 'site', 'sha', 'len', 'prefix'),
    'cst': ('fid', 'site', 'value', 'ctx'),
    'ref': ('fid', 'ord', 'opi', 'kind', 'target', 'import_key'),
    'ins': ('fid', 'blob', 'txt'),
}
_ORDER = {
    'mnem': 'id', 'fn': 'fid', 'bb': 'fid, ord', 'call': 'fid, site, kind, callee, import_key',
    'str': 'fid, site, sha, len, prefix', 'cst': 'fid, site, value, ctx',
    'ref': 'fid, ord, opi, kind, target, import_key', 'ins': 'fid',
}
_READABLE = frozenset((*TABLES, 'meta', 'sqlite_master', 'sqlite_schema', 'sqlite_temp_master'))
_FUNCTIONS = frozenset({'count', 'min', 'max', 'length'})


def error(message: str, reason: str, code: str = 'PT-UNIFIED-IR') -> UnifiedError:
    return UnifiedError(code, message, reason=reason)


def canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False)


def compress(payload: bytes) -> bytes:
    return zlib.compress(payload, 6)


def decompress(blob: bytes, limit: int = MAX_BLOB) -> bytes:
    """zlib-bomb safe: more than `limit` decompressed bytes is an error, never a huge allocation."""
    decoder = zlib.decompressobj()
    try:
        data = decoder.decompress(blob, limit + 1)
        data += decoder.flush()
    except zlib.error:
        raise error('An IR blob is not valid zlib data', 'blob-invalid', 'PT-UNIFIED-STORE') from None
    if len(data) > limit or decoder.unconsumed_tail:
        raise error('An IR blob exceeds the decompression cap', 'blob-too-large', 'PT-UNIFIED-LIMIT')
    return data


# --- writer ---------------------------------------------------------------------------------------------------------

def create_database(path: Path) -> sqlite3.Connection:
    """A fresh writer database in a private directory we own (no journal, no fsync: the file is rebuilt on failure)."""
    connection = sqlite3.connect(str(path), isolation_level=None)
    connection.execute('PRAGMA journal_mode=OFF')
    connection.execute('PRAGMA synchronous=OFF')
    connection.execute('PRAGMA temp_store=MEMORY')
    connection.execute('PRAGMA trusted_schema=OFF')
    for statement in DDL:
        connection.execute(statement)
    return connection


# --- hardened reader (pattern of the .BinDiff importer, secondary/bindiff.py) ---------------------------------------

def _authorizer(action: int, arg1, arg2, dbname, source) -> int:
    if action == sqlite3.SQLITE_SELECT:
        return sqlite3.SQLITE_OK
    if action == sqlite3.SQLITE_READ and isinstance(arg1, str) and arg1.lower() in _READABLE:
        return sqlite3.SQLITE_OK
    if action == sqlite3.SQLITE_FUNCTION and isinstance(arg2, str) and arg2.lower() in _FUNCTIONS:
        return sqlite3.SQLITE_OK
    if action == sqlite3.SQLITE_PRAGMA and arg1 == 'table_info' and isinstance(arg2, str) and arg2 in _READABLE:
        return sqlite3.SQLITE_OK
    return sqlite3.SQLITE_DENY


def open_readonly(path: Path) -> sqlite3.Connection:
    """Read-only, immutable, `trusted_schema=OFF`, SELECT/READ authorizer on the IR tables only."""
    path = Path(path)
    try:
        size = path.stat().st_size
        with path.open('rb') as handle:
            magic = handle.read(16)
    except OSError:
        raise error('The IR database is unreadable', 'ir-unreadable', 'PT-UNIFIED-STORE') from None
    if magic != b'SQLite format 3\x00':
        raise error('The IR file is not a SQLite database', 'ir-not-sqlite', 'PT-UNIFIED-STORE')
    try:
        db = sqlite3.connect(f'{path.resolve().as_uri()}?mode=ro&immutable=1', uri=True)
        db.execute('PRAGMA trusted_schema=OFF')
        db.execute('PRAGMA query_only=1')
        db.execute('PRAGMA cell_size_check=ON')
        page_size = db.execute('PRAGMA page_size').fetchone()[0]
        db.execute(f'PRAGMA max_page_count={max(1, -(-size // page_size))}')
        if hasattr(db, 'setconfig') and hasattr(sqlite3, 'SQLITE_DBCONFIG_DEFENSIVE'):
            db.setconfig(sqlite3.SQLITE_DBCONFIG_DEFENSIVE, True)
        tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if not {'meta', *TABLES} <= tables:
            db.close()
            raise error('The IR database lacks required tables', 'ir-schema', 'PT-UNIFIED-STORE')
        db.set_authorizer(_authorizer)
    except sqlite3.Error:
        raise error('The IR database cannot be opened read-only', 'ir-open', 'PT-UNIFIED-STORE') from None
    return db


# --- digest ---------------------------------------------------------------------------------------------------------

def table_rows(connection: sqlite3.Connection, table: str) -> Iterator[list]:
    """Rows of a table in key order as lists; blobs are replaced by the SHA-256 of their decompressed payload."""
    columns = ', '.join(COLUMNS[table])
    for row in connection.execute(f'SELECT {columns} FROM {table} ORDER BY {_ORDER[table]}'):
        if table == 'ins':
            yield [row[0], hashlib.sha256(decompress(row[1])).hexdigest(),
                   None if row[2] is None else hashlib.sha256(decompress(row[2])).hexdigest()]
        else:
            yield list(row)


def table_digest(connection: sqlite3.Connection, table: str) -> str:
    digest = hashlib.sha256()
    for row in table_rows(connection, table):
        digest.update(canonical_json(row).encode('utf-8'))
        digest.update(b'\n')
    return digest.hexdigest()


def content_digest(connection: sqlite3.Connection) -> str:
    """SHA-256 of the canonical JSON of the per-table digests (meta excluded; 03 s12.5)."""
    tables = {table: table_digest(connection, table) for table in TABLES}
    return hashlib.sha256(canonical_json({'contract': CONTRACT, 'tables': tables}).encode('utf-8')).hexdigest()
