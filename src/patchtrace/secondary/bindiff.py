"""Read-only `.BinDiff` (SQLite) validator and importer (SPEC-10 §2-3, hardened per SPEC-29 §7.2).

The database is untrusted input: it is opened through a read-only, immutable URI so
neither a journal nor a WAL file is created next to it, and every structural property
the importer relies on is checked before any row is turned into a record. Callers that
run BinDiff pass a private preserved copy (immutable is only safe if nothing can change
the file), and only after BinDiff exited cleanly: a killed run can leave a valid-looking
file with an empty `function` table (SPEC-29 §4.4). Layers: `trusted_schema=OFF`,
`query_only`, defensive mode, `cell_size_check=ON`, `max_page_count` capped at the file's
own page count, a progress-handler deadline (`PT-SECONDARY-LIMIT`), an authorizer that
allows only SELECT/READ of the fixed tables, and rejection of any trigger, view or virtual
table in `sqlite_master` (a view named like a required table is never read).
"""
from __future__ import annotations

import hashlib
import os
import sqlite3
import tempfile
import time
from pathlib import Path

from .bindiff_inputs import copy_and_hash
from .contracts import (
    BINDIFF_LIMITATIONS,
    SecondaryError,
    SecondaryMatch,
    SecondaryMatchSet,
    check_pair,
    flag_names,
    to_milli,
)

MAGIC = b'SQLite format 3\x00'
MAX_SIZE = 512 * 1024 * 1024
MASK = 0xFFFF_FFFF_FFFF_FFFF
DEFAULT_DEADLINE = 120.0     # seconds of wall clock for the whole import, checked by the progress handler
PROGRESS_STEPS = 10_000      # SQLite VM instructions between deadline checks
REQUIRED = {
    'basicblockalgorithm': {'id', 'name'},
    'functionalgorithm': {'id', 'name'},
    'file': {'id', 'filename', 'exefilename', 'hash', 'functions', 'libfunctions', 'calls', 'basicblocks',
             'libbasicblocks', 'edges', 'libedges', 'instructions', 'libinstructions'},
    'metadata': {'version', 'file1', 'file2', 'description', 'created', 'modified', 'similarity',
                 'confidence'},
    'function': {'id', 'address1', 'name1', 'address2', 'name2', 'similarity', 'confidence', 'flags',
                 'algorithm', 'evaluate', 'commentsported', 'basicblocks', 'edges', 'instructions'},
    'basicblock': {'id', 'functionid', 'address1', 'address2', 'algorithm', 'evaluate'},
    'instruction': {'basicblockid', 'address1', 'address2'},
}


_SCHEMA_TABLES = frozenset({'sqlite_master', 'sqlite_schema', 'sqlite_temp_master'})
_READABLE = frozenset(REQUIRED) | _SCHEMA_TABLES
_FUNCTIONS = frozenset({'count'})


def _authorizer(action: int, arg1, arg2, dbname, source) -> int:
    """Fail-closed whitelist: SELECT, reads of the fixed tables, `PRAGMA table_info` on them, COUNT()."""
    if action == sqlite3.SQLITE_SELECT:
        return sqlite3.SQLITE_OK
    if action == sqlite3.SQLITE_READ and isinstance(arg1, str) and arg1.lower() in _READABLE:
        return sqlite3.SQLITE_OK
    if action == sqlite3.SQLITE_FUNCTION and isinstance(arg2, str) and arg2.lower() in _FUNCTIONS:
        return sqlite3.SQLITE_OK
    if action == sqlite3.SQLITE_PRAGMA and arg1 == 'table_info' and isinstance(arg2, str) and arg2 in REQUIRED:
        return sqlite3.SQLITE_OK
    return sqlite3.SQLITE_DENY


def _harden(db: sqlite3.Connection, file_size: int) -> None:
    db.execute('PRAGMA trusted_schema=OFF')
    db.execute('PRAGMA query_only=1')
    db.execute('PRAGMA cell_size_check=ON')
    page_size = db.execute('PRAGMA page_size').fetchone()[0]
    if not isinstance(page_size, int) or page_size < 512 or page_size > 65536 or page_size & (page_size - 1):
        raise _fail('malformed BinDiff database: invalid page size')
    db.execute(f'PRAGMA max_page_count={max(1, -(-file_size // page_size))}')  # SQLite keeps >= current size
    if hasattr(db, 'setconfig') and hasattr(sqlite3, 'SQLITE_DBCONFIG_DEFENSIVE'):
        db.setconfig(sqlite3.SQLITE_DBCONFIG_DEFENSIVE, True)
    db.set_authorizer(_authorizer)


def _fail(message: str) -> SecondaryError:
    return SecondaryError('PT-SECONDARY-INPUT', message)


def _address(value: object) -> int:
    # BinDiff stores uint64 VAs in signed BIGINT; values >= 2**63 read back negative.
    if isinstance(value, bool) or not isinstance(value, int):
        raise _fail('function address is not an integer')
    return value & MASK


def _name(value: object) -> str | None:
    if value is None or isinstance(value, str):
        return value
    raise _fail('function name is not text')


def import_bindiff(path: Path, older_sha256: str, newer_sha256: str, *,
                   expected_hashes: tuple[str, str] | None = None,
                   deadline_seconds: float = DEFAULT_DEADLINE, preserve_dir: Path | None = None) -> SecondaryMatchSet:
    """`expected_hashes` (SPEC-29 §3): the `file.hash` pair to require when the BinExport inputs were bound
    by an explicit user assertion rather than a SHA-256 `executable_id`; default = the artifact hashes.
    `deadline_seconds` bounds the whole import (SPEC-29 §7.2); expiry raises `PT-SECONDARY-LIMIT`.
    `preserve_dir`: a user-selected file is first copied there (hashed once, named by its hash) and the copy is
    parsed, so the stored hash describes the bytes read and the upstream raw data is kept."""
    path = Path(path).resolve()
    if preserve_dir is not None:
        path = _preserve(path, Path(preserve_dir))
    try:
        size = path.stat().st_size
        with path.open('rb') as handle:
            header = handle.read(16)
    except OSError as exc:
        raise _fail(f'cannot read BinDiff file: {exc.strerror}') from None
    if header != MAGIC:
        raise _fail('not a SQLite database (BinDiff magic missing)')
    if size > MAX_SIZE:
        raise SecondaryError('PT-SECONDARY-LIMIT', 'BinDiff file exceeds 512 MiB')
    digest = hashlib.sha256()
    with path.open('rb') as handle:
        while chunk := handle.read(1 << 20):
            digest.update(chunk)
    try:
        db = sqlite3.connect(f'{path.as_uri()}?mode=ro&immutable=1', uri=True)
    except sqlite3.Error:
        raise _fail('cannot open BinDiff database read-only') from None
    expired = False
    limit = time.monotonic() + deadline_seconds

    def progress() -> int:
        nonlocal expired
        if time.monotonic() >= limit:  # >=: Windows' monotonic clock ticks every ~15.6 ms, so a zero deadline ties
            expired = True
            return 1  # interrupts the running statement
        return 0

    try:
        db.set_progress_handler(progress, PROGRESS_STEPS)
        _harden(db, size)
        return _read(db, older_sha256, newer_sha256, digest.hexdigest(), expected_hashes)
    except (sqlite3.Error, UnicodeDecodeError, OverflowError) as exc:  # corrupt text/varints, not just pages
        if expired:
            raise SecondaryError('PT-SECONDARY-LIMIT', f'BinDiff database import exceeded the '
                                 f'{deadline_seconds:g} s time limit') from None
        raise _fail(f'malformed BinDiff database: {type(exc).__name__}') from None
    finally:
        db.close()


def _preserve(source: Path, directory: Path) -> Path:
    try:
        directory.mkdir(parents=True, exist_ok=True)
        fd, temp = tempfile.mkstemp(prefix='.bindiff-', suffix='.part', dir=directory)
        os.close(fd)
        Path(temp).unlink()  # copy_and_hash creates its destination exclusively
        try:
            sha = copy_and_hash(source, Path(temp), max_bytes=MAX_SIZE)
            kept = directory / f'bindiff-{sha}.BinDiff'
            os.replace(temp, kept)
        except BaseException:
            Path(temp).unlink(missing_ok=True)
            raise
    except OSError as exc:
        raise _fail(f'cannot preserve BinDiff file: {exc.strerror}') from None
    return kept


def _check_schema_objects(db: sqlite3.Connection) -> set[str]:
    """Only plain tables and their indexes are acceptable; anything executable or indirect is refused."""
    tables: set[str] = set()
    entries = db.execute('SELECT type, name, tbl_name, sql FROM sqlite_master').fetchall()
    for kind, name, _table, sql in entries:
        if kind in ('trigger', 'view'):
            raise _fail(f'BinDiff database contains a {kind}; refusing to read it')
        if kind == 'table':
            if isinstance(sql, str) and sql.lstrip()[:20].upper().replace(' ', '').startswith('CREATEVIRTUAL'):
                raise _fail('BinDiff database contains a virtual table; refusing to read it')
            tables.add(name)
        elif kind != 'index':
            raise _fail(f'BinDiff database contains an unexpected schema object type {str(kind)[:20]!r}')
    for kind, _name, table, _sql in entries:
        if kind == 'index' and table not in tables:
            raise _fail('BinDiff database index refers to a non-table object')
    return tables


def _read(db: sqlite3.Connection, older_sha256: str, newer_sha256: str, file_sha256: str,
          expected_hashes: tuple[str, str] | None = None) -> SecondaryMatchSet:
    tables = _check_schema_objects(db)
    for table, columns in REQUIRED.items():
        if table not in tables:
            raise _fail(f'required table {table!r} missing')
        present = {row[1] for row in db.execute(f'PRAGMA table_info("{table}")')}
        if missing := columns - present:
            raise _fail(f'table {table!r} lacks columns {sorted(missing)}')
    meta = db.execute('SELECT version, file1, file2, similarity, confidence FROM metadata').fetchall()
    if len(meta) != 1:
        raise _fail('metadata must contain exactly one row')
    version, file1, file2, similarity, confidence = meta[0]
    to_milli(similarity, 'metadata.similarity')
    to_milli(confidence, 'metadata.confidence')
    if not isinstance(version, str) or not version.startswith('BinDiff ') or len(version) <= 8:
        raise _fail('metadata.version is not a BinDiff version')
    if (file1, file2) != (1, 2):
        raise _fail('metadata must reference file ids 1 and 2')
    files = dict(db.execute('SELECT id, hash FROM file').fetchall())
    if db.execute('SELECT COUNT(*) FROM file').fetchone()[0] != 2 or set(files) != {1, 2}:
        raise _fail('file table must contain exactly ids 1 and 2')
    if not all(isinstance(files[i], str) for i in (1, 2)):
        raise _fail('file.hash must be text')
    want_older, want_newer = expected_hashes or (older_sha256, newer_sha256)
    check_pair(files[1], files[2], want_older.strip().lower(), want_newer.strip().lower())
    algorithms = {}
    for ident, name in db.execute('SELECT id, name FROM functionalgorithm'):
        if not isinstance(name, str) or not name.strip():
            raise _fail('functionalgorithm row without a name')
        algorithms[ident] = name
    engine_version = version[len('BinDiff '):]
    matches = []
    for row in db.execute('SELECT address1, name1, address2, name2, similarity, confidence, flags, algorithm '
                          'FROM function ORDER BY address1, address2'):
        address1, name1, address2, name2, similarity, confidence, flags, algorithm = row
        if algorithm not in algorithms:
            raise _fail(f'function.algorithm {algorithm!r} has no functionalgorithm row')
        sim_milli, sim_text = to_milli(similarity, 'function.similarity')
        conf_milli, conf_text = to_milli(confidence, 'function.confidence')
        matches.append(SecondaryMatch(
            engine='bindiff', engine_version=engine_version,
            older_address=_address(address1), newer_address=_address(address2),
            older_name=_name(name1), newer_name=_name(name2),
            similarity_milli=sim_milli, similarity_text=sim_text,
            confidence_milli=conf_milli, confidence_text=conf_text,
            flags=flag_names(flags), algorithm=algorithms[algorithm]))
    olders = [m.older_address for m in matches]
    newers = [m.newer_address for m in matches]
    if len(set(olders)) != len(olders) or len(set(newers)) != len(newers):
        raise _fail('a function address appears in more than one BinDiff match')
    # BinExport metadata carries no image-base option, so subtraction is not detectable here.
    return SecondaryMatchSet(engine='bindiff', engine_version=engine_version, older_sha256=older_sha256,
                             newer_sha256=newer_sha256, file_sha256=file_sha256,
                             image_base_subtracted='unknown', matches=tuple(matches),
                             limitations=BINDIFF_LIMITATIONS)
