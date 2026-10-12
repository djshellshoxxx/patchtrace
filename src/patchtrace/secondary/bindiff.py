"""Read-only `.BinDiff` (SQLite) validator and importer (SPEC-10 §2-3).

The database is untrusted input: it is opened through a read-only, immutable URI so
neither a journal nor a WAL file is created next to it, and every structural property
the importer relies on is checked before any row is turned into a record.
"""
from __future__ import annotations

import hashlib
import sqlite3
from pathlib import Path

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


def import_bindiff(path: Path, older_sha256: str, newer_sha256: str) -> SecondaryMatchSet:
    path = Path(path).resolve()
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
    try:
        db.execute('PRAGMA query_only=1')
        return _read(db, older_sha256, newer_sha256, digest.hexdigest())
    except sqlite3.Error as exc:
        raise _fail(f'malformed BinDiff database: {type(exc).__name__}') from None
    finally:
        db.close()


def _read(db: sqlite3.Connection, older_sha256: str, newer_sha256: str, file_sha256: str) -> SecondaryMatchSet:
    tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
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
    check_pair(files[1], files[2], older_sha256, newer_sha256)
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
