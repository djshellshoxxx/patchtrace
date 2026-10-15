"""Segment store (WB1 section 7 'Segment file'): one immutable SQLite file per source group, named by digest.

`build_segment` writes `.staging-<uuid>`, checks it, fsyncs it and `os.replace`s it onto the digest name; a
published file is never modified and an open file is never replaced (an equal existing file wins). `open_segment`
opens read-only and immutable under a fail-closed authorizer [F11], validates identity PRAGMAs, schema and meta,
and runs `quick_check` once per file version. A segment is a disposable cache: anything wrong with one means
"rebuild", never "repair" (`try_open` discards it). Pure stdlib + sqlite3; no Qt, network or process code.
"""
from __future__ import annotations

import contextlib
import enum
import itertools
import os
import re
import sqlite3
import time
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import get_args

from patchtrace.enrichment.identity import domain_id
from patchtrace.search import paths
from patchtrace.search.contracts import SearchKind
from patchtrace.search.errors import SearchError
from patchtrace.search.limits import (
    APPLICATION_ID,
    DEFAULT_LIMITS,
    MIB,
    SEGMENT_CONTRACT,
    SEGMENT_USER_VERSION,
    SearchLimits,
)
from patchtrace.search.normalize import sanitize_text

BUILDER_VERSION = 1
NORM_VERSION = 1
CODE_CHARS = 2 * MIB  # decompiled body cap per function (section 7 'Index sources')
SUBJECT_CHARS, DISPLAY_CHARS, EXTRA_CHARS = 64, 200, 200
SQLITE_MAGIC = b'SQLite format 3\x00'
TABLE_SETS = {'name': ('fts_name', 'tri_name'), 'code': ('fts_code',), 'text': ('fts_text',)}
_DDL = {
    'meta': 'CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT NOT NULL) WITHOUT ROWID',
    'doc': ('CREATE TABLE doc(id INTEGER PRIMARY KEY, kind TEXT NOT NULL, side TEXT, subject TEXT NOT NULL, '
            'display TEXT NOT NULL, extra TEXT NOT NULL, ref INTEGER NOT NULL, rva INTEGER, flags INTEGER NOT NULL, '
            'value_sha TEXT)'),
    'doc_kind_subject': 'CREATE INDEX doc_kind_subject ON doc(kind, subject, side)',
    'doc_value_sha': 'CREATE INDEX doc_value_sha ON doc(value_sha)',
    'fts_name': "CREATE VIRTUAL TABLE fts_name USING fts5(raw, words, tokenize='unicode61 remove_diacritics 2')",
    'tri_name': "CREATE VIRTUAL TABLE tri_name USING fts5(name, tokenize='trigram', detail=full)",
    'fts_code': "CREATE VIRTUAL TABLE fts_code USING fts5(body, idents, tokenize='unicode61', detail=full)",
    'fts_text': "CREATE VIRTUAL TABLE fts_text USING fts5(title, body, tokenize='unicode61', detail=full)",
}
_FTS_TABLES = ('fts_name', 'tri_name', 'fts_code', 'fts_text')
_SHADOW = re.compile(r'^(?:fts_name|tri_name|fts_code|fts_text)_(?:data|idx|content|docsize|config)$')
_SCHEMA_TABLES = frozenset({'sqlite_master', 'sqlite_schema', 'sqlite_temp_master', 'sqlite_temp_schema'})
_FUNCTIONS = frozenset({'match', 'bm25', 'snippet', 'highlight', 'count', 'char', 'instr', 'lower', 'length'})
_SHA256 = re.compile(r'^[0-9a-f]{64}$')
_PLAIN_ASCII = re.compile(r'[ -~\n]*')
_KINDS = frozenset(get_args(SearchKind))
_VERIFIED: set[tuple[str, int, int]] = set()  # (path, size, mtime_ns) that passed quick_check in this process


class Flag(enum.IntFlag):
    AUTO = 1  # placeholder name (`FUN_...`): ranked last, never fuzzy
    DERIVED = 2  # words derived from a demangled or MSVC-light form, never shown as the name
    SYMBOL = 4
    UNCHANGED = 8
    SECRET = 16  # text replaced by `[redacted: kind]` + hash


@dataclass(frozen=True, slots=True)
class SegmentDoc:
    """One document: a `doc` row plus the text of the FTS tables it belongs to. `ref` is the ordinal in the
    group's digest-pinned, sorted source list; line numbers are never indexed."""
    kind: str
    side: str | None
    subject: str
    display: str
    ref: int
    extra: str = ''
    rva: int | None = None
    flags: int = 0
    value_sha: str | None = None
    name_raw: str | None = None  # folded name: fts_name.raw and tri_name.name
    name_words: str = ''
    code_body: str | None = None
    code_idents: str = ''
    text_title: str | None = None
    text_body: str = ''


@dataclass(frozen=True, slots=True)
class SegmentInfo:
    group: str
    digest16: str
    tables: tuple[str, ...]  # logical table sets: 'name', 'code', 'text'
    docs: int
    size_bytes: int
    truncated: bool
    built_utc: str
    sqlite_version: str
    path: Path


def _source_error(message: str) -> SearchError:
    return SearchError('PT-SEARCH-SOURCE', message, recoverable=True)


def _corrupt(detail: str) -> SearchError:
    return SearchError('PT-SEARCH-STORE', f'the search index file is unusable ({detail}); it will be rebuilt',
                       recoverable=True)


def _tables(table_sets: Iterable[str]) -> tuple[str, ...]:
    chosen = sorted(set(table_sets))
    if not chosen or not set(chosen) <= set(TABLE_SETS):
        raise _source_error('a segment needs one or more of the table sets name, code, text')
    return tuple(chosen)


def _fts_names(table_sets: Iterable[str]) -> list[str]:
    return [name for key in _tables(table_sets) for name in TABLE_SETS[key]]


def tokenizer_digest(table_sets: Iterable[str]) -> str:
    """Digest of the exact FTS5 table definitions (tokenizers and options) a segment of these sets carries."""
    return domain_id('search-tok', 1, [_DDL[name] for name in _fts_names(table_sets)])[:16]


def segment_digest(group: str, table_sets: Iterable[str], inputs) -> str:
    """The digest16 in a segment's file name. `inputs` is the group's digest-pinned input description (section 7
    'Digest'); the SQLite major.minor is part of it because tokenizer tables may differ between releases."""
    major_minor = '.'.join(sqlite3.sqlite_version.split('.')[:2])
    return domain_id('search-seg', 1, {
        'group': group, 'builder_version': BUILDER_VERSION, 'norm_version': NORM_VERSION,
        'tokenizer_digest': tokenizer_digest(table_sets), 'sqlite_major_minor': major_minor,
        'inputs': inputs})[:16]


# ------------------------------------------------------------------------------------------------ build

def _clean(text: str, limit: int) -> str:
    if len(text) <= limit and _PLAIN_ASCII.fullmatch(text):
        return text
    return sanitize_text(text, limit, multiline=True)


def _valid(doc: SegmentDoc) -> None:
    bad = (doc.kind not in _KINDS or doc.side not in (None, 'older', 'newer') or doc.ref < 0
           or not 0 <= doc.flags < 1 << 31)
    bad = bad or (doc.rva is not None and not 0 <= doc.rva < 1 << 63)
    bad = bad or (doc.value_sha is not None and not _SHA256.match(doc.value_sha))
    if bad:
        raise _source_error('a document has an invalid kind, side, reference, address, flag or hash')


def _rows(chunk: tuple[SegmentDoc, ...], first_id: int, sets: tuple[str, ...], limits: SearchLimits) -> dict[str, list]:
    rows: dict[str, list] = {name: [] for name in ('doc', *_fts_names(sets))}
    field = limits.field_bytes

    def add(table: str, doc_id: int, *values: str) -> None:
        if table not in rows:
            raise _source_error(f'a document carries text for {table}, which this segment does not have')
        rows[table].append((doc_id, *values))

    for doc_id, doc in enumerate(chunk, first_id):
        _valid(doc)
        rows['doc'].append((doc_id, doc.kind, doc.side, _clean(doc.subject, SUBJECT_CHARS),
                            _clean(doc.display, DISPLAY_CHARS), _clean(doc.extra, EXTRA_CHARS), doc.ref, doc.rva,
                            doc.flags, doc.value_sha))
        if doc.name_raw is not None:
            raw = _clean(doc.name_raw, field)
            add('fts_name', doc_id, raw, _clean(doc.name_words, field))
            add('tri_name', doc_id, raw)
        if doc.code_body is not None:
            add('fts_code', doc_id, _clean(doc.code_body, CODE_CHARS), _clean(doc.code_idents, field))
        if doc.text_title is not None:
            add('fts_text', doc_id, _clean(doc.text_title, field), _clean(doc.text_body, field))
    return rows


def _create_schema(db: sqlite3.Connection, table_sets: tuple[str, ...]) -> None:
    db.execute(f'PRAGMA application_id={APPLICATION_ID}')
    db.execute(f'PRAGMA user_version={SEGMENT_USER_VERSION}')
    for name in ('meta', 'doc', 'doc_kind_subject', 'doc_value_sha', *_fts_names(table_sets)):
        db.execute(_DDL[name])


def _insert(db: sqlite3.Connection, rows: dict[str, list]) -> None:
    db.executemany('INSERT INTO doc(id, kind, side, subject, display, extra, ref, rva, flags, value_sha) '
                   'VALUES (?,?,?,?,?,?,?,?,?,?)', rows['doc'])
    columns = {'fts_name': 'raw, words', 'tri_name': 'name', 'fts_code': 'body, idents', 'fts_text': 'title, body'}
    for table, values in rows.items():
        if table != 'doc' and values:
            marks = ','.join('?' * (len(values[0]) - 1))
            db.executemany(f'INSERT INTO {table}(rowid, {columns[table]}) VALUES (?,{marks})', values)


def _write_meta(db: sqlite3.Connection, info: dict[str, str]) -> None:
    db.executemany('INSERT INTO meta(key, value) VALUES (?, ?)', sorted(info.items()))


def _fsync(path: Path) -> None:
    with path.open('rb+') as handle:
        os.fsync(handle.fileno())


def _utc_now() -> str:
    return datetime.now(UTC).strftime('%Y-%m-%dT%H:%M:%SZ')


def build_segment(directory: Path, group: str, digest16: str, docs: Iterable[SegmentDoc],
                  table_sets: Iterable[str], *, cancel: Callable[[], bool] = lambda: False,
                  limits: SearchLimits = DEFAULT_LIMITS, max_docs: int | None = None,
                  clock: Callable[[], float] = time.monotonic, built_utc: str | None = None) -> SegmentInfo:
    """Build and publish `<group>-<digest16>.sqlite3` in `directory`. Doc ids are 1.. in iteration order, so the
    caller's sort order is the index order. `max_docs` stops early and marks the segment truncated. Cancel and the
    build deadline are checked every `limits.cancel_check_docs` documents; either removes the staging file."""
    target = paths.segment_path(directory, group, digest16)
    sets = _tables(table_sets)
    paths.ensure_writable(directory)
    staging = paths.staging_path(directory)
    try:
        info = _build_staging(staging, group, digest16, docs, sets, cancel, limits, max_docs, clock,
                              built_utc or _utc_now(), target)
        return _publish(staging, target, info)
    finally:
        _discard_files(staging)


def _build_staging(staging: Path, group: str, digest16: str, docs: Iterable[SegmentDoc], sets: tuple[str, ...],
                   cancel: Callable[[], bool], limits: SearchLimits, max_docs: int | None,
                   clock: Callable[[], float], built_utc: str, target: Path) -> SegmentInfo:
    started, count, truncated = clock(), 0, False
    stream: Iterator[SegmentDoc] = iter(docs)
    if max_docs is not None:
        stream = itertools.islice(stream, max_docs + 1)
    db = sqlite3.connect(staging, isolation_level=None)
    try:
        db.execute('PRAGMA journal_mode=OFF')
        db.execute('PRAGMA synchronous=OFF')
        _create_schema(db, sets)
        db.execute('BEGIN')
        for chunk in itertools.batched(stream, limits.cancel_check_docs):
            if max_docs is not None and count + len(chunk) > max_docs:
                chunk, truncated = chunk[:max_docs - count], True
            _insert(db, _rows(chunk, count + 1, sets, limits))
            count += len(chunk)
            if cancel():
                raise SearchError('PT-SEARCH-CANCEL', 'the index build was cancelled')
            if clock() - started >= limits.segment_build_s:
                raise SearchError('PT-SEARCH-TIMEOUT', 'building one search index segment took too long', recoverable=True)
        db.execute('COMMIT')
        size = db.execute('PRAGMA page_count').fetchone()[0] * db.execute('PRAGMA page_size').fetchone()[0]
        if size > limits.bytes_per_project:
            raise SearchError('PT-SEARCH-LIMIT', 'one search index segment exceeds the per-project size limit')
        _write_meta(db, {
            'contract': SEGMENT_CONTRACT, 'group': group, 'digest16': digest16, 'tables': ','.join(sets),
            'tokenizer_digest': tokenizer_digest(sets), 'sqlite_version': sqlite3.sqlite_version,
            'builder_version': str(BUILDER_VERSION), 'norm_version': str(NORM_VERSION), 'docs': str(count),
            'size_bytes': str(size), 'truncated': '1' if truncated else '0', 'built_utc': built_utc})
        if db.execute('PRAGMA quick_check').fetchone()[0] != 'ok':
            raise _corrupt('self-check failed')
    except sqlite3.Error as exc:
        raise SearchError('PT-SEARCH-STORE', f'building the search index failed ({type(exc).__name__})',
                          recoverable=True) from exc
    finally:
        db.close()
    _fsync(staging)
    return SegmentInfo(group, digest16, sets, count, size, truncated, built_utc, sqlite3.sqlite_version, target)


def _publish(staging: Path, target: Path, info: SegmentInfo) -> SegmentInfo:
    """An equal existing file wins (digest-named, so equal by construction; an open file is never replaced);
    otherwise atomic replace. A failed replace is tolerated when a valid file exists meanwhile."""
    if (existing := _valid_info(target)) is not None:
        return existing
    try:
        os.replace(staging, target)
    except OSError as exc:  # AV or an open handle on Windows
        if (existing := _valid_info(target)) is not None:
            return existing
        raise SearchError('PT-SEARCH-STORE', f'publishing the search index failed ({type(exc).__name__})',
                          recoverable=True) from exc
    return info


def _valid_info(path: Path) -> SegmentInfo | None:
    try:
        with open_segment(path) as segment:
            return segment.info
    except SearchError:
        return None


def _discard_files(*files: Path) -> None:
    for file in files:
        with contextlib.suppress(OSError):
            file.unlink(missing_ok=True)


# ------------------------------------------------------------------------------------------------- open

def _authorizer(action: int, arg1, arg2, dbname, source) -> int:
    """Fail-closed allow-list: SELECT, reads of this schema's tables and FTS shadow tables, the FTS/text functions
    and `PRAGMA data_version` (FTS5 issues it). ATTACH, DDL, DML, `load_extension` and FTS commands stay denied."""
    if action == sqlite3.SQLITE_SELECT:
        return sqlite3.SQLITE_OK
    if action == sqlite3.SQLITE_READ and isinstance(arg1, str):
        known = arg1 in _DDL or arg1.lower() in _SCHEMA_TABLES or _SHADOW.match(arg1)
        return sqlite3.SQLITE_OK if known else sqlite3.SQLITE_DENY
    if action == sqlite3.SQLITE_FUNCTION and isinstance(arg2, str) and arg2.lower() in _FUNCTIONS:
        return sqlite3.SQLITE_OK
    if action == sqlite3.SQLITE_PRAGMA and arg1 == 'data_version':
        return sqlite3.SQLITE_OK
    return sqlite3.SQLITE_DENY


def _harden(db: sqlite3.Connection, file_size: int) -> None:
    db.execute('PRAGMA trusted_schema=OFF')
    db.execute('PRAGMA query_only=1')
    db.execute('PRAGMA cell_size_check=ON')
    page_size = db.execute('PRAGMA page_size').fetchone()[0]
    if not isinstance(page_size, int) or page_size < 512 or page_size > 65536 or page_size & (page_size - 1):
        raise _corrupt('invalid page size')
    db.execute(f'PRAGMA max_page_count={max(1, -(-file_size // page_size))}')  # SQLite keeps >= current size
    if hasattr(db, 'setconfig') and hasattr(sqlite3, 'SQLITE_DBCONFIG_DEFENSIVE'):
        db.setconfig(sqlite3.SQLITE_DBCONFIG_DEFENSIVE, True)


def _check_schema(db: sqlite3.Connection) -> tuple[str, ...]:
    """Only the exact objects this builder creates are acceptable; returns the FTS table names found."""
    found: set[str] = set()
    for kind, name, sql in db.execute('SELECT type, name, sql FROM sqlite_master'):
        if kind == 'index' and sql is None:
            continue  # automatic index of the meta primary key
        if kind in ('table', 'index') and name in _DDL:
            if ' '.join((sql or '').split()) != ' '.join(_DDL[name].split()):
                raise _corrupt(f'unexpected definition of {name}')
            found.add(name)
        elif not (kind == 'table' and _SHADOW.match(name)):
            raise _corrupt('unexpected schema object')
    if not {'meta', 'doc', 'doc_kind_subject', 'doc_value_sha'} <= found:
        raise _corrupt('required tables missing')
    return tuple(name for name in _FTS_TABLES if name in found)


def _read_meta(db: sqlite3.Connection) -> dict[str, str]:
    meta = dict(db.execute('SELECT key, value FROM meta'))
    keys = {'contract', 'group', 'digest16', 'tables', 'tokenizer_digest', 'sqlite_version', 'builder_version',
            'norm_version', 'docs', 'size_bytes', 'truncated', 'built_utc'}
    if set(meta) != keys:
        raise _corrupt('meta is incomplete')
    return meta


def _info(meta: dict[str, str], path: Path, fts: tuple[str, ...]) -> SegmentInfo:
    sets = tuple(sorted(key for key, names in TABLE_SETS.items() if set(names) <= set(fts)))
    if not sets or set(fts) != set(_fts_names(sets)):
        raise _corrupt('incomplete table set')
    if (meta['contract'] != SEGMENT_CONTRACT or meta['builder_version'] != str(BUILDER_VERSION)
            or meta['tables'] != ','.join(sets) or meta['tokenizer_digest'] != tokenizer_digest(sets)):
        raise _corrupt('meta does not describe this build')
    if paths.parse_segment_filename(path.name) != (meta['group'], meta['digest16']):
        raise _corrupt('meta does not match the file name')
    try:
        return SegmentInfo(meta['group'], meta['digest16'], sets, int(meta['docs']), int(meta['size_bytes']),
                           meta['truncated'] == '1', meta['built_utc'], meta['sqlite_version'], path)
    except ValueError:
        raise _corrupt('meta numbers are malformed') from None


class Segment:
    """An open, hardened, read-only segment. `conn` is for the owning (reader) thread only."""

    def __init__(self, conn: sqlite3.Connection, info: SegmentInfo):
        self.conn = conn
        self.info = info

    def interrupt(self) -> None:
        self.conn.interrupt()

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> Segment:
        return self

    def __exit__(self, *exc) -> None:
        self.close()


def open_segment(path: Path, limits: SearchLimits = DEFAULT_LIMITS) -> Segment:
    """Open a published segment read-only and immutable. Raises `PT-SEARCH-STORE` (recoverable) if it is missing
    or fails any check, so the caller rebuilds."""
    path = Path(path)
    try:
        stat = path.stat()
        with path.open('rb') as handle:
            header = handle.read(16)
    except OSError as exc:
        raise SearchError('PT-SEARCH-STORE', f'cannot read the search index file ({type(exc).__name__})',
                          recoverable=True) from exc
    if header != SQLITE_MAGIC or stat.st_size > limits.bytes_per_project:
        raise _corrupt('not a segment file')
    try:
        db = sqlite3.connect(f'{path.resolve().as_uri()}?mode=ro&immutable=1', uri=True)
    except sqlite3.Error:
        raise _corrupt('cannot open read-only') from None
    try:
        _harden(db, stat.st_size)
        if (db.execute('PRAGMA application_id').fetchone()[0] != APPLICATION_ID
                or db.execute('PRAGMA user_version').fetchone()[0] != SEGMENT_USER_VERSION):
            raise _corrupt('wrong application identity')
        key = (str(path), stat.st_size, stat.st_mtime_ns)
        if key not in _VERIFIED:
            if db.execute('PRAGMA quick_check').fetchone()[0] != 'ok':
                raise _corrupt('integrity check failed')
            _VERIFIED.add(key)
        fts = _check_schema(db)
        db.set_authorizer(_authorizer)
        return Segment(db, _info(_read_meta(db), path, fts))
    except SearchError:
        db.close()
        raise
    except (sqlite3.Error, UnicodeDecodeError, OverflowError) as exc:
        db.close()
        raise _corrupt(type(exc).__name__) from None


def try_open(path: Path, limits: SearchLimits = DEFAULT_LIMITS) -> Segment | None:
    """The segment, or None when absent or corrupt (a corrupt file is deleted so the caller rebuilds)."""
    if not Path(path).exists():
        return None
    try:
        return open_segment(path, limits)
    except SearchError:
        _discard_files(Path(path))
        return None


# ---------------------------------------------------------------------------------------------------- GC

def collect_garbage(directory: Path, expected: Iterable[tuple[str, str]], *, now: float | None = None,
                    limits: SearchLimits = DEFAULT_LIMITS) -> tuple[str, ...]:
    """Delete derived files only: staging and probe files, and published segments not in `expected`
    (group, digest16), each older than `limits.stale_segment_age_s` (a younger one may belong to a running
    build). Errors are ignored (an open file on Windows stays). Returns the removed names, sorted."""
    now = time.time() if now is None else now
    keep, removed = set(expected), []
    try:
        entries = list(directory.iterdir())
    except OSError:
        return ()
    for entry in entries:
        parsed = paths.parse_segment_filename(entry.name)
        derived = entry.name.startswith((paths.STAGING_PREFIX, '.write-test-')) or (parsed is not None and parsed not in keep)
        try:
            if derived and entry.is_file() and now - entry.stat().st_mtime >= limits.stale_segment_age_s:
                entry.unlink()
                removed.append(entry.name)
        except OSError:
            continue
    return tuple(sorted(removed))


def trim_cache(cache_root: Path, active: Path | None = None, *, limits: SearchLimits = DEFAULT_LIMITS) -> tuple[str, ...]:
    """While the search cache exceeds `limits.cache_bytes`, empty the least recently modified project directory
    (never `active`), removing derived files only. Returns the emptied directory names, oldest first."""
    root = cache_root / 'search'
    projects = []
    with contextlib.suppress(OSError):
        for entry in root.iterdir():
            if re.fullmatch(r'[0-9a-f]{16}', entry.name) and entry.is_dir():
                files = [f for f in entry.iterdir() if f.is_file()]
                projects.append((max((f.stat().st_mtime for f in files), default=0.0), entry,
                                 sum(f.stat().st_size for f in files), files))
    total = sum(size for *_, size, _ in projects)
    emptied = []
    for _mtime, entry, size, files in sorted(projects, key=lambda p: (p[0], p[1].name)):
        if total <= limits.cache_bytes:
            break
        if active is not None and entry == active:
            continue
        for file in files:
            if paths.parse_segment_filename(file.name) or file.name.startswith((paths.STAGING_PREFIX, '.write-test-')):
                _discard_files(file)
        total -= size
        with contextlib.suppress(OSError):
            entry.rmdir()
            emptied.append(entry.name)
    return tuple(emptied)

