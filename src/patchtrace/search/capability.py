"""Authoritative runtime probe: a throw-away in-memory FTS5 table per tokenizer, not compile options."""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass

from patchtrace import optional_deps
from patchtrace.search.errors import SearchError


@dataclass(frozen=True)
class SearchCapability:
    sqlite_version: str
    fts5: bool
    unicode61: bool
    trigram: bool
    rapidfuzz_version: str  # '' when absent
    rapidfuzz_backend: str  # 'cpp-avx2', 'cpp', 'python', 'unknown' or '' when absent

    @property
    def usable(self) -> bool:
        return self.fts5 and self.unicode61 and self.trigram

    @property
    def rapidfuzz_native(self) -> bool:
        return self.rapidfuzz_backend.startswith('cpp')


def _fts_finds(tokenize: str, text: str, query: str) -> bool:
    db = sqlite3.connect(':memory:')
    try:
        db.execute(f"CREATE VIRTUAL TABLE t USING fts5(name, tokenize='{tokenize}')")
        db.execute('INSERT INTO t(name) VALUES (?)', (text,))
        return db.execute('SELECT count(*) FROM t WHERE t MATCH ?', (query,)).fetchone()[0] == 1
    except sqlite3.Error:
        return False
    finally:
        db.close()


def rapidfuzz_backend() -> str:
    """Backend RapidFuzz chose at import; '' when it is not installed."""
    if not optional_deps.available('rapidfuzz'):
        return ''
    from rapidfuzz import fuzz
    tail = getattr(fuzz.ratio, '__module__', '').rsplit('.', 1)[-1]
    if tail.startswith('fuzz_cpp'):
        return 'cpp' + tail[len('fuzz_cpp'):].replace('_', '-')
    return 'python' if tail == 'fuzz_py' else 'unknown'


def probe_capability() -> SearchCapability:
    fts5 = _fts_finds('unicode61', 'alpha beta', 'beta')
    # `_` must split words (F8) and a quoted phrase on trigram must be a literal substring match (F7)
    unicode61 = fts5 and _fts_finds('unicode61 remove_diacritics 2', 'Rtl_CopyMemory', 'rtl')
    trigram = _fts_finds('trigram', 'RtlCopyMemory', '"opyMem"')
    rapidfuzz = optional_deps.probe(('rapidfuzz',))['rapidfuzz']
    return SearchCapability(sqlite3.sqlite_version, fts5, unicode61, trigram,
                            rapidfuzz.version if rapidfuzz.available else '', rapidfuzz_backend())


def require_search(capability: SearchCapability) -> None:
    if not capability.usable:
        missing = [name for name, ok in (('FTS5', capability.fts5), ('unicode61', capability.unicode61),
                                         ('trigram', capability.trigram)) if not ok]
        raise SearchError('PT-SEARCH-CAPABILITY', f'SQLite {capability.sqlite_version} lacks: {", ".join(missing)}')
