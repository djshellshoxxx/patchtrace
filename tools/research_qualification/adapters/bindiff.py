"""BinDiff `.BinDiff` SQLite export -> ranked changed-function names.

UNVERIFIED against a real export (none was available); the schema is the documented one: table `function` with
`address1`, `name1`, `address2`, `name2`, `similarity`, `confidence` (REAL 0..1). Only matched pairs are stored in
the file, so added/removed-only functions cannot be recovered and are never reported. similarity >= 1.0 = identical
(excluded); magnitude = 1 - similarity, ties by lower confidence first, then name. Name = `name1` (primary/older),
else `name2`; pairs with neither name are skipped (never invented from addresses).

Input is a path (PathLike, confined) or the raw bytes of the file; plain `str` is refused as ambiguous. The database
is opened with `mode=ro` through a URI and only a bounded SELECT is run. A copy to a temp file is made for bytes.
"""
from __future__ import annotations

import os
import sqlite3
import tempfile
from pathlib import Path
from urllib.parse import quote

from .. import pathguard
from ._common import MAX_FUNCTIONS, MAX_INPUT_BYTES, normalise_name, rank, unit_float

_MAGIC = b'SQLite format 3\x00'


def parse(source: str | bytes | os.PathLike) -> list[str]:
    if isinstance(source, str):
        raise ValueError('bindiff: pass a Path (or the raw bytes); a str is ambiguous for a binary database')
    if isinstance(source, os.PathLike):
        return _read(pathguard.confine(source, 'BinDiff database'))
    if isinstance(source, bytes | bytearray):
        if len(source) > MAX_INPUT_BYTES:
            raise ValueError(f'BinDiff database exceeds {MAX_INPUT_BYTES} bytes')
        with tempfile.TemporaryDirectory(prefix='rq-bindiff-') as tmp:
            copy = Path(tmp) / 'in.BinDiff'
            copy.write_bytes(bytes(source))
            return _read(copy)
    raise ValueError(f'bindiff: unsupported source type {type(source).__name__}')


def _read(path: Path) -> list[str]:
    if not path.is_file():
        raise ValueError(f'BinDiff database is not a regular file: {path}')
    if path.stat().st_size > MAX_INPUT_BYTES:
        raise ValueError(f'BinDiff database exceeds {MAX_INPUT_BYTES} bytes')
    with path.open('rb') as fh:
        if fh.read(len(_MAGIC)) != _MAGIC:
            raise ValueError('not a SQLite database (bad header)')
    try:
        con = sqlite3.connect(f'file:{quote(path.as_posix())}?mode=ro', uri=True)
    except sqlite3.Error as exc:
        raise ValueError(f'cannot open BinDiff database read-only: {exc}') from exc
    try:
        con.execute('PRAGMA query_only = ON')
        try:
            rows = con.execute(
                'SELECT name1, name2, similarity, confidence FROM function LIMIT ?', (MAX_FUNCTIONS + 1,)).fetchall()
        except sqlite3.Error as exc:
            raise ValueError(f'BinDiff database has no usable `function` table: {exc}') from exc
    finally:
        con.close()
    if len(rows) > MAX_FUNCTIONS:
        raise ValueError(f'more than {MAX_FUNCTIONS} function rows')
    changed: list[tuple[str, float]] = []
    for name1, name2, sim, conf in rows:
        name = normalise_name(name1) or normalise_name(name2)
        if name is None:
            continue
        similarity = unit_float(sim, f'similarity for {name!r}')
        if similarity >= 1.0:
            continue
        confidence = unit_float(conf if conf is not None else 1.0, f'confidence for {name!r}')
        changed.append((name, (1.0 - similarity) + 1e-6 * (1.0 - confidence)))
    return rank(changed)
