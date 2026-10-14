"""Shared `.BinDiff` (SQLite) builder for tests, the fake `bindiff` executable and the golden fixture script.

The schema mirrors the tables/columns `import_bindiff` requires (SPEC-10 §2). It is a synthetic stand-in,
not a database written by BinDiff; a live-produced golden replaces it once SPEC-29 §9.3 runs on a real install.
"""
from __future__ import annotations

import sqlite3

OLD, NEW = 'a' * 64, 'b' * 64
SCHEMA = [
    'CREATE TABLE basicblockalgorithm(id SMALLINT PRIMARY KEY, name TEXT)',
    'CREATE TABLE functionalgorithm(id SMALLINT PRIMARY KEY, name TEXT)',
    'CREATE TABLE file(id INT, filename TEXT, exefilename TEXT, hash CHARACTER(40), functions INT, '
    'libfunctions INT, calls INT, basicblocks INT, libbasicblocks INT, edges INT, libedges INT, '
    'instructions INT, libinstructions INT)',
    'CREATE TABLE metadata(version TEXT, file1 INT, file2 INT, description TEXT, created DATE, modified DATE, '
    'similarity DOUBLE PRECISION, confidence DOUBLE PRECISION)',
    'CREATE TABLE function(id INT PRIMARY KEY, address1 BIGINT, name1 TEXT, address2 BIGINT, name2 TEXT, '
    'similarity DOUBLE PRECISION, confidence DOUBLE PRECISION, flags INTEGER, algorithm SMALLINT, '
    'evaluate BOOLEAN, commentsported BOOLEAN, basicblocks INTEGER, edges INTEGER, instructions INTEGER, '
    'UNIQUE(address1,address2))',
    'CREATE TABLE basicblock(id INT PRIMARY KEY, functionid INT, address1 BIGINT, address2 BIGINT, '
    'algorithm SMALLINT, evaluate BOOLEAN)',
    'CREATE TABLE instruction(basicblockid INT, address1 BIGINT, address2 BIGINT)',
]


def build(path, *, hashes=(OLD, NEW), version='BinDiff 8 (@123)', drop=None, extra=(), functions=None,
          algorithms=((7, 'function: hash matching'), (3, 'function: name hash matching')),
          created='2026-10-14 00:00:00'):
    db = sqlite3.connect(path)
    for sql in SCHEMA:
        db.execute(sql)
    db.executemany('INSERT INTO functionalgorithm VALUES(?,?)', algorithms)
    for ident, digest in zip((1, 2), hashes, strict=True):
        db.execute('INSERT INTO file(id, filename, exefilename, hash) VALUES(?,?,?,?)',
                   (ident, f'f{ident}', f'f{ident}.sys', digest))
    db.execute("INSERT INTO metadata VALUES(?,1,2,'',?,?,0.9,0.95)", (version, created, created))
    rows = functions if functions is not None else [
        (1, 0x140001000, 'Foo', 0x140001000, 'Foo', 1.0, 0.99, 0, 7),
        (2, 0x140002000, 'Bar', 0x140002010, 'Bar', 0.8125, 0.5, 1 | 2 | 64, 3),
    ]
    db.executemany('INSERT INTO function(id,address1,name1,address2,name2,similarity,confidence,flags,algorithm) '
                   'VALUES(?,?,?,?,?,?,?,?,?)', rows)
    for sql in extra:
        db.execute(sql)
    if drop:
        db.execute(drop)
    db.commit()
    db.close()
    return path
