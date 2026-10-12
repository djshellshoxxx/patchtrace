"""SPEC-10 §2/§6: `.BinDiff` validator/importer against handcrafted SQLite files."""
from __future__ import annotations

import json
import sqlite3

import pytest

from patchtrace.secondary.bindiff import import_bindiff
from patchtrace.secondary.contracts import SecondaryError

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
          algorithms=((7, 'function: hash matching'), (3, 'function: name hash matching'))):
    db = sqlite3.connect(path)
    for sql in SCHEMA:
        db.execute(sql)
    db.executemany('INSERT INTO functionalgorithm VALUES(?,?)', algorithms)
    for ident, digest in zip((1, 2), hashes, strict=True):
        db.execute('INSERT INTO file(id, filename, exefilename, hash) VALUES(?,?,?,?)',
                   (ident, f'f{ident}', f'f{ident}.sys', digest))
    db.execute("INSERT INTO metadata VALUES(?,1,2,'',DATETIME('NOW'),DATETIME('NOW'),0.9,0.95)", (version,))
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


def test_valid_import_joins_algorithms_by_name_and_keeps_text(tmp_path):
    path = build(tmp_path / 'a_vs_b.BinDiff')
    before = path.read_bytes()
    result = import_bindiff(path, OLD, NEW)
    assert result.engine == 'bindiff' and result.engine_version == '8 (@123)'
    assert result.image_base_subtracted == 'unknown'
    first, second = result.matches
    assert first.algorithm == 'function: hash matching'
    assert second.algorithm == 'function: name hash matching'
    assert (second.similarity_milli, second.similarity_text) == (812, '0.8125')
    assert (second.confidence_milli, second.confidence_text) == (500, '0.5')
    assert second.flags == ('G', 'I', 'C')
    assert (second.older_address, second.newer_address) == (0x140002000, 0x140002010)
    # Read-only open leaves the file and directory untouched (no journal/WAL).
    assert path.read_bytes() == before
    assert sorted(p.name for p in tmp_path.iterdir()) == ['a_vs_b.BinDiff']


def test_negative_bigint_addresses_are_masked(tmp_path):
    path = build(tmp_path / 'x.BinDiff', functions=[(1, -2, 'hi', -0x8000000000000000, 'hi', 1.0, 1.0, 0, 7)])
    match = import_bindiff(path, OLD, NEW).matches[0]
    assert match.older_address == 0xFFFF_FFFF_FFFF_FFFE
    assert match.newer_address == 0x8000_0000_0000_0000


def test_wrong_magic_and_json_lookalike_rejected(tmp_path):
    fake = tmp_path / 'fake.BinDiff'
    fake.write_text(json.dumps({'engine': 'bindiff', 'matches': []}))
    with pytest.raises(SecondaryError, match='magic'):
        import_bindiff(fake, OLD, NEW)
    truncated = tmp_path / 'trunc.BinDiff'
    truncated.write_bytes(b'SQLite format 3\x00' + b'\x00' * 50)
    with pytest.raises(SecondaryError):
        import_bindiff(truncated, OLD, NEW)


@pytest.mark.parametrize('drop, needle', [
    ('DROP TABLE basicblock', "'basicblock' missing"),
    ('DROP TABLE functionalgorithm', "'functionalgorithm' missing"),
    ('ALTER TABLE function DROP COLUMN flags', 'lacks columns'),
    ('ALTER TABLE metadata DROP COLUMN confidence', 'lacks columns'),
])
def test_missing_table_or_column(tmp_path, drop, needle):
    with pytest.raises(SecondaryError, match=needle):
        import_bindiff(build(tmp_path / 'x.BinDiff', drop=drop), OLD, NEW)


def test_reversed_hashes_are_orientation_mismatch(tmp_path):
    with pytest.raises(SecondaryError) as info:
        import_bindiff(build(tmp_path / 'x.BinDiff', hashes=(NEW, OLD)), OLD, NEW)
    assert info.value.code == 'PT-SECONDARY-ORIENTATION'


@pytest.mark.parametrize('hashes', [(OLD, 'c' * 64), ('c' * 64, NEW), (OLD[:40], NEW[:40])])
def test_wrong_pair_rejected(tmp_path, hashes):
    with pytest.raises(SecondaryError) as info:
        import_bindiff(build(tmp_path / 'x.BinDiff', hashes=hashes), OLD, NEW)
    assert info.value.code == 'PT-SECONDARY-PAIR'


def test_uppercase_hashes_accepted(tmp_path):
    assert import_bindiff(build(tmp_path / 'x.BinDiff', hashes=(OLD.upper(), NEW.upper())), OLD, NEW)


def test_algorithm_without_row_rejected(tmp_path):
    rows = [(1, 1, 'a', 1, 'a', 1.0, 1.0, 0, 99)]
    with pytest.raises(SecondaryError, match='no functionalgorithm row'):
        import_bindiff(build(tmp_path / 'x.BinDiff', functions=rows), OLD, NEW)


@pytest.mark.parametrize('similarity, confidence', [(1.5, 0.5), (-0.1, 0.5), (0.5, 2.0), ('high', 0.5),
                                                    (None, 0.5)])
def test_similarity_confidence_out_of_range(tmp_path, similarity, confidence):
    rows = [(1, 1, 'a', 1, 'a', similarity, confidence, 0, 7)]
    with pytest.raises(SecondaryError):
        import_bindiff(build(tmp_path / 'x.BinDiff', functions=rows), OLD, NEW)


@pytest.mark.parametrize('kwargs, extra', [
    ({'version': 'NotBinDiff 8'}, ()),
    ({}, ("INSERT INTO metadata(version,file1,file2) VALUES('BinDiff 8',1,2)",)),
    ({}, ('UPDATE metadata SET file1=2, file2=1',)),
    ({}, ("INSERT INTO file(id, hash) VALUES(3, 'x')",)),
    ({}, ('UPDATE metadata SET similarity=3.0',)),
    ({}, ('UPDATE function SET flags=128',)),
    ({}, ('UPDATE function SET address2=1 WHERE id=2', 'UPDATE function SET address2=1 WHERE id=1')),
    ({'algorithms': ((7, None), (3, 'x'))}, ()),
])
def test_structural_violations(tmp_path, kwargs, extra):
    with pytest.raises(SecondaryError):
        import_bindiff(build(tmp_path / 'x.BinDiff', extra=extra, **kwargs), OLD, NEW)


def test_missing_file_reported(tmp_path):
    with pytest.raises(SecondaryError, match='cannot read'):
        import_bindiff(tmp_path / 'absent.BinDiff', OLD, NEW)
