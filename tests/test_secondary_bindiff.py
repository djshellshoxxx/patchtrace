"""SPEC-10 §2/§6: `.BinDiff` validator/importer against handcrafted SQLite files."""
from __future__ import annotations

import json

import pytest
from bindiff_builder import NEW, OLD, SCHEMA, build  # noqa: F401  (re-exported for older imports)

from patchtrace.secondary.bindiff import import_bindiff
from patchtrace.secondary.contracts import SecondaryError


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
