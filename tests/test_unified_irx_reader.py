"""irx audit: a failed ingest leaves nothing behind; a corrupt sidecar is a typed STORE error, never a raw
IndexError / sqlite3.DatabaseError / JSONDecodeError (verify=False models a database that passes the hash check)."""
from __future__ import annotations

import sqlite3

import pytest
from unified_extract_builder import SHA, document_set, footer, function, pe_view, write_jsonl

from patchtrace.unified.ir import schema
from patchtrace.unified.ir.ingest import ExpectedSide, ingest
from patchtrace.unified.ir.reader import IrReader
from patchtrace.unified.limits import UnifiedError

STRAIGHT = [('lea', 0x2040), ('call', 0x1100), ('cmp', 7), ('mov',), ('ret',)]


def build(tmp_path, name='b'):
    callee = function(0x1100, [('mov',), ('ret',)], name='callee')
    caller = function(0x1000, STRAIGHT, name='caller', calls=[(0x1007, 0x1100, None, 'call')],
                      aliases=['alias_one'])
    path = write_jsonl(tmp_path / f'{name}.jsonl', document_set(caller, callee))
    out = tmp_path / f'out-{name}'
    out.mkdir()
    return ingest(path, ExpectedSide('older', SHA, pe_view(), mode='analyze'), out_dir=out)


def test_a_failed_ingest_leaves_no_sidecar_behind(tmp_path):
    docs = list(document_set(function(0x1000, STRAIGHT, name='caller'), function(0x1100, [('ret',)])))
    docs[-1] = footer(5, 5)                                   # footer counts differ from the records
    path = write_jsonl(tmp_path / 'bad.jsonl', docs)
    out = tmp_path / 'out'
    out.mkdir()
    with pytest.raises(UnifiedError) as caught:
        ingest(path, ExpectedSide('older', SHA, pe_view(), mode='analyze'), out_dir=out)
    assert caught.value.reason == 'footer-mismatch'
    assert list(out.iterdir()) == []


def test_an_ingest_over_the_file_cap_leaves_no_sidecar_behind(tmp_path):
    from patchtrace.unified.limits import UnifiedLimits
    path = write_jsonl(tmp_path / 'ok.jsonl', document_set(function(0x1000, STRAIGHT, name='caller')))
    out = tmp_path / 'out'
    out.mkdir()
    with pytest.raises(UnifiedError) as caught:
        ingest(path, ExpectedSide('older', SHA, pe_view(), mode='analyze'), UnifiedLimits(l07_ir_file_bytes=1024),
               out_dir=out)
    assert caught.value.reason == 'ir-too-large'
    assert list(out.iterdir()) == []


def tamper(directory, sql, args=()):
    connection = sqlite3.connect(str(directory / schema.DB_NAME))
    connection.execute(sql, args)
    connection.commit()
    connection.close()


@pytest.mark.parametrize('sql', [
    'UPDATE call SET callee=99',                   # beyond the function table
    'UPDATE call SET callee=-1',                   # would silently index from the end
    'UPDATE call SET fid=99',
    "UPDATE fn SET aliases='not json' WHERE fid=0",
    "UPDATE fn SET rva='text' WHERE fid=0",       # SQLite is typeless: a TEXT cell must not reach array('q')
])
def test_a_corrupt_row_is_a_typed_store_error(tmp_path, sql):
    result = build(tmp_path)
    tamper(result.directory, sql)
    with pytest.raises(UnifiedError) as caught:
        IrReader.open(result.directory, verify=False)
    assert caught.value.code == 'PT-UNIFIED-STORE'


def test_a_truncated_database_is_a_typed_store_error(tmp_path):
    result = build(tmp_path)
    database = result.directory / schema.DB_NAME
    data = database.read_bytes()
    database.write_bytes(data[:len(data) // 2])
    with pytest.raises(UnifiedError) as caught:
        IrReader.open(result.directory, verify=False)
    assert caught.value.code == 'PT-UNIFIED-STORE'


@pytest.mark.parametrize('sql', ["UPDATE bb SET succ='[[0,99]]'", "UPDATE bb SET succ='oops'"])
def test_a_corrupt_block_row_is_a_typed_store_error(tmp_path, sql):
    result = build(tmp_path)
    tamper(result.directory, sql)
    reader = IrReader.open(result.directory, verify=False)
    try:
        with pytest.raises(UnifiedError) as caught:
            reader.blocks(0)
        assert caught.value.code == 'PT-UNIFIED-STORE'
    finally:
        reader.close()
