"""SPEC-31 S1: the IR reader, the hardened read-only database and content-addressed placement (ir/reader.py,
ir/schema.py, ir/place.py)."""
from __future__ import annotations

import json
import sqlite3
from array import array

import pytest
from unified_extract_builder import SHA, document_set, function, pe_view, write_jsonl

from patchtrace.unified.ir import ins as ins_module
from patchtrace.unified.ir import place, schema
from patchtrace.unified.ir.features import NULL_KEY
from patchtrace.unified.ir.ingest import ExpectedSide, ingest
from patchtrace.unified.ir.reader import FunctionTable, IrReader, read_manifest
from patchtrace.unified.limits import UnifiedError

STRAIGHT = [('lea', 0x2040), ('call', 0x1100), ('cmp', 7), ('mov',), ('ret',)]


def build(tmp_path, name='b'):
    callee = function(0x1100, [('mov',), ('ret',)], name='callee')
    caller = function(0x1000, STRAIGHT, name='caller', calls=[(0x1007, 0x1100, None, 'call')],
                      strings=[(0x1000, 'ab' * 32, 4, 'text')], aliases=['alias_one'])
    path = write_jsonl(tmp_path / f'{name}.jsonl', document_set(caller, callee))
    out = tmp_path / f'out-{name}'
    out.mkdir()
    return ingest(path, ExpectedSide('older', SHA, pe_view(), mode='analyze'), out_dir=out)


def test_reader_loads_columns_adjacency_and_on_demand_rows(tmp_path):
    result = build(tmp_path)
    with_reader = IrReader.open(result.directory)
    try:
        table = with_reader.functions
        assert table.n == 2 and list(table.rva) == [0x1000, 0x1100] and table.name == ['caller', 'callee']
        assert table.aliases[0] == ('alias_one',) and table.rva_to_fid == {0x1000: 0, 0x1100: 1}
        assert table.get('h1', 0) is not None and table.get('md_td', 0) is None and table.md_td[0] == NULL_KEY
        assert list(with_reader.callees(0)) == [1] and list(with_reader.callers(1)) == [0]
        assert with_reader.call_edges() == [(0, 1)]
        assert [r.callee for r in with_reader.calls(0)] == [1]
        assert with_reader.strings(0)[0].prefix == 'text' and with_reader.constants(0)[0].value == 7
        kinds = [r.kind for r in with_reader.refs(0)]
        assert kinds == ['data', 'code']
        insns = with_reader.instructions(0)
        assert [i.mnem for i in insns] == ['LEA', 'CALL', 'CMP', 'MOV', 'RET']
        assert insns[0].ops[1].vkind == 4 and insns[0].ops[1].value == 0x2040 and insns[0].ops[1].length == 4
        assert insns[1].flags & 1 and insns[4].flags & 8 and insns[2].ops[1].value == 7
        assert with_reader.texts(0)[:2] == ['LEA #0', 'CALL #1']
        assert with_reader.mnemonics() == sorted({'LEA', 'CALL', 'CMP', 'MOV', 'RET'})
    finally:
        with_reader.close()


def test_reader_verifies_the_manifest_and_file_hash(tmp_path):
    result = build(tmp_path)
    database = result.directory / schema.DB_NAME
    database.write_bytes(database.read_bytes() + b'\0')                       # tampered after publish
    with pytest.raises(UnifiedError) as caught:
        IrReader.open(result.directory)
    assert caught.value.code == 'PT-UNIFIED-STORE' and caught.value.reason == 'ir-file-hash'


def test_reader_refuses_a_newer_contract_and_a_missing_manifest(tmp_path):
    result = build(tmp_path)
    manifest = result.directory / schema.MANIFEST_NAME
    document = json.loads(manifest.read_text(encoding='utf-8'))
    document['contract'] = 'program-ir/2'
    manifest.write_text(json.dumps(document), encoding='utf-8')
    with pytest.raises(UnifiedError) as caught:
        read_manifest(result.directory)
    assert caught.value.code == 'PT-UNIFIED-STALE' and caught.value.reason == 'newer-contract'
    manifest.unlink()
    with pytest.raises(UnifiedError) as caught:
        read_manifest(result.directory)
    assert caught.value.reason == 'manifest-missing'


def test_ir_reader_refuses_writable_or_tampered_file(tmp_path):
    result = build(tmp_path)
    database = result.directory / schema.DB_NAME
    db = schema.open_readonly(database)
    for statement in ('INSERT INTO fn(fid) VALUES (9)', 'DELETE FROM mnem', 'CREATE TABLE x(a)', 'DROP TABLE fn',
                      "ATTACH DATABASE ':memory:' AS other", 'PRAGMA writable_schema=1', 'UPDATE meta SET value=1'):
        with pytest.raises(sqlite3.DatabaseError):
            db.execute(statement)
    with pytest.raises(sqlite3.DatabaseError):
        db.execute('SELECT load_extension("x")')
    assert db.execute('SELECT COUNT(*) FROM fn').fetchone()[0] == 2
    db.close()
    database.write_bytes(b'not a database' + b'\0' * 100)
    with pytest.raises(UnifiedError) as caught:
        schema.open_readonly(database)
    assert caught.value.reason == 'ir-not-sqlite'


def test_a_database_missing_tables_is_refused(tmp_path):
    path = tmp_path / 'x.sqlite3'
    connection = sqlite3.connect(path)
    connection.execute('CREATE TABLE meta(key TEXT, value TEXT)')
    connection.commit()
    connection.close()
    with pytest.raises(UnifiedError) as caught:
        schema.open_readonly(path)
    assert caught.value.reason == 'ir-schema'


def test_decompression_is_bounded(tmp_path):
    bomb = schema.compress(b'\0' * (2 * 1024 * 1024))
    with pytest.raises(UnifiedError) as caught:
        schema.decompress(bomb, 1024 * 1024)
    assert caught.value.code == 'PT-UNIFIED-LIMIT' and caught.value.reason == 'blob-too-large'
    with pytest.raises(UnifiedError) as caught:
        schema.decompress(b'garbage')
    assert caught.value.reason == 'blob-invalid'
    with pytest.raises(UnifiedError) as caught:
        ins_module.decode_instructions(schema.compress(b'["ins/2"]'))
    assert caught.value.reason == 'ins-invalid'


def test_reader_without_a_database_serves_builders(tmp_path):
    reader = IrReader.from_columns({'rva': [0x1000, 0x1100, 0x1200], 'h1': [5, 5, None], 'n_insn': [9, 9, 3]},
                                   names=['a', 'b', 'c'], calls=[(0, 1), (0, 1), (2, 0)])
    assert isinstance(reader.functions, FunctionTable) and reader.functions.n == 3
    assert list(reader.functions.h1) == [5, 5, NULL_KEY] and reader.functions.get('h1', 2) is None
    assert list(reader.callees(0)) == [1] and list(reader.callers(0)) == [2] and list(reader.callees(1)) == []
    assert reader.functions.rva_to_fid[0x1200] == 2
    with pytest.raises(UnifiedError) as caught:
        reader.blocks(0)
    assert caught.value.reason == 'no-database'


# --- placement --------------------------------------------------------------------------------------------------------

def test_place_ir_moves_a_verified_directory_to_its_content_addressed_place(tmp_path):
    result = build(tmp_path)
    root = tmp_path / 'project'
    key = result.manifest.ir_key
    final = place.place_ir(root, 'run-1', result.directory)
    assert final == root / 'runs' / 'run-1' / 'unified' / 'ir' / key[:16] and not result.directory.exists()
    assert place.find_ir(root, 'run-1', key) == final and place.find_ir(root, 'run-2', key) is None
    reader = IrReader.open(final)
    assert reader.manifest.ir_key == key
    reader.close()


def test_place_ir_is_idempotent_and_replaces_a_corrupt_leftover(tmp_path):
    first = build(tmp_path, 'one')
    root = tmp_path / 'project'
    final = place.place_ir(root, 'run-1', first.directory)
    again = build(tmp_path, 'two')                                         # the same key built a second time
    assert place.place_ir(root, 'run-1', again.directory) == final and not again.directory.exists()
    (final / schema.DB_NAME).write_bytes(b'corrupt')
    assert place.find_ir(root, 'run-1', first.manifest.ir_key) is None     # a miss, never a crash
    third = build(tmp_path, 'three')
    assert place.place_ir(root, 'run-1', third.directory) == final
    assert place.find_ir(root, 'run-1', first.manifest.ir_key) == final


def test_place_ir_refuses_unverified_directories_and_bad_identities(tmp_path):
    result = build(tmp_path)
    (result.directory / 'extra.txt').write_text('x')
    with pytest.raises(UnifiedError) as caught:
        place.place_ir(tmp_path / 'project', 'run-1', result.directory)
    assert caught.value.reason == 'unexpected-files'
    with pytest.raises(UnifiedError):
        place.ir_relative_dir('../escape', 'a' * 64)
    with pytest.raises(UnifiedError):
        place.ir_relative_dir('run', 'short')
    assert place.find_ir(tmp_path / 'project', '../x', 'a' * 64) is None


def test_function_table_array_columns_are_int64():
    reader = IrReader.from_columns({'rva': [1, 2]})
    assert isinstance(reader.functions.rva, array) and reader.functions.rva.typecode == 'q'
