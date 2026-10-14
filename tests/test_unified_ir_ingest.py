"""SPEC-31 S1: ingest of the extractor's untrusted JSON Lines into the `program-ir/1` sidecar (03 s5, s12).

Synthetic documents come from tests/unified_extract_builder.py; the recorded fixtures under tests/fixtures/unified/
are REAL Ghidra 12.0.4 output of clang/MinGW-built PEs (provenance: PROVENANCE.json there). Everything runs without
Ghidra or Java."""
from __future__ import annotations

import json
import shutil
import sqlite3
import threading
from array import array
from pathlib import Path

import pytest
from unified_extract_builder import (
    BASE,
    SHA,
    SIZE,
    document_set,
    footer,
    function,
    header,
    pe_view,
    write_jsonl,
)

from patchtrace.unified.ir import schema
from patchtrace.unified.ir.ingest import ExpectedSide, ingest
from patchtrace.unified.ir.pe_tables import PeTables, Primary, Section
from patchtrace.unified.ir.reader import IrReader
from patchtrace.unified.limits import DEFAULT_LIMITS, Budget, BudgetExhausted, UnifiedError, UnifiedLimits

FIXTURES = Path(__file__).parent / 'fixtures' / 'unified'
STRAIGHT = [('mov',), ('mov',), ('cmp', 5), ('mov',), ('mov',), ('movimm', 70000), ('ret',)]
FIVE_BLOCKS = [('cmp', 1), ('jcc', 0x100d), ('mov',), ('jcc', 0x100d), ('mov',), ('jmp', 0x100f), ('mov',), ('ret',)]
FIVE_LAYOUT = [(0, [3, 1], ['cond', 'fall']), (2, [3, 2], ['cond', 'fall']), (4, [4], ['jump']), (6, [4], ['fall']),
               (7, [], [])]


def run(tmp_path, documents, *, expect=None, limits=DEFAULT_LIMITS, budget=None, name='ir.jsonl', raw_text=None):
    path = tmp_path / name
    if raw_text is not None:
        path.write_text(raw_text, encoding='utf-8', newline='\n')
    else:
        write_jsonl(path, documents)
    out = tmp_path / ('out-' + name)
    out.mkdir()
    return ingest(path, expect or ExpectedSide('older', SHA, pe_view(), mode='analyze'), limits, budget, out_dir=out)


def query(result, sql, args=()):
    db = schema.open_readonly(result.directory / schema.DB_NAME)
    try:
        return db.execute(sql, args).fetchall()
    finally:
        db.close()


def fn_row(result, name):
    columns = schema.COLUMNS['fn']
    (row,) = query(result, f'SELECT {", ".join(columns)} FROM fn WHERE name=?', (name,))
    return dict(zip(columns, row, strict=True))


def pe_from_json(path):
    data = json.loads(path.read_text(encoding='utf-8'))
    tables = PeTables(image_base=data['image_base'], size_of_image=data['size_of_image'],
                      sections=tuple(Section(n, a, b, e) for n, a, b, e in data['sections']),
                      relocs=array('I', data['relocs']), warnings=list(data['warnings']))
    for begin, item in data['primaries'].items():
        tables.primaries[int(begin)] = Primary(int(begin), item['end'], item['unwind'], [tuple(c) for c in item['chunks']])
        tables.eh[int(begin)] = item['eh']
    return tables


def recorded(tmp_path, stem, mode='analyze'):
    pe_path = FIXTURES / f'{stem}.pe.json'
    data = json.loads(pe_path.read_text(encoding='utf-8'))
    out = tmp_path / stem
    out.mkdir()
    return ingest(FIXTURES / f'{stem}.ir.jsonl', ExpectedSide('older', data['sha256'], pe_from_json(pe_path), mode=mode),
                  out_dir=out)


# --- recorded real output ---------------------------------------------------------------------------------------------

def test_recorded_probe_pair_keys_show_what_each_level_hides(tmp_path):
    old, new = recorded(tmp_path, 'probe_old'), recorded(tmp_path, 'probe_new')
    assert old.manifest.counts.functions == new.manifest.counts.functions == 7
    assert old.manifest.warnings == () and old.manifest.limits_hit == ()
    same = {}
    for name in ('add_clamped', 'dispatch', 'use_data', 'say', 'tick', 'loop_sum', 'limit_check'):
        a, b = fn_row(old, name), fn_row(new, name)
        same[name] = tuple(a[k] == b[k] for k in ('h0', 'h1', 'h2', 'h3', 'hms'))
    # an edited constant: bytes and L1 differ, L2 (immediates masked) and L3 are equal
    assert same['add_clamped'] == (False, False, True, True, True)
    assert same['dispatch'] == (False, False, True, True, True)
    # data moved by the new global: RIP-relative displacements changed, L1 masks them, so only h0 differs
    assert same['say'][:2] == (False, True) and same['tick'][:2] == (False, True)
    assert all(same['say']) is False and same['say'][2:] == (True, True, True)
    # untouched position-independent code is identical at every level, although it moved
    assert same['loop_sum'] == (True,) * 5 and same['limit_check'][0] is True
    assert fn_row(old, 'loop_sum')['rva'] != fn_row(new, 'loop_sum')['rva']
    # a real edit (guard added, new global read) differs at every level
    assert not any(same['use_data'][:3])


def test_recorded_probe_golden_digest_and_counts(tmp_path):
    old = recorded(tmp_path, 'probe_old')
    c = old.manifest.counts
    assert (c.functions, c.blocks, c.instructions, c.strings, c.mask_unlocated, c.pdata_confirmed) == (7, 26, 108, 2, 0, 0)
    assert old.manifest.content_digest == schema.content_digest(schema.open_readonly(old.directory / schema.DB_NAME))
    golden = json.loads((FIXTURES / 'golden.json').read_text(encoding='utf-8'))
    assert old.manifest.content_digest == golden['probe_old']['content_digest']      # same value on Linux and Windows
    for name, keys in golden['probe_old']['functions'].items():
        row = fn_row(old, name)
        assert {k: row[k] for k in keys} == keys, name


def test_recorded_mingw_fixture_thunks_imports_chunks_and_pdata(tmp_path):
    result = recorded(tmp_path, 'mingw_old')
    c = result.manifest.counts
    assert c.thunks == 23 and c.imports == 22 and c.pdata_confirmed == 38 and c.mask_unlocated == 0
    sleep = fn_row(result, 'Sleep')
    assert sleep['kind'] == 1 and sleep['import_key'] == 'kernel32.dll!Sleep' and sleep['flags'] & 2 and sleep['flags'] & 4
    chunks = fn_row(result, '_CRT_INIT')
    # ten Ghidra ranges separated by alignment padding, one .pdata entry: confirmed
    assert chunks['extent_src'] == 1 and chunks['size'] > 300 and chunks['flags'] & schema.FN_FLAGS['pdata-confirmed']
    assert query(result, "SELECT COUNT(*) FROM call WHERE import_key='kernel32.dll!Sleep'")[0][0] >= 1
    assert result.manifest.counts.call_edges > 0


# --- semantics of the derived columns ---------------------------------------------------------------------------------

def test_nop_family_and_trailing_int3_do_not_change_keys_but_change_bytes(tmp_path):
    plain = function(0x1000, STRAIGHT, name='plain')
    padded = function(0x1100, [STRAIGHT[0], ('nop',), STRAIGHT[1], ('nop',), ('nop',), *STRAIGHT[2:], ('int3',),
                               ('int3',)], name='padded')
    result = run(tmp_path, document_set(plain, padded))
    a, b = fn_row(result, 'plain'), fn_row(result, 'padded')
    assert a['h0'] != b['h0'] and a['n_insn'] == 7 and b['n_insn'] == 12
    for key in ('h1', 'h2', 'h3', 'hm', 'hms'):
        assert a[key] == b[key], key


def test_int3_before_the_last_ret_is_not_padding(tmp_path):
    a = function(0x1000, [('mov',), ('int3',), ('ret',)], name='a')
    b = function(0x1100, [('mov',), ('ret',)], name='b')
    result = run(tmp_path, document_set(a, b))
    assert fn_row(result, 'a')['hm'] != fn_row(result, 'b')['hm']


def test_tiny_functions_are_flagged_and_all_nop_functions_have_no_content_keys(tmp_path):
    tiny = function(0x1000, [('mov',), ('ret',)], name='tiny')
    big = function(0x1100, STRAIGHT, name='big')
    empty = function(0x1200, [('nop',), ('nop',)], name='empty')
    result = run(tmp_path, document_set(tiny, big, empty))
    assert fn_row(result, 'tiny')['flags'] & schema.FN_FLAGS['tiny'] and not fn_row(result, 'big')['flags'] & 1
    row = fn_row(result, 'empty')
    assert row['h0'] is not None and all(row[k] is None for k in ('h1', 'h2', 'h3', 'hm', 'hms'))


def test_missing_instruction_mask_makes_h3_null_and_flags_mask_missing(tmp_path):
    f = function(0x1000, STRAIGHT, name='f')
    f['insns'][1][3] = None
    result = run(tmp_path, document_set(f))
    row = fn_row(result, 'f')
    assert row['h3'] is None and row['h1'] is not None and row['flags'] & schema.FN_FLAGS['mask-missing']


def test_unlocated_address_operand_flags_the_function_and_is_counted(tmp_path):
    f = function(0x1000, [('lea', 0x2000), ('ret',)], name='f')
    raw = bytearray(bytes.fromhex(f['raw']))
    raw[3] ^= 0x01                                  # the encoded displacement no longer matches the target
    f['raw'] = raw.hex()
    result = run(tmp_path, document_set(f))
    assert fn_row(result, 'f')['flags'] & schema.FN_FLAGS['mask-unlocated'] and result.manifest.counts.mask_unlocated == 1


def test_l1_and_l2_levels_mask_only_located_fields(tmp_path):
    a = function(0x1000, [('lea', 0x2000), ('cmp', 5), ('ret',)], name='a')
    b = function(0x1100, [('lea', 0x2040), ('cmp', 9), ('ret',)], name='b')      # other global, other immediate
    c = function(0x1200, [('lea', 0x2040), ('cmp', 5), ('ret',)], name='c')
    result = run(tmp_path, document_set(a, b, c))
    ra, rb, rc = (fn_row(result, n) for n in 'abc')
    assert ra['h1'] == rc['h1'] and ra['h1'] != rb['h1']          # address masked at L1, the immediate is not
    assert ra['h2'] == rb['h2'] == rc['h2']                       # immediates masked at L2
    assert len({ra['h0'], rb['h0'], rc['h0']}) == 3


def test_blocks_edges_loops_md_and_the_terminator_free_body_key(tmp_path):
    f = function(0x1000, FIVE_BLOCKS, name='five', blocks=FIVE_LAYOUT)
    four = function(0x1100, FIVE_BLOCKS[:2] + FIVE_BLOCKS[4:], name='four')     # shape irrelevant: 1 block, md NULL
    result = run(tmp_path, document_set(f, four))
    row = fn_row(result, 'five')
    assert (row['n_bb'], row['n_edge'], row['loops']) == (5, 6, 0)
    assert row['md_td'] is not None and row['md_bu'] is not None
    assert fn_row(result, 'four')['md_td'] is None
    blocks = query(result, 'SELECT ord, rva, n_insn, succ FROM bb WHERE fid=0 ORDER BY ord')
    assert [b[:3] for b in blocks] == [(0, 0x1000, 2), (1, 0x1005, 2), (2, 0x1009, 2), (3, 0x100d, 1), (4, 0x100f, 1)]
    assert json.loads(blocks[0][3]) == [[1, 0], [3, 2]]            # successors sorted by target: fall -> 1, cond -> 3
    reader = IrReader.open(result.directory)
    assert [b.succ for b in reader.blocks(0)][0] == ((1, 'fall'), (3, 'cond'))
    reader.close()


def test_block_body_key_ignores_the_terminating_branch_polarity_and_target(tmp_path):
    a = function(0x1000, FIVE_BLOCKS, name='a', blocks=FIVE_LAYOUT)
    b = function(0x1100, FIVE_BLOCKS, name='b', blocks=FIVE_LAYOUT)
    b['insns'][1][2] = 'JNZ'                                   # the block-0 terminator becomes a JNZ (jcc inverted)
    raw = bytearray(bytes.fromhex(b['raw']))
    raw[3] = 0x75
    b['raw'] = raw.hex()
    result = run(tmp_path, document_set(a, b))
    bodies_a = query(result, 'SELECT h1 FROM bb WHERE fid=0 ORDER BY ord')
    bodies_b = query(result, 'SELECT h1 FROM bb WHERE fid=1 ORDER BY ord')
    assert bodies_a[0] == bodies_b[0]                          # block 0 body = CMP only, the terminator is excluded
    assert fn_row(result, 'a')['h1'] != fn_row(result, 'b')['h1']          # but the whole function still differs


def test_loops_count_back_edges(tmp_path):
    specs = [('cmp', 1), ('jcc', 0x1000), ('ret',)]
    f = function(0x1000, specs, name='loop', blocks=[(0, [0, 1], ['cond', 'fall']), (2, [], [])])
    result = run(tmp_path, document_set(f))
    row = fn_row(result, 'loop')
    assert row['loops'] == 1 and row['n_edge'] == 2


def test_calls_are_resolved_to_function_ids_imports_and_unresolved(tmp_path):
    caller = function(0x1000, [('call', 0x1100), ('call', 0x1103), ('iatcall', 0x2100, 'kernel32.dll!Sleep'), ('ret',)],
                      name='caller', calls=[(0x1000, 0x1100, None, 'call'), (0x1005, 0x1103, None, 'call'),
                                            (0x100a, None, 'kernel32.dll!Sleep', 'call'), (0x1010, None, None, 'call')])
    callee = function(0x1100, [('mov',), ('ret',)], name='callee')
    result = run(tmp_path, document_set(caller, callee))
    rows = query(result, 'SELECT site, callee, import_key, kind FROM call WHERE fid=0 ORDER BY site')
    assert rows == [(0x1000, 1, None, 0), (0x1005, None, None, 0), (0x100a, None, 'kernel32.dll!Sleep', 0),
                    (0x1010, None, None, 0)]
    assert fn_row(result, 'caller')['n_call'] == 4 and result.manifest.counts.call_edges == 1
    reader = IrReader.open(result.directory)
    assert list(reader.callees(0)) == [1] and list(reader.callers(1)) == [0] and list(reader.callers(0)) == []
    reader.close()


def test_import_thunks_carry_the_import_key_and_flags(tmp_path):
    thunk = function(0x1000, [('ret',)], name='Sleep', kind='thunk', imp={'dll': 'KERNEL32.DLL', 'name': 'Sleep',
                                                                         'ordinal': None})
    ordinal = function(0x1100, [('ret',)], name='ord', kind='thunk', imp={'dll': 'user32.dll', 'name': None,
                                                                         'ordinal': 12})
    result = run(tmp_path, document_set(thunk, ordinal))
    assert fn_row(result, 'Sleep')['import_key'] == 'kernel32.dll!Sleep'
    assert fn_row(result, 'ord')['import_key'] == 'user32.dll!#12'
    assert result.manifest.counts.thunks == 2 and result.manifest.counts.imports == 2


def test_references_constants_and_strings_become_rows(tmp_path):
    f = function(0x1000, [('lea', 0x2040), ('call', 0x1200), ('cmp', 6), ('iatcall', 0x2100, 'kernel32.dll!Sleep'),
                          ('ret',)], name='f',
                 strings=[(0x1000, 'ab' * 32, 11, 'hello world')])
    result = run(tmp_path, document_set(f))
    refs = query(result, 'SELECT ord, opi, kind, target, import_key FROM ref WHERE fid=0 ORDER BY ord, opi, kind')
    assert refs == [(0, 1, 1, 0x2040, None), (1, 0, 0, 0x1200, None), (3, 0, 2, None, 'kernel32.dll!Sleep')]
    assert query(result, 'SELECT site, value, ctx FROM cst') == [(0x100c, 6, 1)]      # CMP is the compare context
    assert query(result, 'SELECT site, sha, len, prefix FROM str') == [(0x1000, 'ab' * 32, 11, 'hello world')]
    assert result.manifest.counts.refs == 3 and result.manifest.counts.consts == 1


def test_pdata_extent_and_eh_are_taken_from_the_pe_tables(tmp_path):
    f = function(0x1000, STRAIGHT, name='f')
    length = f['ranges'][0][1]
    pe = pe_view(primaries={0x1000: (0x1000 + length, [])}, eh={0x1000: '{"v":1,"x":1}'})
    result = run(tmp_path, document_set(f), expect=ExpectedSide('older', SHA, pe, mode='analyze'))
    row = fn_row(result, 'f')
    assert row['extent_src'] == 1 and row['flags'] & schema.FN_FLAGS['pdata-confirmed'] and row['eh'] == '{"v":1,"x":1}'
    assert result.manifest.counts.pdata_confirmed == 1
    conflict = pe_view(primaries={0x1000: (0x1000 + length + 0x40, [])})
    other = run(tmp_path, document_set(function(0x1000, STRAIGHT, name='f')), name='c.jsonl',
                expect=ExpectedSide('older', SHA, conflict, mode='analyze'))
    assert fn_row(other, 'f')['extent_src'] == 2 and fn_row(other, 'f')['eh'] is None


def test_names_are_sanitised_and_counted(tmp_path):
    f = function(0x1000, STRAIGHT, name='bad\x01name‮', aliases=['al\x07ias'])
    result = run(tmp_path, document_set(f))
    row = query(result, 'SELECT name, aliases FROM fn')[0]
    assert row[0] == 'bad?name?' and json.loads(row[1]) == ['al?ias']
    assert any('sanitized-text-fields: 2' in w for w in result.manifest.warnings)


def test_oversize_and_truncated_functions_keep_a_row_with_flags_and_null_keys(tmp_path):
    over = function(0x1000, STRAIGHT, name='over')
    over.update(raw=None, insns=[], text=[], blocks=[], calls=[], strings=[])
    cut = function(0x1100, STRAIGHT, name='cut')
    cut.update(raw=None, insns=[], text=[], blocks=[], calls=[], strings=[], truncated=True)
    result = run(tmp_path, document_set(over, cut))
    a, b = fn_row(result, 'over'), fn_row(result, 'cut')
    assert a['flags'] & schema.FN_FLAGS['oversize'] and b['flags'] & schema.FN_FLAGS['truncated']
    assert a['h0'] is None and b['h1'] is None and a['n_bb'] == 0
    assert set(result.manifest.limits_hit) == {'fn-oversize', 'fn-truncated'}


def test_unknown_name_source_ai_is_accepted(tmp_path):
    result = run(tmp_path, document_set(function(0x1000, STRAIGHT, name='ai', name_src='AI')))
    assert fn_row(result, 'ai')['name_src'] == 4


# --- determinism ------------------------------------------------------------------------------------------------------

def test_ingest_is_deterministic_under_record_permutation_of_equal_keys(tmp_path):
    base = [function(0x1000, STRAIGHT, name='f', aliases=['b', 'a'],
                     calls=[(0x1000, None, 'a.dll!x', 'call'), (0x1003, None, 'b.dll!y', 'call')],
                     strings=[(0x1000, 'aa' * 32, 3, 'abc'), (0x1002, 'bb' * 32, 2, 'xy')])]
    shuffled = [function(0x1000, STRAIGHT, name='f', aliases=['a', 'b'],
                         calls=[(0x1003, None, 'b.dll!y', 'call'), (0x1000, None, 'a.dll!x', 'call')],
                         strings=[(0x1002, 'bb' * 32, 2, 'xy'), (0x1000, 'aa' * 32, 3, 'abc')])]
    one = run(tmp_path, document_set(*base), name='one.jsonl')
    two = run(tmp_path, document_set(*shuffled), name='two.jsonl')
    assert one.manifest.content_digest == two.manifest.content_digest and one.manifest.ir_key == two.manifest.ir_key


def test_content_digest_independent_of_sqlite_file_bytes(tmp_path):
    result = run(tmp_path, document_set(function(0x1000, FIVE_BLOCKS, blocks=FIVE_LAYOUT)))
    copy = tmp_path / 'copy.sqlite3'
    shutil.copy(result.directory / schema.DB_NAME, copy)
    db = sqlite3.connect(copy)
    db.execute('PRAGMA page_size=8192')
    db.execute('VACUUM')                                         # different page layout, same rows
    db.close()
    assert copy.read_bytes() != (result.directory / schema.DB_NAME).read_bytes()
    reopened = sqlite3.connect(copy)
    assert schema.content_digest(reopened) == result.manifest.content_digest
    reopened.close()


def test_same_input_gives_same_digest_and_a_changed_input_gives_another(tmp_path):
    docs = document_set(function(0x1000, STRAIGHT, name='f'))
    a, b = run(tmp_path, docs, name='a.jsonl'), run(tmp_path, docs, name='b.jsonl')
    assert a.manifest.content_digest == b.manifest.content_digest
    changed = document_set(function(0x1000, STRAIGHT[:-2] + [('movimm', 71000), ('ret',)], name='f'))
    assert run(tmp_path, changed, name='c.jsonl').manifest.content_digest != a.manifest.content_digest


def test_ir_key_depends_on_producer_facts_but_not_on_matching_limits(tmp_path):
    docs = document_set(function(0x1000, STRAIGHT, name='f'))
    base = run(tmp_path, docs, name='a.jsonl')
    tuned = UnifiedLimits(l16_set_min_elements=3, l19_implied_min_votes=3)             # ladder thresholds only
    assert run(tmp_path, docs, limits=tuned, name='b.jsonl').manifest.ir_key == base.manifest.ir_key
    ingest_limit = UnifiedLimits(l11_md_min_blocks=6)
    assert run(tmp_path, docs, limits=ingest_limit, name='c.jsonl').manifest.ir_key != base.manifest.ir_key
    other = document_set(function(0x1000, STRAIGHT, name='f'), ghidra='12.0.5')
    assert run(tmp_path, other, name='d.jsonl').manifest.ir_key != base.manifest.ir_key


# --- strict rejection -------------------------------------------------------------------------------------------------

def raw_lines(documents, edit=None):
    lines = [json.dumps(d, separators=(',', ':')) for d in documents]
    if edit:
        edit(lines)
    return '\n'.join(lines) + '\n'


def good():
    return document_set(function(0x1000, STRAIGHT, name='f'), function(0x1100, STRAIGHT, name='g'))


CASES = {
    'extra-key': ('PT-UNIFIED-IR', 'bad-record-keys'),
    'nan': ('PT-UNIFIED-IR', 'bad-record-json'),
    'dup-key': ('PT-UNIFIED-IR', 'bad-record-json'),
    'float': ('PT-UNIFIED-IR', 'bad-record-json'),
    'bool-rva': ('PT-UNIFIED-IR', 'bad-record-rva'),
    'order': ('PT-UNIFIED-IR', 'fn-order'),
    'no-footer': ('PT-UNIFIED-IR', 'no-footer'),
    'footer-count': ('PT-UNIFIED-IR', 'footer-mismatch'),
    'range-out': ('PT-UNIFIED-IR', 'bad-record-ranges'),
    'bad-hex': ('PT-UNIFIED-IR', 'bad-record-raw'),
    'insn-overlap': ('PT-UNIFIED-IR', 'bad-record-insns'),
    'block-cnt': ('PT-UNIFIED-IR', 'bad-record-blocks'),
    'trailing': ('PT-UNIFIED-IR', 'trailing-data'),
    'no-newline': ('PT-UNIFIED-IR', 'truncated'),
    'wrong-sha': ('PT-UNIFIED-PAIR', 'artifact-hash'),
    'reversed': ('PT-UNIFIED-ORIENTATION', 'reversed-side'),
    'base-moved': ('PT-UNIFIED-IR', 'image-base-mismatch'),
    'unanalyzed': ('PT-UNIFIED-EXTRACT', 'gzf-not-analyzed'),
    'not-x64': ('PT-UNIFIED-UNSUPPORTED', 'unsupported-language'),
    'mode': ('PT-UNIFIED-IR', 'mode-mismatch'),
    'partial': ('PT-UNIFIED-LIMIT', 'functions-cap'),
}


@pytest.mark.parametrize('case', sorted(CASES))
def test_ingest_rejects(tmp_path, case):
    docs = good()
    expect = ExpectedSide('older', SHA, pe_view(), mode='analyze', other_sha256='99' * 32)
    text = None
    if case == 'extra-key':
        docs[1]['bogus'] = 1
    elif case == 'nan':
        text = raw_lines(docs).replace('"rva":4096', '"rva":NaN', 1)
    elif case == 'dup-key':
        text = raw_lines(docs).replace('"type":"fn","rva":4096', '"type":"fn","rva":4096,"rva":4096', 1)
    elif case == 'float':
        docs[1]['rva'] = 4096.5
    elif case == 'bool-rva':
        docs[1]['rva'] = True
    elif case == 'order':
        docs[1], docs[2] = docs[2], docs[1]
    elif case == 'no-footer':
        docs = docs[:-1]
    elif case == 'footer-count':
        docs[-1]['functions'] = 5
    elif case == 'range-out':
        docs[1]['ranges'] = [[SIZE - 4, 100]]
    elif case == 'bad-hex':
        docs[1]['raw'] = docs[1]['raw'][:-1]
    elif case == 'insn-overlap':
        docs[1]['insns'][2][0] -= 1
    elif case == 'block-cnt':
        docs[1]['blocks'][0][2] += 1
    elif case == 'trailing':
        docs.append(footer(2, 14))
    elif case == 'no-newline':
        text = raw_lines(docs).rstrip('\n')
    elif case == 'wrong-sha':
        expect = ExpectedSide('older', 'cd' * 32, pe_view(), mode='analyze')
    elif case == 'reversed':
        expect = ExpectedSide('older', '99' * 32, pe_view(), mode='analyze', other_sha256=SHA)
    elif case == 'base-moved':
        docs[0]['image_base'] = BASE + 0x10000
    elif case == 'unanalyzed':
        docs[0]['producer']['analyzed'] = False
    elif case == 'not-x64':
        docs[0]['language'] = 'x86:LE:32:default'
    elif case == 'mode':
        expect = ExpectedSide('older', SHA, pe_view(), mode='gzf')
    elif case == 'partial':
        docs[-1].update(status='partial', warnings=['functions-cap:1'])
    code, reason = CASES[case]
    with pytest.raises(UnifiedError) as caught:
        run(tmp_path, docs, expect=expect, raw_text=text)
    assert (caught.value.code, caught.value.reason) == (code, reason)


def test_limits_are_enforced_with_their_reasons(tmp_path):
    docs = good()
    with pytest.raises(UnifiedError) as caught:
        run(tmp_path, docs, limits=UnifiedLimits(l01_functions_per_side=1), name='l1.jsonl')
    assert caught.value.reason == 'functions-cap' and caught.value.code == 'PT-UNIFIED-LIMIT'
    with pytest.raises(UnifiedError) as caught:
        run(tmp_path, docs, limits=UnifiedLimits(l02_instructions_per_side=10, l02_warn_instructions=5), name='l2.jsonl')
    assert caught.value.reason == 'instructions-cap'
    with pytest.raises(UnifiedError) as caught:
        run(tmp_path, docs, limits=UnifiedLimits(l05_line_bytes=200), name='l5.jsonl')
    assert caught.value.reason == 'line-too-long'
    with pytest.raises(UnifiedError) as caught:
        run(tmp_path, docs, limits=UnifiedLimits(l05_output_bytes=200), name='l5o.jsonl')
    assert caught.value.reason == 'output-limit'
    with pytest.raises(UnifiedError) as caught:
        run(tmp_path, docs, limits=UnifiedLimits(l07_ir_file_bytes=4096), name='l7.jsonl')
    assert caught.value.reason == 'ir-too-large'


def test_missing_or_symlinked_output_is_refused(tmp_path):
    out = tmp_path / 'out'
    out.mkdir()
    with pytest.raises(UnifiedError) as caught:
        ingest(tmp_path / 'absent.jsonl', ExpectedSide('older', SHA, pe_view()), out_dir=out)
    assert caught.value.reason == 'no-output'
    real = write_jsonl(tmp_path / 'real.jsonl', good())
    link = tmp_path / 'link.jsonl'
    try:
        link.symlink_to(real)
    except OSError:
        pytest.skip('symlinks are not available on this runner')
    with pytest.raises(UnifiedError):
        ingest(link, ExpectedSide('older', SHA, pe_view()), out_dir=out)


def test_expected_producer_facts_are_enforced(tmp_path):
    docs = good()
    for label, kwargs, reason in (('opt', {'analysis_options_digest': '11' * 32}, 'options-digest-mismatch'),
                                  ('script', {'script_sha256': '22' * 32}, 'script-mismatch'),
                                  ('sym', {'symbols': 'primary'}, 'symbols-mismatch')):
        with pytest.raises(UnifiedError) as caught:
            run(tmp_path, docs, expect=ExpectedSide('older', SHA, pe_view(), mode='analyze', **kwargs),
                name=f'{label}.jsonl')
        assert caught.value.reason == reason


def test_cancel_and_deadline_stop_the_ingest(tmp_path):
    cancel = threading.Event()
    cancel.set()
    with pytest.raises(BudgetExhausted) as caught:
        run(tmp_path, good(), budget=Budget(None, cancel, check_every=1), name='c.jsonl')
    assert caught.value.code == 'PT-UNIFIED-CANCEL'
    with pytest.raises(BudgetExhausted) as caught:
        run(tmp_path, good(), budget=Budget(0.0, None, check_every=1, clock=lambda: 1.0), name='d.jsonl')
    assert caught.value.code == 'PT-UNIFIED-TIMEOUT'


def test_header_helper_defaults_are_consistent():
    assert header()['producer']['symbols'] == 'none' and header(mode='gzf')['producer']['symbols'] == 'primary'
