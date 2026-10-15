"""WB1 S9: group ir:<side> over a fake IrReader (all functions, masked asm, constants hex + decimal, 100k gate)."""
from __future__ import annotations

import time
from types import SimpleNamespace

import pytest

from patchtrace.search.query import parse_query
from patchtrace.search.segment import Flag, build_segment, open_segment
from patchtrace.search.sources.unified import NO_IR, constant_words, unified_spec
from patchtrace.unified.ir.ins import Insn
from patchtrace.unified.ir.reader import ConstRow, IrReader


class FakeReader:
    """The IrPort surface over in-memory rows; the function table is the real `FunctionTable`."""

    def __init__(self, rvas, names, asm=None, consts=None):
        self.functions = IrReader.from_columns({'rva': rvas}, names=names).functions
        self.manifest = SimpleNamespace(ir_key='k' * 16)
        self._asm, self._consts = asm or {}, consts or {}

    def texts(self, fid):
        return [t for t, _ in self._asm.get(fid, [])]

    def instructions(self, fid):
        return [Insn(0, b'', m, 0, 'fall', ()) for _, m in self._asm.get(fid, [])]

    def constants(self, fid):
        return [ConstRow(0, v, 0) for v in self._consts.get(fid, [])]


def small_reader():
    return FakeReader(
        [0x1000, 0x2000, 0x3000], ['ProbeForRead', None, 'ValidateLength'],
        asm={0: [('mov eax, [ptr]', 'MOV'), ('cmp eax, 0x2a', 'CMP'), ('ret', 'RET')],
             2: [('sub rsp, 0x28', 'SUB')]},
        consts={0: [42, 4096, -1], 2: [40]})


def docs(spec):
    return list(spec.documents())


def test_all_functions_listed_including_nameless_and_asm_only_where_text_exists():
    spec = unified_spec('newer', small_reader())
    assert spec.group == 'ir:newer' and spec.buildable and spec.kinds == ('function', 'asm')
    got = docs(spec)
    assert [(d.kind, d.display, d.ref) for d in got] == [
        ('function', 'ProbeForRead', 0), ('asm', 'ProbeForRead', 0),
        ('function', 'sub_2000', 1), ('function', 'ValidateLength', 2), ('asm', 'ValidateLength', 2)]
    placeholder = got[2]
    assert placeholder.flags & int(Flag.AUTO) and placeholder.rva == 0x2000
    assert all(d.side == 'newer' for d in got)


def test_asm_body_is_the_masked_reader_text_and_idents_hold_mnemonics_and_constants():
    asm = docs(unified_spec('older', small_reader()))[1]
    assert asm.code_body == 'mov eax, [ptr]\ncmp eax, 0x2a\nret'
    assert set(asm.code_idents.split()) == {'mov', 'cmp', 'ret', '0x2a', '42', '0x1000', '4096', '-1'}


@pytest.mark.parametrize(('value', 'words'), [
    (42, ('0x2a', '42')), (15, ('15',)), (16, ('0x10', '16')), (-1, ('-1',)),
    (-32, ('0xffffffffffffffe0', '-32')),
], ids=['small-hex', 'below-16', 'sixteen', 'minus-one', 'negative'])
def test_constant_spellings(value, words):
    assert constant_words(value) == words


def test_missing_ir_is_reported_unavailable_not_built():
    spec = unified_spec('newer', None)
    assert not spec.buildable and spec.status == 'unavailable' and spec.reason == NO_IR and spec.digest16 is None
    bare = small_reader()
    bare.manifest = None
    assert unified_spec('newer', bare).status == 'unavailable'


def test_subjects_link_rva_to_live_function_ids_and_change_the_digest():
    plain = unified_spec('newer', small_reader())
    linked = unified_spec('newer', small_reader(), {0x1000: 'f-new-probe'})
    assert docs(plain)[0].subject == 'ir0' and docs(linked)[0].subject == 'f-new-probe'
    assert plain.digest16 != linked.digest16
    assert plain.digest16 == unified_spec('newer', small_reader()).digest16


def test_asm_is_searchable_by_mnemonic_and_by_constant_in_both_spellings(tmp_path):
    spec = unified_spec('newer', small_reader())
    info = build_segment(tmp_path, spec.group, spec.digest16, spec.documents(), spec.table_sets)
    assert info.docs == 5
    with open_segment(info.path) as segment:
        def kinds(match):
            return [r[0] for r in segment.conn.execute(
                'SELECT d.kind FROM fts_code JOIN doc d ON d.id = fts_code.rowid WHERE fts_code MATCH ?', (match,))]
        assert kinds('idents:cmp') == ['asm']
        assert kinds('idents:"0x2a"') == ['asm'] and kinds('idents:"42"') == ['asm']
        assert kinds('idents:nosuchword') == []


def test_no_asm_document_when_reader_has_no_instruction_text():
    reader = FakeReader([0x10], ['Foo'])
    assert [d.kind for d in docs(unified_spec('older', reader))] == ['function']


def test_query_side_spelling_of_a_constant_matches_the_indexed_words():
    assert parse_query('kind:asm 0x2a').terms[0].alt == ('42',)


def test_hundred_thousand_function_gate(tmp_path):
    count = 100_000
    reader = FakeReader([0x1000 + 16 * i for i in range(count)], [f'Func{i}' for i in range(count)])
    reader.texts = lambda fid: [f'mov eax, {fid}', 'ret']
    reader.instructions = lambda fid: [Insn(0, b'', 'MOV', 0, 'fall', ()), Insn(0, b'', 'RET', 0, 'ret', ())]
    reader.constants = lambda fid: [ConstRow(0, fid, 0)]
    spec = unified_spec('newer', reader)
    started = time.monotonic()
    info = build_segment(tmp_path, spec.group, spec.digest16, spec.documents(), spec.table_sets)
    elapsed = time.monotonic() - started
    assert info.docs == 2 * count and not info.truncated
    assert elapsed >= 0 and elapsed < 600  # the section 7 per-segment build limit
    with open_segment(info.path) as segment:
        assert segment.conn.execute("SELECT count(*) FROM doc WHERE kind = 'function'").fetchone()[0] == count
