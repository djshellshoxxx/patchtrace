"""SPEC-31 04 s6.1 / S2 and S5 seams: the adapters from a real `IrReader` to the ladder's `IrSide` port and to the
residual stage's `MnemonicSource`. The sidecars are hand-assembled x86-64 through the REAL ingest (synthetic, never
live Ghidra evidence); the column mapping is also checked on database-less readers so that every code of the frozen
`program-ir/1` columns has a row."""
from __future__ import annotations

import pytest
from unified_facts_builder import NEW_SHA, OLD_SHA, build_reader, function

from patchtrace.unified.ir import schema
from patchtrace.unified.ir.ladder_port import ReaderMnemonics, ReaderSide
from patchtrace.unified.ir.reader import IrReader
from patchtrace.unified.ladder.engine import run_ladder
from patchtrace.unified.ladder.passes import PASSES
from patchtrace.unified.ladder.ports import IrSide
from patchtrace.unified.ladder.side import K_EXTERNAL, K_NORMAL, K_THUNK, SideData
from patchtrace.unified.limits import DEFAULT_LIMITS, UnifiedError

SYM = {'main': 0x1000, 'helper': 0x1100, 'forward': 0x1180, 'sleep': 0x1200, 'slot': 0x2100, 'text': 0x2200}
SLEEP = {'dll': 'kernel32.dll', 'name': 'Sleep', 'ordinal': None}
PAD = [('nop',)] * 8


def image(*, shift=0):
    """Six functions: a caller with an internal call, an import call, a string and a constant; a leaf; a thunk to the
    leaf; an import stub; a tiny function padded with NOPs; and one whose name Ghidra's AI analyser chose."""
    sym = {**SYM}
    return [
        function(0x1000, [('mov_ri', 'EAX', 0x2000), ('call', 'helper'), ('call_iat', 'slot', 'kernel32.dll!Sleep'),
                          ('lea_g', 'RDX', 'text', 'hello world'), ('cmp_ri', 'ECX', 6), ('jcc', 'A', 'done'),
                          ('add_ri', 'EAX', 3), ('label', 'done'), ('ret',)], name='main', sym=sym,
                 aliases=('main_alias',)),
        function(0x1100, [('mov_ri', 'EAX', 1), ('mov_rr', 'EDX', 'EAX'), ('xor_rr', 'ECX', 'ECX'),
                          ('add_ri', 'EAX', 9), ('test_rr', 'EAX', 'EAX'), ('mov_ri', 'EAX', 2), ('ret',)],
                 name='helper', sym=sym),
        function(0x1180, [('tail_call', 'helper')], name='forward', sym=sym, kind='thunk', thunk_target=0x1100),
        function(0x1200, [('jmp_iat', 'slot', 'kernel32.dll!Sleep')], name='Sleep', sym=sym, kind='thunk', imp=SLEEP,
                 name_src='IMPORTED'),
        function(0x1280, [('mov_ri', 'EAX', 5), ('ret',), *PAD], name='tiny_padded', sym=sym),
        function(0x1300, [('mov_ri', 'EAX', 8), ('add_ri', 'EAX', 1), ('ret',)], name='ai_named', sym=sym,
                 name_src='AI'),
    ]


@pytest.fixture
def reader(tmp_path):
    return build_reader(tmp_path, 'readers', image(), sha=OLD_SHA)


def rows_by_name(side: ReaderSide, reader: IrReader) -> dict:
    return {row.name: row for row in side.function_rows()}


def test_the_reader_side_is_an_ir_side(reader):
    assert isinstance(ReaderSide(reader), IrSide)


def test_every_function_becomes_one_row_with_the_decoded_columns(reader):
    rows = list(ReaderSide(reader).function_rows())
    assert [r.fid for r in rows] == list(range(6)) and [r.rva for r in rows] == [0x1000, 0x1100, 0x1180, 0x1200,
                                                                              0x1280, 0x1300]
    by_name = {r.name: r for r in rows}
    main, helper = by_name['main'], by_name['helper']
    table = reader.functions
    assert main.kind == helper.kind == 'normal' and main.aliases == ('main_alias',) and main.import_key is None
    assert (main.h0, main.h1, main.hm, main.hms) == tuple(table.get(c, 0) for c in ('h0', 'h1', 'hm', 'hms'))
    assert (main.n_bb, main.n_edge, main.n_insn, main.size) == tuple(table.get(c, 0) for c in
                                                                    ('n_bb', 'n_edge', 'n_insn', 'size'))
    assert main.name_src == 'USER_DEFINED' and not main.oversize and not main.pdata_confirmed
    assert by_name['forward'].kind == 'thunk' and by_name['forward'].thunk_target == 1     # fid of `helper`, not an rva


def test_an_import_stub_is_an_external_function_with_its_import_key(reader):
    """Ghidra gives an import a THUNK stub (03 s12.2 item 3); P01 matches imports by key, so the ladder sees it as
    `external` and keeps it out of every content pass (I6)."""
    stub = rows_by_name(ReaderSide(reader), reader)['Sleep']
    assert stub.kind == 'external' and stub.import_key == 'kernel32.dll!Sleep' and stub.thunk_target is None


def test_the_ai_name_source_is_never_a_name_anchor(reader):
    """03 s12.1 item 2: AI, like DEFAULT and ANALYSIS, is no name anchor; the port knows four sources."""
    row = rows_by_name(ReaderSide(reader), reader)['ai_named']
    assert row.name_src == 'ANALYSIS'
    side = SideData.from_ir(ReaderSide(reader))
    assert 'ai_named' not in side.name_index() and 'helper' in side.name_index()


def test_a_function_the_ir_calls_tiny_stays_tiny_for_the_ladder_even_with_padding(reader):
    """`tiny` counts the instructions that are not alignment padding; the ladder counts `n_insn`, so the adapter caps
    it: two real instructions and eight NOPs must not become a content-matchable 10-instruction function."""
    rows = rows_by_name(ReaderSide(reader), reader)
    assert reader.functions.get('flags', 4) & schema.FN_FLAGS['tiny'] and reader.functions.get('n_insn', 4) == 10
    assert rows['tiny_padded'].n_insn <= DEFAULT_LIMITS.l10_tiny_instructions
    side = SideData.from_ir(ReaderSide(reader))
    assert not side.content_ok[4] and side.content_ok[1] and side.kind[3] == K_EXTERNAL
    assert side.kind[2] == K_THUNK and side.kind[0] == K_NORMAL


def test_call_string_constant_and_block_rows_stream_from_the_database(reader):
    side = ReaderSide(reader)
    calls = [(c.fid, c.callee, c.import_key, c.jump) for c in side.call_rows()]
    assert (0, 1, None, False) in calls                         # main -> helper (a fid)
    assert (0, None, 'kernel32.dll!Sleep', False) in calls      # the indirect call through the IAT slot
    assert (2, 1, None, False) in calls                         # forward -> helper (a tail call recorded as a call)
    assert (3, None, 'kernel32.dll!Sleep', True) in calls       # the stub jumps through its slot
    strings = list(side.string_rows())
    assert [(s.fid, s.length) for s in strings] == [(0, len('hello world'))] and len(strings[0].sha) == 64
    constants = [(c.fid, c.value) for c in side.constant_rows()]
    assert (0, 0x2000) in constants and (1, 9) in constants
    blocks = [(b.fid, b.ord, b.n_insn) for b in side.block_rows()]
    assert (0, 0, 6) in blocks and len([b for b in blocks if b[0] == 0]) == len(reader.blocks(0))


def test_the_ladder_runs_over_two_real_sidecars_and_matches_the_untouched_functions(tmp_path):
    old = build_reader(tmp_path, 'old', image(), sha=OLD_SHA)
    new = build_reader(tmp_path, 'new', image(), sha=NEW_SHA)
    result = run_ladder(ReaderSide(old), ReaderSide(new), passes=PASSES)
    assert result.status == 'complete'
    pairs = {(p.older_fid, p.newer_fid): p for p in result.pairs}
    assert {k for k in pairs} >= {(1, 1), (3, 3)}               # `helper` by bytes, the stub by its import key (P01)
    assert pairs[(3, 3)].pass_id == 'P01' and pairs[(3, 3)].tier == 'A'
    assert pairs[(1, 1)].tier == 'A' and pairs[(1, 1)].pass_id in ('P03', 'P04', 'P05')


def test_the_mnemonic_adapter_streams_the_instruction_mnemonics_of_one_function(reader):
    source = ReaderMnemonics(reader)
    assert list(source.mnemonics(1)) == [i.mnem for i in reader.instructions(1)]
    assert list(source.mnemonics(1))[:3] == ['MOV', 'MOV', 'XOR']
    assert not isinstance(source.mnemonics(1), list)            # read on demand and consumed once, never kept
    assert list(source.mnemonics(2)) == ['JMP']


@pytest.mark.parametrize('code, word', [(0, 'normal'), (1, 'thunk'), (2, 'external')], ids=['normal', 'thunk', 'ext'])
def test_the_kind_codes_of_the_frozen_contract_have_a_word(code, word):
    reader = IrReader.from_columns({'rva': [0x1000, 0x2000], 'size': [20, 20], 'kind': [code, 0]},
                                   names=['a', 'b'])
    assert next(iter(ReaderSide(reader).function_rows())).kind == word


@pytest.mark.parametrize('flags, extent, oversize, pdata', [
    (0, 0, False, False), (schema.FN_FLAGS['oversize'], 0, True, False), (schema.FN_FLAGS['truncated'], 0, True, False),
    (schema.FN_FLAGS['pdata-confirmed'], 1, False, True), (0, 2, False, False),
    (schema.FN_FLAGS['tiny'] | schema.FN_FLAGS['mask-missing'], 0, False, False),
], ids=['plain', 'oversize', 'truncated', 'pdata', 'extent-2', 'tiny-mask'])
def test_flags_and_extent_decode_to_the_ports_booleans(flags, extent, oversize, pdata):
    reader = IrReader.from_columns({'rva': [0x1000], 'size': [64], 'flags': [flags], 'extent_src': [extent],
                                    'n_insn': [40]}, names=['f'])
    row = next(iter(ReaderSide(reader).function_rows()))
    assert (row.oversize, row.pdata_confirmed) == (oversize, pdata)


def test_null_keys_stay_none_and_an_unknown_thunk_target_is_none():
    reader = IrReader.from_columns({'rva': [0x1000, 0x1100], 'size': [64, 64], 'kind': [1, 0],
                                    'thunk_target': [0x7777, None], 'h0': [5, None], 'md_td': [None, 7]},
                                   names=['t', 'f'])
    first, second = ReaderSide(reader).function_rows()
    assert first.thunk_target is None and first.h0 == 5 and first.md_td is None
    assert second.h0 is None and second.md_td == 7


@pytest.mark.parametrize('column, reason', [('name_src', 'name-src'), ('kind', 'kind')], ids=['name-src', 'kind'])
def test_an_unknown_code_is_a_typed_ir_error(column, reason):
    reader = IrReader.from_columns({'rva': [0x1000], 'size': [64], column: [9]}, names=['f'])
    with pytest.raises(UnifiedError) as bad:
        list(ReaderSide(reader).function_rows())
    assert bad.value.code == 'PT-UNIFIED-IR' and bad.value.reason == reason
