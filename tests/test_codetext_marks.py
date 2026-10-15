"""WBQ S8 (codetext-marks): operand classes, oracles, token marks of a row pair, and the model a highlighter reads.

Synthetic text only: no binaries, no Qt. Gates from docs/specs/program-e/WBQ-integration-plan.md (s9 row S8): the
SYN-WBQ-1 counts, the mutation property (replacing any non-address token yields a `changed` mark), named symbols
never masked, and a shift-only control with no `changed` mark. Besides those: the alignment is the optimum of its
four-part cost (checked against exhaustive search), swapping the two lines swaps the marks and keeps every count,
bounded work on hostile text, orientation on every mark, and a summary that is always one printable line.
"""
from __future__ import annotations

import re
import time
import unicodedata
from collections import Counter
from typing import get_args
from unittest import mock

import pytest
from hypothesis import HealthCheck, assume, given, settings
from hypothesis import strategies as st

import patchtrace.codetext as codetext
from patchtrace.alignment import align_lines, diff_hunks
from patchtrace.codetext import intraline
from patchtrace.codetext import model as model_module
from patchtrace.codetext.intraline import (
    MAX_DP_CELLS,
    MAX_PAIR_TOKENS,
    NO_DIFFERENCE,
    SMALL_EDIT,
    diff_row,
    long_line_sentence,
)
from patchtrace.codetext.marks import LABELS, SIDES, FormatSpan, Mark, RowMarks, StyleKey
from patchtrace.codetext.model import (
    LRU_LINES,
    MAX_PAIRS_PER_REFRESH,
    MAX_WORK_PER_REFRESH,
    CodeTextModel,
    Found,
    Refresh,
    utf16_length,
    utf16_offset,
)
from patchtrace.codetext.operands import (
    OPERAND_CLASSES,
    ImageRange,
    Operand,
    TextOperandSource,
    asm_mnemonic,
    number_value,
)
from patchtrace.codetext.oracle import (
    MatchPairOracle,
    NullOracle,
    NullRenameOracle,
    Target,
)
from patchtrace.codetext.palette import MARK_STATES, ROLES
from patchtrace.codetext.tokens import MAX_LINE_CHARS, tokenize_line

FAST = settings(deadline=None, suppress_health_check=[HealthCheck.too_slow], max_examples=150)
IMAGE = ImageRange(0x140000000, 0x200000)
REASONS = ('', 'similarity', 'long-line', 'tokens', 'size')
# Three groups of at most three entries, each entry two snippets of at most 43 characters and a label or a note.
MAX_SUMMARY = 1200

# --- SYN-WBQ-1 (docs/specs/program-e/WBQ-integration-plan.md s5): one function, two builds -----------------------
# The newer build shifts every FUN_/DAT_ name by +0x40, renumbers uVarN/lVarN, changes `param_2 < 0x20` to 0x40 and
# inserts `RtlULongAdd(param_2,0x10,&param_2);`. Held as lines so that no checkout can change a line ending.
SYN_OLD = '\n'.join([
    'undefined8 FUN_140001000(longlong param_1,uint param_2,undefined8 *param_3)',
    '',
    '{',
    '  uint uVar1;',
    '  longlong lVar2;',
    '',
    '  lVar2 = *(longlong *)(param_1 + 0x10);',
    '  if ((lVar2 == 0) || (param_2 < 0x20)) {',
    '    return 0xc000000d;',
    '  }',
    '  uVar1 = FUN_140002340(lVar2,param_2);',
    '  FUN_14000a000(DAT_14000b000,uVar1);',
    '  return 0;',
    '}',
])
SYN_NEW = '\n'.join([
    'undefined8 FUN_140001040(longlong param_1,uint param_2,undefined8 *param_3)',
    '',
    '{',
    '  uint uVar2;',
    '  longlong lVar3;',
    '',
    '  lVar3 = *(longlong *)(param_1 + 0x10);',
    '  if ((lVar3 == 0) || (param_2 < 0x40)) {',
    '    return 0xc000000d;',
    '  }',
    '  RtlULongAdd(param_2,0x10,&param_2);',
    '  uVar2 = FUN_140002380(lVar3,param_2);',
    '  FUN_14000a040(DAT_14000b040,uVar2);',
    '  return 0;',
    '}',
])
SYN_ROWS = align_lines(SYN_OLD, SYN_NEW)
# The same function with the layout shift and the renumbering only: no real edit.
SYN_SHIFT_ONLY = '\n'.join([
    'undefined8 FUN_140001040(longlong param_1,uint param_2,undefined8 *param_3)',
    '',
    '{',
    '  uint uVar2;',
    '  longlong lVar3;',
    '',
    '  lVar3 = *(longlong *)(param_1 + 0x10);',
    '  if ((lVar3 == 0) || (param_2 < 0x20)) {',
    '    return 0xc000000d;',
    '  }',
    '  uVar2 = FUN_140002380(lVar3,param_2);',
    '  FUN_14000a040(DAT_14000b040,uVar2);',
    '  return 0;',
    '}',
])
# Assembly shift-only control: three rows differ, every difference is an address-derived name.
ASM_OLD = [
    'PUSH RBX',
    'SUB RSP,0x30',
    'MOV RBX,RCX',
    'MOV EAX,dword ptr [RBX + 0x8]',
    'CMP EAX,0x20',
    'JA LAB_140001040',
    'MOV ECX,dword ptr [RSP + 0x20]',
    'CALL FUN_140002340',
    'LEA RAX,[DAT_14000a000]',
    'MOV qword ptr [RBX + 0x10],RAX',
    'CALL qword ptr [->KERNEL32.DLL::CreateFileW]',
    'ADD RSP,0x30',
    'POP RBX',
    'RET',
]
ASM_SHIFTED = [line.replace('140001040', '140001080').replace('140002340', '140002380').replace('14000a000', '14000a040')
               for line in ASM_OLD]


def decoded(text: str, spans: tuple[FormatSpan, ...]) -> list[tuple[str, str, str | None]]:
    """(text, role, mark) of ASCII-only spans."""
    return [(text[s.start:s.start + s.length], s.style_key.role, s.style_key.mark) for s in spans]


# --- contract and vocabulary -------------------------------------------------------------------------------------

def test_mark_states_labels_and_operand_classes_are_the_documented_vocabulary():
    from patchtrace.unified.contracts import ChangeClass
    from patchtrace.unified.ir.operands import VKIND_NAMES

    assert set(get_args(codetext.marks.MarkState)) == set(MARK_STATES)
    assert SIDES == ('older', 'newer')
    assert set(LABELS) - {'token'} <= set(get_args(ChangeClass))
    assert len(set(LABELS)) == len(LABELS)
    assert set(OPERAND_CLASSES) == set(VKIND_NAMES)
    assert set(ROLES) >= {'address', 'stack', 'number', 'register'}  # the roles an operand class chooses


def test_public_names_are_exported():
    names = ('CodeTextModel', 'diff_row', 'Mark', 'RowMarks', 'FormatSpan', 'StyleKey', 'LABELS', 'OPERAND_CLASSES',
             'Operand', 'OperandSource', 'TextOperandSource', 'ImageRange', 'Target', 'TargetOracle', 'NullOracle',
             'MatchPairOracle', 'RenameOracle', 'NullRenameOracle', 'utf16_offset', 'utf16_length', 'Refresh', 'Found',
             'SIMILARITY_GATE', 'SMALL_EDIT', 'MAX_PAIR_TOKENS', 'MAX_DP_CELLS', 'MAX_PAIRS_PER_REFRESH')
    for name in names:
        assert name in codetext.__all__ and hasattr(codetext, name), name
    assert codetext.CONTRACT == 'codetext/1'


def test_gate_constants_are_the_plan_values():
    assert (codetext.SIMILARITY_GATE, MAX_PAIR_TOKENS, MAX_PAIRS_PER_REFRESH, LRU_LINES) == (0.8, 256, 200, 4096)
    assert SMALL_EDIT == 2 and MAX_DP_CELLS == 8192


def test_row_marks_report_a_change_only_for_the_changed_state():
    mark = Mark('older', 0, 1, 'changed', 'token')
    quiet = Mark('older', 0, 1, 'address-only', 'address-only')
    assert RowMarks(0, (mark,), (), 1.0, False, '').has_change
    assert RowMarks(0, (), (Mark('newer', 0, 1, 'changed', 'token'),), 1.0, False, '').has_change
    assert not RowMarks(0, (quiet,), (), 1.0, False, '').has_change
    assert StyleKey('number', 'changed') == ('number', 'changed')


# --- operand classes (positive evidence only) --------------------------------------------------------------------

def classes(line: str, language: str, image: ImageRange | None = None) -> str:
    found = tokenize_line(line, language).tokens
    operands = TextOperandSource(image).operands(line, found, language)
    out = []
    for index, token in enumerate(found):
        if index in operands:
            operand = operands[index]
            where = f'({operand.target.kind})' if operand.target else ''
            out.append(f'{line[token.start:token.end]}={operand.cls}{where}')
    return ' | '.join(out)


ASM_OPERANDS = [
    pytest.param('MOV RAX,qword ptr [RSP + 0x28]', None, 'RAX=register | RSP=register | 0x28=stack', id='stack-slot'),
    pytest.param('MOV EAX,dword ptr [RBP + -0x4]', None, 'EAX=register | RBP=register | 0x4=stack', id='negative-frame'),
    pytest.param('MOV EAX,dword ptr [RCX + 0x10]', None, 'EAX=register | RCX=register | 0x10=memory', id='field'),
    pytest.param('MOV EAX,dword ptr [EBP + 0x8]', None, 'EAX=register | EBP=register | 0x8=stack', id='ebp-frame'),
    pytest.param('MOV EAX,dword ptr [ESP + 0x4]', None, 'EAX=register | ESP=register | 0x4=stack', id='esp-frame'),
    pytest.param('MOV EAX,dword ptr [ECX + 0x4]', None, 'EAX=register | ECX=register | 0x4=memory', id='32-bit-field'),
    pytest.param('MOV EAX,dword ptr [RAX*4 + 0x14000b000]', None,
                 'EAX=register | RAX=register | 4=scalar | 0x14000b000=memory', id='scale-and-table-without-an-image'),
    pytest.param('LEA RAX,[RIP + 0x2f1c]', None, 'RAX=register | RIP=register | 0x2f1c=address',
                 id='rip-relative-has-no-target'),
    pytest.param('CALL FUN_140002340', None, 'FUN_140002340=address(function)', id='call-auto-name'),
    pytest.param('CALL 0x140001000', None, '0x140001000=address(function)', id='direct-call-number'),
    pytest.param('JMP 0x140001234', None, '0x140001234=address(label)', id='direct-jump-number'),
    pytest.param('JZ LAB_140001234', None, 'LAB_140001234=address(label)', id='conditional-branch-label'),
    pytest.param('LOOP 0x140001000', None, '0x140001000=address(label)', id='loop'),
    pytest.param('MOV R8D,0x20', None, 'R8D=register | 0x20=scalar', id='immediate'),
    pytest.param('ADD RSP,-0x80', None, 'RSP=register | 0x80=scalar', id='negative-immediate'),
    pytest.param('RET 8', None, '8=scalar', id='ret-count-is-not-a-target'),
    pytest.param('CALL qword ptr [->KERNEL32.DLL::CreateFileW]', None, '', id='import-call-is-named'),
    pytest.param('MOV dword ptr [RSP + local_10],EAX', None, 'RSP=register | EAX=register', id='named-stack-slot'),
    pytest.param('MOV RAX,qword ptr GS:[0x30]', None, 'RAX=register | GS=register | 0x30=memory', id='segment'),
    pytest.param('MOV EAX,dword ptr [RSP + RCX*4 + 0x10]', None,
                 'EAX=register | RSP=register | RCX=register | 4=scalar | 0x10=stack', id='frame-base-with-an-index'),
    pytest.param('MOV EAX,dword ptr [RAX + RSP*2 + 0x8]', None,
                 'EAX=register | RAX=register | RSP=register | 2=scalar | 0x8=memory', id='frame-register-as-an-index'),
    pytest.param('LEA RAX,[0x14000b000]', None, 'RAX=register | 0x14000b000=memory', id='absolute-without-image'),
    pytest.param('LEA RAX,[0x14000b000]', IMAGE, 'RAX=register | 0x14000b000=address(data)',
                 id='absolute-inside-image'),
    pytest.param('MOV RAX,0x140001000', None, 'RAX=register | 0x140001000=scalar', id='immediate-without-image'),
    pytest.param('MOV RAX,0x140001000', IMAGE, 'RAX=register | 0x140001000=address(data)', id='immediate-inside-image'),
    pytest.param('MOV RAX,0x7ff600000000', IMAGE, 'RAX=register | 0x7ff600000000=scalar', id='outside-the-image'),
    pytest.param('140001000 MOV RAX,RBX', None, '140001000=address | RAX=register | RBX=register',
                 id='listing-address-column'),
    pytest.param('MOV EAX,dword ptr [RSP + 0x8', None, 'EAX=register | RSP=register | 0x8=stack',
                 id='unterminated-bracket'),
    pytest.param('DAT_14000b000 DB 0x90', None, 'DAT_14000b000=address(data) | 0x90=scalar', id='data-label-line'),
    pytest.param('JMP qword ptr [PTR_FUN_14000c010]', None, 'PTR_FUN_14000c010=address(data)', id='pointer-cell'),
    pytest.param('LOCK CMPXCHG dword ptr [RCX],EDX', None, 'RCX=register | EDX=register', id='prefix'),
    pytest.param('ADD X0,X1,#0x10', None, '0x10=scalar', id='arm-names-are-not-registers'),
    pytest.param('0x28', None, '0x28=scalar', id='no-mnemonic-no-address-column'),
]
C_OPERANDS = [
    pytest.param('x = FUN_140001000(param_1, 0x20);', None, 'FUN_140001000=address(function) | 0x20=scalar',
                 id='call-and-constant'),
    pytest.param('thunk_FUN_140001000();', None, 'thunk_FUN_140001000=address(function)', id='thunk'),
    pytest.param('p = DAT_14000b000;', None, 'DAT_14000b000=address(data)', id='data'),
    pytest.param('goto LAB_140001234;', None, 'LAB_140001234=address(label)', id='label'),
    pytest.param('q = PTR_FUN_14000c010;', None, 'PTR_FUN_14000c010=address(data)', id='pointer-cell'),
    pytest.param('x = 0x14000b000;', IMAGE, '0x14000b000=address(data)', id='number-in-image'),
    pytest.param('x = 0x20;', IMAGE, '0x20=scalar', id='small-number'),
    pytest.param('x = a->b[3] + 1.5f + 2e3 + 0b101;', None, '3=scalar | 1.5f=scalar | 2e3=scalar | 0b101=scalar',
                 id='c-brackets-are-not-memory-operands'),
    pytest.param('s = "FUN_140001000";', None, '', id='string-is-not-an-operand'),
    pytest.param('CreateFileW(h);', None, '', id='named-callee'),
]


@pytest.mark.parametrize('line, image, expected', ASM_OPERANDS)
def test_assembly_operand_classes(line, image, expected):
    assert classes(line, 'asm', image) == expected


@pytest.mark.parametrize('line, image, expected', C_OPERANDS)
def test_c_operand_classes(line, image, expected):
    assert classes(line, 'c', image) == expected


@pytest.mark.parametrize('text, value', [
    pytest.param('0x20', 32, id='hex'), pytest.param('32', 32, id='decimal'), pytest.param('20h', 32, id='h-suffix'),
    pytest.param('0FFh', 255, id='h-suffix-leading-digit'), pytest.param('0x20UL', 32, id='integer-suffix'),
    pytest.param('0X7FFF', 0x7FFF, id='capital-x'), pytest.param('1e5', None, id='float'),
    pytest.param('0b101', None, id='binary'), pytest.param('1.5', None, id='fraction'),
    pytest.param('', None, id='empty'), pytest.param('0x', None, id='bare-prefix'),
    pytest.param('0x' + 'f' * 16, 2 ** 64 - 1, id='16-hex-digits'), pytest.param('0x' + 'f' * 17, None, id='too-wide'),
    pytest.param('9' * 18, 10 ** 18 - 1, id='18-decimal-digits'), pytest.param('9' * 19, None, id='19-decimal-digits'),
    pytest.param('abc', None, id='word')])
def test_number_value(text, value):
    assert number_value(text) == value


def test_image_range_is_half_open():
    assert IMAGE.contains(0x140000000) and IMAGE.contains(0x1401fffff) and not IMAGE.contains(0x140200000)
    assert not IMAGE.contains(0x13fffffff)


@pytest.mark.parametrize('line, expected', [
    pytest.param('MOV RAX,RBX', (0, 'mov'), id='plain'),
    pytest.param('LOCK CMPXCHG [RCX],EDX', (0, 'cmpxchg'), id='prefix-is-skipped'),
    pytest.param('140001000 CALL FUN_1', (2, 'call'), id='address-column'),
    pytest.param('LAB_140001234:', (-1, ''), id='label-only'),
    pytest.param('', (-1, ''), id='empty')])
def test_asm_mnemonic(line, expected):
    assert asm_mnemonic(line, tokenize_line(line, 'asm').tokens) == expected


@pytest.mark.parametrize('language', ['c', 'asm'])
@given(text=st.text(max_size=120))
@FAST
def test_operand_classes_are_total_and_name_only_tokens_that_exist(language, text):
    found = tokenize_line(text, language).tokens
    operands = TextOperandSource(IMAGE).operands(text, found, language)
    assert all(0 <= index < len(found) for index in operands)
    assert all(operand.cls in OPERAND_CLASSES for operand in operands.values())
    kinds = {found[index].kind for index in operands}
    assert kinds <= {'auto_name', 'number', 'register'}  # a named operand never gets a class


# --- oracles -----------------------------------------------------------------------------------------------------

def test_null_oracles_know_nothing():
    assert NullOracle().target_state(Target('function', 1), Target('function', 2)) == 'unmapped'
    assert NullRenameOracle().rename_state('uVar1', 'uVar2') == 'unknown'


@pytest.mark.parametrize('old, new, expected', [
    pytest.param(0x1000, 0x1040, 'mapped', id='paired'),
    pytest.param(0x1000, 0x2000, 'conflict', id='older-is-paired-elsewhere'),
    pytest.param(0x3000, 0x1040, 'conflict', id='newer-is-paired-elsewhere'),
    pytest.param(0x3000, 0x4000, 'unmapped', id='neither-is-paired'),
    pytest.param(0x1000, 0x1050, 'mapped', id='one-to-many-first'),
    pytest.param(0x1000, 0x1060, 'conflict', id='one-to-many-other-partner')])
def test_match_pair_oracle_resolves_functions(old, new, expected):
    oracle = MatchPairOracle([(0x1000, 0x1040), (0x1000, 0x1050), (0x2000, 0x2040)])
    assert oracle.target_state(Target('function', old), Target('function', new)) == expected


@pytest.mark.parametrize('kinds', [('data', 'data'), ('label', 'label'), ('function', 'data'), ('data', 'function')])
def test_match_pair_oracle_has_no_evidence_for_anything_but_functions(kinds):
    oracle = MatchPairOracle([(0x1000, 0x1040)])
    assert oracle.target_state(Target(kinds[0], 0x1000), Target(kinds[1], 0x1040)) == 'unmapped'


def test_match_pair_oracle_accepts_any_iterable_once():
    oracle = MatchPairOracle(iter([(1, 2)]))
    assert oracle.target_state(Target('function', 1), Target('function', 2)) == 'mapped'
    assert MatchPairOracle([]).target_state(Target('function', 1), Target('function', 2)) == 'unmapped'


# --- SYN-WBQ-1: the gate of the slice ----------------------------------------------------------------------------

def test_syn_text_is_the_plan_scenario():
    """15 aligned rows, 8 non-equal, in 4 replace hunks (the plan's measurement with the real `align_lines`)."""
    assert len(SYN_ROWS) == 15
    assert [index for index, (_, _, operation) in enumerate(SYN_ROWS) if operation != 'equal'] == [0, 3, 4, 6, 7, 10,
                                                                                                    11, 12]
    hunks = [h for h in diff_hunks(SYN_OLD, SYN_NEW, 'm') if h.operation != 'equal']
    assert [(h.operation, h.old_start, h.old_end, h.new_start, h.new_end) for h in hunks] == [
        ('replace', 0, 1, 0, 1), ('replace', 3, 5, 3, 5), ('replace', 6, 8, 6, 8), ('replace', 10, 12, 10, 13)]
    assert SYN_ROWS[12][0] is None  # the inserted line has no older line
    assert len(SYN_OLD.splitlines()) == 14 and len(SYN_NEW.splitlines()) == 15


SYN_EXPECTED = {
    0: [('FUN_140001000', 'FUN_140001040', 'address-only', 'address-only')],
    3: [('uVar1', 'uVar2', 'rename-maybe', 'name-only')],
    4: [('lVar2', 'lVar3', 'rename-maybe', 'name-only')],
    6: [('lVar2', 'lVar3', 'rename-maybe', 'name-only')],
    7: [('lVar2', 'lVar3', 'rename-maybe', 'name-only'), ('0x20', '0x40', 'changed', 'constant')],
}


def syn_row(index: int, **options) -> RowMarks:
    old, new, _ = SYN_ROWS[index]
    return diff_row(old, new, 'c', row=index, rows=len(SYN_ROWS), **options)


@pytest.mark.parametrize('index', sorted(SYN_EXPECTED))
def test_syn_wbq_1_rows_carry_exactly_the_expected_marks(index):
    old, new, _ = SYN_ROWS[index]
    row = syn_row(index)
    assert not row.gated and row.reason == '' and row.row == index
    expected = SYN_EXPECTED[index]
    assert [(old[m.start:m.end], m.state, m.label) for m in row.old] == [(o, s, label) for o, _, s, label in expected]
    assert [(new[m.start:m.end], m.state, m.label) for m in row.new] == [(n, s, label) for _, n, s, label in expected]
    assert {m.side for m in row.old} <= {'older'} and {m.side for m in row.new} <= {'newer'}


@pytest.mark.parametrize('index, shared, total', [pytest.param(10, 6, 19, id='row-10'), pytest.param(11, 6, 16, id='row-11')])
def test_syn_wbq_1_rows_paired_by_position_only_are_skipped(index, shared, total):
    row = syn_row(index)
    assert row.gated and row.reason == 'similarity' and not row.old and not row.new
    assert row.similarity == pytest.approx(2 * shared / total) and row.similarity < codetext.SIMILARITY_GATE
    assert row.summary == f'Lines are paired by position only (similarity {200 * shared // total / 100:.2f}); ' \
                          'token marks skipped.'


def test_syn_wbq_1_counts():
    """1 changed pair, 1 address-only, 4 rename-maybe, 2 rows paired by position only (the plan's s5 table)."""
    counted = {'changed': 0, 'address-only': 0, 'rename-maybe': 0}
    skipped = []
    for index, (old, new, operation) in enumerate(SYN_ROWS):
        if operation != 'replace' or old is None or new is None:
            continue
        row = syn_row(index)
        skipped += [index] if row.gated else []
        for mark in row.old:
            counted[mark.state] += 1
    assert counted == {'changed': 1, 'address-only': 1, 'rename-maybe': 4} and skipped == [10, 11]


def test_syn_wbq_1_copy_is_the_plan_copy():
    assert syn_row(7).summary == 'Line 8 of 15: 1 change: constant 0x20 -> 0x40; 1 possible rename (lVar2 -> lVar3).'
    assert syn_row(0).summary == ('Line 1 of 15: address-only difference (FUN_140001000 -> FUN_140001040); '
                                  'target not verified.')
    assert syn_row(3).summary == 'Line 4 of 15: 1 possible rename (uVar1 -> uVar2).'


def test_syn_wbq_1_model_counts_and_f8_stops():
    model = CodeTextModel.from_aligned(SYN_ROWS, 'c')
    assert model.paired_rows == (0, 3, 4, 6, 7, 10, 11)  # row 12 has only a newer line
    assert model.refresh(0, 14) == Refresh(7, 0)
    changed = [row for row in model.paired_rows if model.row_marks(row).has_change]
    assert changed == [7]  # renames, address-only differences and skipped rows are no F8 stops
    assert model.find_change(-1, +1) == Found(7, True)
    assert model.find_change(7, +1) == Found(None, True)
    assert model.find_change(15, -1) == Found(7, True)
    assert model.find_change(7, -1) == Found(None, True)


def test_shift_only_control_has_no_changed_mark_in_c():
    model = CodeTextModel.from_aligned(align_lines(SYN_OLD, SYN_SHIFT_ONLY), 'c')
    model.refresh(0, 14)
    rows = [model.row_marks(row) for row in model.paired_rows]
    assert [row.row for row in rows] == [0, 3, 4, 6, 7, 10, 11]
    assert not any(row.has_change or row.gated for row in rows)
    counts = Counter(mark.state for row in rows for mark in row.old)
    assert counts == {'address-only': 4, 'rename-maybe': 7}


@pytest.mark.parametrize('source', [None, TextOperandSource(ImageRange(0x140000000, 0x200000))], ids=['no-image', 'image'])
def test_shift_only_control_has_no_changed_mark_in_assembly(source):
    model = CodeTextModel(ASM_OLD, ASM_SHIFTED, 'asm', paired=range(len(ASM_OLD)), source=source)
    model.refresh(0, len(ASM_OLD))
    differing = [row for row in range(len(ASM_OLD)) if ASM_OLD[row] != ASM_SHIFTED[row]]
    assert differing == [5, 7, 8]
    rows = [model.row_marks(row) for row in differing]
    assert all(not row.has_change and not row.gated for row in rows)
    assert [[(m.state, m.label) for m in row.old] for row in rows] == [[('address-only', 'address-only')]] * 3
    assert all('address-only difference' in row.summary and 'target not verified' in row.summary for row in rows)


SHIFTABLE = ['CALL FUN_{:x}', 'MOV RAX,qword ptr [DAT_{:x}]', 'JZ LAB_{:x}', 'LEA RCX,[PTR_DAT_{:x}]', 'JMP thunk_FUN_{:x}']


@FAST
@given(template=st.sampled_from(SHIFTABLE), base=st.integers(0x1000, 0xFFFFFF), delta=st.integers(1, 0xFFFF))
def test_a_pure_address_shift_never_makes_a_changed_mark(template, base, delta):
    row = diff_row(template.format(base), template.format(base + delta), 'asm')
    assert not row.gated and not row.has_change
    assert [m.state for m in row.old] == ['address-only'] == [m.state for m in row.new]


@FAST
@given(base=st.integers(0x140001000, 0x140100000), delta=st.integers(1, 0xFFFF))
def test_image_range_numbers_are_masked_and_other_numbers_are_not(base, delta):
    source = TextOperandSource(IMAGE)
    shifted = diff_row(f'LEA RAX,[{base:#x}]', f'LEA RAX,[{base + delta:#x}]', 'asm', source=source)
    assert [m.state for m in shifted.old] == ['address-only']
    plain = diff_row(f'MOV RAX,{base % 0x1000:#x}', f'MOV RAX,{base % 0x1000 + delta:#x}', 'asm', source=source)
    assert [(m.state, m.label) for m in plain.old] == [('changed', 'constant')]


# --- the mutation property: replacing any non-address token yields a changed mark -------------------------------------

C_BASES = [
    'if ((count == 0) || (limit < 32)) {',
    'status = CreateFileW(path, flags, 0x20, \'a\', "name");',
    'result = *(longlong *)(base + 8) - offset;',
    'while (index <= total && buffer[index] != 0) index++;',
    'return value >> 3 | 0x10;',
    'name = (char *)obj->field.next;  // walk the list',
]
ASM_BASES = [
    'MOV RAX,qword ptr [RSP + 0x28]',
    'CMP EAX,0x20',
    'CALL qword ptr [->KERNEL32.DLL::CreateFileW]',
    'LEA RCX,[RDX + RAX*4 + 0x10]',
    'XOR EDX,EDX',
    'JZ target_label',
    'MOVZX EAX,byte ptr [RCX + RDX*0x4 + 0x8] ; load',
]
REPLACEMENTS = {
    'c': ['zzz', '77', 'return', '<=', '"s"', "'q'", 'uVar9', 'FUN_149999999', '/* c */', '&&', 'long'],
    'asm': ['RDX', '0x99', 'ptr', 'sym_x', '"s"', "'q'", 'local_99', 'FUN_149999999', 'XCHG', '-', '; other'],
}


def non_blank(line: str, language: str):
    found = tokenize_line(line, language).tokens
    return found, [(index, token) for index, token in enumerate(found) if token.kind != 'ws']


def is_masked(token_kind: str, operand: Operand | None) -> bool:
    return token_kind in ('temp', 'auto_name') or (operand is not None and operand.cls == 'address')


def clean_mutation(line: str, language: str, index: int, replacement: str):
    """(mutated line, its replaced token) when exactly that token changed and every other token kept its kind and
    spelling; a replacement that merges with a neighbour, or turns a name into a callee, is not a single-token edit."""
    found, kept = non_blank(line, language)
    token = found[index]
    mutated = line[:token.start] + replacement + line[token.end:]
    again, kept_again = non_blank(mutated, language)
    if len(kept) != len(kept_again) or replacement == line[token.start:token.end]:
        return None
    replaced = None
    for (position, old_token), (_, new_token) in zip(kept, kept_again, strict=True):
        same = (old_token.kind, line[old_token.start:old_token.end]) == (
            new_token.kind, mutated[new_token.start:new_token.end])
        if (position == index) == same:
            return None
        if position == index:
            replaced = new_token
    return mutated, replaced


@pytest.mark.parametrize('language, bases', [pytest.param('c', C_BASES, id='c'), pytest.param('asm', ASM_BASES, id='asm')])
def test_replacing_any_unmasked_token_yields_a_changed_mark_on_both_sides(language, bases):
    clean = 0
    for line in bases:
        found, kept = non_blank(line, language)
        operands = TextOperandSource().operands(line, found, language)
        for index, token in kept:
            if is_masked(token.kind, operands.get(index)):
                continue
            for replacement in REPLACEMENTS[language]:
                mutation = clean_mutation(line, language, index, replacement)
                if mutation is None:
                    continue
                clean += 1
                mutated, mutated_token = mutation
                row = diff_row(line, mutated, language)
                where = (line, mutated, replacement)
                assert not row.gated, where
                assert [(m.start, m.end) for m in row.old if m.state == 'changed'] == [(token.start, token.end)], where
                assert [(m.start, m.end) for m in row.new if m.state == 'changed'] == [
                    (mutated_token.start, mutated_token.end)], where
    assert clean >= 150  # the corpus is not vacuous


C_ATOMS = ['x', 'count', 'if', 'int', 'return', '0', '32', '0x20', '+', '-', '*', '==', '<', '&&', ';', ',', ')', '{', '}',
           '"s"', "'c'", 'CreateFileW', 'uVar1', 'FUN_140001000']
ASM_ATOMS = ['rax', 'RSP', 'qword', 'ptr', '[', ']', ',', '+', '-', '*', '0x28', '28', '10h', 'sym_a', 'FUN_140001000',
             'xmm0', 'r8d', ':']


@FAST
@given(data=st.data(), language=st.sampled_from(['c', 'asm']))
def test_replacing_any_unmasked_token_yields_a_changed_mark_for_generated_lines(data, language):
    atoms = C_ATOMS if language == 'c' else ASM_ATOMS
    words = data.draw(st.lists(st.sampled_from(atoms), min_size=2, max_size=12))
    line = ('mov ' if language == 'asm' else '') + ' '.join(words)
    found, kept = non_blank(line, language)
    operands = TextOperandSource().operands(line, found, language)
    candidates = [index for index, token in kept if not is_masked(token.kind, operands.get(index))]
    assume(candidates)
    index = data.draw(st.sampled_from(candidates))
    replacement = data.draw(st.sampled_from(REPLACEMENTS[language]))
    mutation = clean_mutation(line, language, index, replacement)
    assume(mutation is not None)
    mutated, mutated_token = mutation
    row = diff_row(line, mutated, language)
    assert not row.gated and row.has_change
    assert any(m.state == 'changed' and m.start == found[index].start for m in row.old)
    assert any(m.state == 'changed' and m.start == mutated_token.start for m in row.new)


@pytest.mark.parametrize('old, new, state, label', [
    pytest.param('x = FUN_140001000(a);', 'x = FUN_140001040(a);', 'address-only', 'address-only', id='function-address'),
    pytest.param('x = DAT_14000b000;', 'x = DAT_14000b0a0;', 'address-only', 'address-only', id='data-address'),
    pytest.param('goto LAB_140001234;', 'goto LAB_140001274;', 'address-only', 'address-only', id='label-address'),
    pytest.param('x = FUN_140001000(a);', 'x = FUN_1400010000(a);', 'address-only', 'address-only', id='wider-address'),
    pytest.param('uVar1 = a + b;', 'uVar2 = a + b;', 'rename-maybe', 'name-only', id='renumbered-temporary'),
    pytest.param('local_18 = a + b;', 'param_3 = a + b;', 'rename-maybe', 'name-only', id='another-temporary-family'),
    pytest.param('x = FUN_140001000(a);', 'x = DAT_140001000(a);', 'changed', 'callee', id='prefix-differs-is-a-change'),
    pytest.param('goto LAB_140001234;', 'goto DAT_140001234;', 'changed', 'data-ref', id='label-became-data'),
    pytest.param('x = FUN_140001000(a);', 'x = thunk_FUN_140001000(a);', 'changed', 'callee', id='became-a-thunk'),
])
def test_masked_replacement_states(old, new, state, label):
    row = diff_row(old, new, 'c')
    assert not row.gated and len(row.old) == len(row.new) == 1
    assert (row.old[0].state, row.old[0].label, row.new[0].state, row.new[0].label) == (state, label, state, label)


# --- named symbols are never masked ----------------------------------------------------------------------------------

class Recorder:
    def __init__(self, state: str = 'unmapped') -> None:
        self.state, self.calls = state, []

    def target_state(self, old, new):
        self.calls.append((old, new))
        return self.state


@pytest.mark.parametrize('language, old, new, label', [
    pytest.param('c', 'status = CreateFileW(path);', 'status = CreateFileA(path);', 'callee', id='c-api-variant'),
    pytest.param('c', 'strcpy(dst, src);', 'strncpy(dst, src);', 'callee', id='c-library-call'),
    pytest.param('c', 'FUN_140001000(x);', 'CreateFileW(x);', 'callee', id='auto-name-to-name'),
    pytest.param('c', 'CreateFileW(x);', 'FUN_140001000(x);', 'callee', id='name-to-auto-name'),
    pytest.param('c', 'CParser::ParsePacket(this, a);', 'CParser::ParseBlock(this, a);', 'callee', id='scoped-callee'),
    pytest.param('asm', 'CALL qword ptr [->KERNEL32.DLL::CreateFileW]', 'CALL qword ptr [->KERNEL32.DLL::CreateFileA]',
                 'callee', id='import-call'),
    pytest.param('asm', 'MOV RAX,qword ptr [->KERNEL32.DLL::GetTickCount]',
                 'MOV RAX,qword ptr [->KERNEL32.DLL::GetTickCount64]', 'data-ref', id='import-read'),
    pytest.param('asm', 'CALL ?ParsePacket@CParser@@QEAAJPEBEK@Z', 'CALL ?ParsePacket@CParser@@QEAAJPEBE_K@Z', 'callee',
                 id='decorated-name'),
])
def test_named_symbols_are_never_masked_and_never_ask_an_oracle(language, old, new, label):
    oracle = Recorder('mapped')
    row = diff_row(old, new, language, targets=oracle)
    assert [(m.state, m.label) for m in row.old] == [('changed', label)]
    assert [(m.state, m.label) for m in row.new] == [('changed', label)]
    assert oracle.calls == []


def test_a_name_that_becomes_a_callee_is_a_different_token_even_though_it_is_spelled_alike():
    old, new = 'a b c d e f g h i j foo ;', 'a b c d e f g h i j foo ( ) ;'
    row = diff_row(old, new, 'c')
    assert not row.gated
    assert [old[m.start:m.end] for m in row.old] == ['foo'] and [new[m.start:m.end] for m in row.new] == ['foo ( )']


def test_the_class_of_a_number_pair_needs_both_numbers():
    row = diff_row('MOV EAX,dword ptr [RSP + 0x20]', 'MOV EAX,dword ptr [RCX + 0x28]', 'asm')
    assert [m.label for m in row.old] == ['register-only', 'constant'] == [m.label for m in row.new]


def test_a_run_of_several_tokens_is_labelled_token_whatever_it_holds():
    old, new = 'a b c 1 2 f g h i j k', 'a b c 3 4 f g h i j k'
    row = diff_row(old, new, 'c')
    assert [m.label for m in row.old] == ['token'] == [m.label for m in row.new]
    assert old[row.old[0].start:row.old[0].end] == '1 2'
    assert row.summary == 'Line 1 of 1: 1 change: token 1 2 -> 3 4.'


def test_a_renamed_plain_variable_is_a_changed_token():
    row = diff_row('total = count + 1;', 'total = limit + 1;', 'c')
    assert [(m.state, m.label) for m in row.old + row.new] == [('changed', 'token')] * 2


# --- oracles in action -------------------------------------------------------------------------------------------------

def test_the_default_oracle_never_verifies_a_target():
    row = diff_row('CALL FUN_140001000', 'CALL FUN_140001040', 'asm')
    assert row.summary == ('Line 1 of 1: address-only difference (FUN_140001000 -> FUN_140001040); '
                           'target not verified.')


def test_a_mapped_pair_stays_address_only_and_says_the_run_pairs_it():
    oracle = MatchPairOracle([(0x140001000, 0x140001040)])
    row = diff_row('CALL FUN_140001000', 'CALL FUN_140001040', 'asm', targets=oracle)
    assert [m.state for m in row.old] == ['address-only']
    assert row.summary == ('Line 1 of 1: address-only difference (FUN_140001000 -> FUN_140001040); '
                           'target paired by this run.')


def test_a_pair_that_the_run_matches_elsewhere_is_a_changed_callee():
    oracle = MatchPairOracle([(0x140001000, 0x140009000)])
    row = diff_row('CALL FUN_140001000', 'CALL FUN_140001040', 'asm', targets=oracle)
    assert [(m.side, m.state, m.label) for m in row.old] == [('older', 'changed', 'callee')]
    assert [(m.side, m.state, m.label) for m in row.new] == [('newer', 'changed', 'callee')]
    assert row.summary == 'Line 1 of 1: 1 change: callee FUN_140001000 -> FUN_140001040 (not a matched pair).'


def test_mixed_target_states_are_reported_per_pair_count():
    oracle = MatchPairOracle([(0x1000, 0x1040)])
    row = diff_row('f(FUN_1000, FUN_5000);', 'f(FUN_1040, FUN_5040);', 'c', targets=oracle)
    assert row.summary == ('Line 1 of 1: 2 address-only differences (FUN_1000 -> FUN_1040, FUN_5000 -> FUN_5040); '
                           '1 of 2 targets paired by this run, the rest not verified.')


def test_a_conflict_of_a_data_or_label_target_is_labelled_by_what_it_points_at():
    oracle = Recorder('conflict')
    assert diff_row('x = DAT_14000b000;', 'x = DAT_14000b040;', 'c', targets=oracle).old[0].label == 'data-ref'
    assert diff_row('goto LAB_140001234;', 'goto LAB_140001274;', 'c', targets=oracle).old[0].label == 'cfg'
    assert diff_row('f(FUN_140001000);', 'f(FUN_140001040);', 'c', targets=oracle).old[0].label == 'callee'


def test_an_oracle_is_asked_only_about_differing_targets_with_a_known_address():
    oracle = Recorder()
    diff_row('CALL FUN_140001000', 'CALL FUN_140001000', 'asm', targets=oracle)  # equal lines
    diff_row('CALL FUN_140001000 ; a', 'CALL FUN_140001000 ; b', 'asm', targets=oracle)  # equal targets
    diff_row('LEA RAX,[RIP + 0x2f1c]', 'LEA RAX,[RIP + 0x2f5c]', 'asm', targets=oracle)  # a displacement has no target
    assert oracle.calls == []
    diff_row('CALL FUN_140001000', 'CALL FUN_140001040', 'asm', targets=oracle)
    assert oracle.calls == [(Target('function', 0x140001000), Target('function', 0x140001040))]


def test_an_oracle_is_not_asked_when_only_one_address_has_a_target():
    oracle = Recorder('conflict')
    source = TextOperandSource(IMAGE)
    row = diff_row('LEA RAX,[RIP + 0x2f1c]', 'LEA RAX,[0x14000b000]', 'asm', source=source, targets=oracle)
    assert oracle.calls == [] and [m.state for m in row.old if m.state != 'changed'] == ['address-only']


@pytest.mark.parametrize('answer', ['banana', None, 7, ''])
def test_an_unexpected_oracle_answer_is_no_evidence(answer):
    row = diff_row('CALL FUN_140001000', 'CALL FUN_140001040', 'asm', targets=Recorder(answer))
    assert [m.state for m in row.old] == ['address-only'] and row.summary.endswith('target not verified.')


class Renames:
    def __init__(self, answer):
        self.answer = answer

    def rename_state(self, old, new):
        return self.answer


def test_a_consistent_rename_is_still_only_a_rename_maybe():
    row = diff_row('uVar1 = a;', 'uVar2 = a;', 'c', renames=Renames('consistent'))
    assert [(m.state, m.label) for m in row.old] == [('rename-maybe', 'name-only')]
    assert row.summary == 'Line 1 of 1: 1 consistent rename (uVar1 -> uVar2).'


def test_a_contradicted_rename_is_a_changed_token():
    row = diff_row('uVar1 = a;', 'uVar2 = a;', 'c', renames=Renames('conflict'))
    assert [(m.state, m.label) for m in row.old] == [('changed', 'token')]
    assert row.summary == 'Line 1 of 1: 1 change: token uVar1 -> uVar2 (inconsistent rename).'


@pytest.mark.parametrize('answer', ['unknown', 'banana', None])
def test_an_unknown_rename_is_a_possible_rename(answer):
    row = diff_row('uVar1 = a;', 'uVar2 = a;', 'c', renames=Renames(answer))
    assert [m.state for m in row.old] == ['rename-maybe']
    assert row.summary == 'Line 1 of 1: 1 possible rename (uVar1 -> uVar2).'


def test_renames_are_consistent_only_when_every_rename_is():
    class Half:
        def rename_state(self, old, new):
            return 'consistent' if old == 'uVar1' else 'unknown'

    row = diff_row('f(uVar1, uVar3);', 'f(uVar2, uVar4);', 'c', renames=Half())
    assert row.summary == 'Line 1 of 1: 2 possible renames (uVar1 -> uVar2, uVar3 -> uVar4).'


# --- orientation -------------------------------------------------------------------------------------------------------

LONG_OLD = 'status = a + b + c + d + e + f + g + h;'
LONG_NEW = 'status = a + b + c + d + e + f + g + h + CheckSize(x);'


def test_an_added_call_exists_on_the_newer_side_only():
    row = diff_row(LONG_OLD, LONG_NEW, 'c')
    assert not row.old and [(m.side, m.state, m.label) for m in row.new] == [('newer', 'changed', 'call-added')]
    assert LONG_NEW[row.new[0].start:row.new[0].end] == '+ CheckSize(x)'
    assert row.summary == 'Line 1 of 1: 1 change: call-added (none) -> + CheckSize(x).'


def test_a_removed_call_exists_on_the_older_side_only():
    row = diff_row(LONG_NEW, LONG_OLD, 'c')
    assert not row.new and [(m.side, m.state, m.label) for m in row.old] == [('older', 'changed', 'call-removed')]
    assert row.summary == 'Line 1 of 1: 1 change: call-removed + CheckSize(x) -> (none).'


def test_swapping_the_lines_swaps_the_arrow_and_the_sides():
    forward = diff_row('x = 1;', 'x = 2;', 'c')
    backward = diff_row('x = 2;', 'x = 1;', 'c')
    assert forward.summary == 'Line 1 of 1: 1 change: constant 1 -> 2.'
    assert backward.summary == 'Line 1 of 1: 1 change: constant 2 -> 1.'
    assert (forward.old[0].side, forward.new[0].side) == ('older', 'newer')
    assert (forward.old[0].start, forward.old[0].end) == (backward.new[0].start, backward.new[0].end)


@pytest.mark.parametrize('old, new, language, label', [
    pytest.param('x == 1', 'x != 1', 'c', 'comparison', id='relational-operator'),
    pytest.param('a < b', 'a <= b', 'c', 'comparison', id='bound'),
    pytest.param('a && b', 'a || b', 'c', 'condition', id='logical-operator'),
    pytest.param('a < b', 'a + b', 'c', 'token', id='relational-replaced-by-arithmetic'),
    pytest.param('a * b', 'a <= b', 'c', 'token', id='arithmetic-replaced-by-relational'),
    pytest.param('a && b', 'a + b', 'c', 'token', id='logical-replaced-by-arithmetic'),
    pytest.param('a + b', 'a || b', 'c', 'token', id='arithmetic-replaced-by-logical'),
    pytest.param('CALL LAB_140001234', 'JNZ LAB_140001234', 'asm', 'token', id='call-replaced-by-jump'),
    pytest.param('JZ LAB_140001234', 'CALL LAB_140001234', 'asm', 'token', id='jump-replaced-by-call'),
    pytest.param('x + 1', 'x - 1', 'c', 'token', id='arithmetic-operator'),
    pytest.param('x = "a";', 'x = "b";', 'c', 'string', id='string'),
    pytest.param("x = 'a';", "x = 'b';", 'c', 'constant', id='character'),
    pytest.param('MOV EAX,ECX', 'MOV EAX,EDX', 'asm', 'register-only', id='register'),
    pytest.param('JZ LAB_140001234', 'JNZ LAB_140001234', 'asm', 'condition', id='conditional-jump'),
    pytest.param('MOV EAX,1', 'XOR EAX,1', 'asm', 'token', id='mnemonic'),
    pytest.param('MOV EAX,dword ptr [RSP + 0x20]', 'MOV EAX,dword ptr [RSP + 0x28]', 'asm', 'frame', id='frame-offset'),
    pytest.param('MOV EAX,dword ptr [RCX + 0x20]', 'MOV EAX,dword ptr [RCX + 0x28]', 'asm', 'struct-offset',
                 id='field-offset'),
    pytest.param('MOV EAX,dword ptr [RCX + RDX*4]', 'MOV EAX,dword ptr [RCX + RDX*8]', 'asm', 'constant', id='scale'),
    pytest.param('MOV EAX,dword ptr [RCX]', 'MOV EAX,qword ptr [RCX]', 'asm', 'token', id='operand-size'),
    pytest.param('MOV EAX,ECX', 'MOV EAX,5', 'asm', 'token', id='register-replaced-by-a-number'),
    pytest.param('CALL FUN_140002340', 'CALL RAX', 'asm', 'token', id='direct-call-replaced-by-an-indirect-one'),
    pytest.param('status = CreateFileW(path);', 'status = 5(path);', 'c', 'token', id='callee-replaced-by-a-number'),
])
def test_labels_are_the_unified_change_classes(old, new, language, label):
    row = diff_row(old, new, language)
    assert not row.gated and [m.label for m in row.old] == [label] == [m.label for m in row.new]
    assert label in LABELS


# --- the gate: paired by position only -----------------------------------------------------------------------------------

def words(count: int, swapped=(), prefix='a', other='z') -> str:
    return ' '.join(f'{other}{i}' if i in swapped else f'{prefix}{i}' for i in range(count))


def test_the_similarity_gate_is_inclusive_at_eighty_percent():
    row = diff_row(words(10), words(10, {1, 5}), 'c')
    assert not row.gated and row.similarity == 0.8 and len(row.old) == len(row.new) == 2


def test_below_the_gate_the_row_is_skipped_with_the_status_copy():
    row = diff_row(words(10), words(10, {1, 5, 8}), 'c')
    assert row.gated and row.reason == 'similarity' and row.similarity == pytest.approx(0.7)
    assert not row.old and not row.new
    assert row.summary == 'Lines are paired by position only (similarity 0.70); token marks skipped.'


def test_a_gated_similarity_is_printed_rounded_down_so_it_never_shows_the_gate():
    row = diff_row(words(49), words(49, set(range(0, 49, 5))), 'c')  # 39 of 49 tokens shared: 0.7959
    assert row.gated and row.summary == 'Lines are paired by position only (similarity 0.79); token marks skipped.'


@pytest.mark.parametrize('language, old, new, marked', [
    pytest.param('c', 'return 0;', 'return 1;', True, id='one-token-replaced'),
    pytest.param('c', '}', '{', True, id='nothing-shared-but-one-token'),
    pytest.param('c', 'a b', 'a b c d', True, id='two-tokens-inserted'),
    pytest.param('c', 'a b c d', 'a b', True, id='two-tokens-removed'),
    pytest.param('c', 'a b c', 'a b', True, id='one-token-removed'),
    pytest.param('c', 'x = 1;', 'y = 2;', False, id='two-tokens-replaced'),
    pytest.param('c', 'x = 1;', 'x = foo(1);', False, id='three-tokens-inserted'),
    pytest.param('c', 'a b', 'a b c d e', False, id='three-tokens-inserted-in-a-short-line'),
    pytest.param('asm', 'MOV EAX,ECX', 'MOV EAX,EDX', True, id='one-register'),
    pytest.param('asm', 'XOR EDX,EDX', 'XOR ECX,ECX', False, id='two-registers-in-a-short-line'),
])
def test_one_token_edit_is_always_marked_and_a_bigger_edit_of_a_short_line_is_not(language, old, new, marked):
    row = diff_row(old, new, language)
    assert row.gated != marked and bool(row.old or row.new) == marked


def test_the_gate_does_not_apply_to_lines_that_differ_only_in_spacing():
    row = diff_row('x=1;', 'x = 1;', 'c')
    assert not row.gated and not row.old and not row.new and row.similarity == 1.0
    assert row.summary == NO_DIFFERENCE == 'No token-level differences on this line.'
    assert diff_row('', '   ', 'c').summary == NO_DIFFERENCE
    assert diff_row('x', 'x', 'c', row=3, rows=9).summary == NO_DIFFERENCE


def test_equal_lines_have_no_marks_and_cost_no_tokenization():
    same = 'x = FUN_140001000(a);'
    with mock.patch.object(intraline, 'tokenize_line') as tokenizer:
        assert diff_row(same, same, 'c') == RowMarks(0, (), (), 1.0, False, NO_DIFFERENCE)
    tokenizer.assert_not_called()


def test_the_token_cap_is_256_per_side():
    at_cap = diff_row(words(256), words(256, {255}), 'c')
    assert not at_cap.gated and [m.state for m in at_cap.old] == ['changed']
    for old, new in ((words(257), words(256)), (words(256), words(257)), (words(257), words(257, {3}))):
        over = diff_row(old, new, 'c', row=4)
        assert over.gated and over.reason == 'tokens' and over.similarity is None and not over.old and not over.new
        assert over.summary == 'Line 5 has more than 256 tokens; token marks skipped.'


def test_the_line_cap_is_4096_characters_per_side():
    at_cap = diff_row('a' * MAX_LINE_CHARS, 'a' * (MAX_LINE_CHARS - 1) + 'b', 'c')
    assert not at_cap.gated and [m.state for m in at_cap.old] == ['changed']
    for old, new in (('a' * (MAX_LINE_CHARS + 1), 'a'), ('a', 'a' * (MAX_LINE_CHARS + 1))):
        over = diff_row(old, new, 'c', row=411)
        assert over.gated and over.reason == 'long-line' and not over.old and not over.new
        assert over.summary == long_line_sentence(411)
        assert over.summary == 'Line 412 is longer than 4,096 characters; shown without colours or token marks.'


def prepared(text: str, language: str = 'c'):
    return intraline._prepare(text, language, False, TextOperandSource())


def long_pair(edits=(), prefix_words: int = 74, suffix_words: int = 74):
    """A 150-token line and the same line with the first and last token respelled, one token inserted in the middle
    and `edits` (word numbers of the first half) respelled: pairing the tokens in order is useless after the insertion,
    so the exact band is wide."""
    first = words(prefix_words).split()
    second = words(suffix_words, prefix='b').split()
    old = ' '.join(['p0', *first, *second, 'q0'])
    changed = [('z' + w[1:]) if index in edits else w for index, w in enumerate(first)]
    new = ' '.join(['p1', *changed, 'x', *second, 'q1'])
    return old, new


def test_the_band_is_sized_by_the_exact_distance_and_not_by_how_badly_the_lines_pair_in_order():
    """Pairing these lines in order fails after the insertion (about 76 of 150 positions differ), but only five tokens
    are inserted or removed, so the exact band is 3 wide and the table is a few hundred cells."""
    old, new = long_pair()
    first, second = prepared(old), prepared(new)
    measure = intraline._measure(first, second)
    assert measure.distance == 5 and measure.shared == 148
    found = intraline._align(first, second)
    assert found.pairs is not None and found.distance == 5 and 0 < found.cells < 1500
    row = diff_row(old, new, 'c')
    assert not row.gated and row.work == found.cells
    assert [old[m.start:m.end] for m in row.old] == ['p0', 'q0']
    assert [new[m.start:m.end] for m in row.new] == ['p1', 'x', 'q1']


def test_a_pair_that_passes_the_gate_but_needs_more_than_the_cell_cap_is_skipped_not_approximated():
    fits = long_pair(edits=set(range(0, 74, 2)[:26]))  # 57 inserted or removed tokens: 8,068 cells
    over = long_pair(edits=set(range(0, 74, 2)[:27]))  # 59: 8,311 cells, one band wider than the cap allows
    assert diff_row(*fits, 'c').work <= MAX_DP_CELLS and not diff_row(*fits, 'c').gated
    first, second = prepared(over[0]), prepared(over[1])
    measure = intraline._measure(first, second)
    assert 5 * measure.shared >= 2 * (len(first) + len(second))  # the ratio gate lets it through
    found = intraline._align(first, second)
    assert found.pairs is None and found.cells == 0 and found.distance == measure.distance == 59
    row = diff_row(*over, 'c', row=2)
    assert row.gated and row.reason == 'size' and row.similarity is None and row.work == 0
    assert row.summary == 'Line 3 differs in too many places to compare within the work limit; token marks skipped.'


def test_a_row_that_fails_the_gate_builds_no_table():
    row = diff_row(words(255), words(255, prefix='b'), 'c')
    assert row.gated and row.reason == 'similarity' and row.similarity == 0.0 and row.work == 0
    assert row.summary == 'Lines are paired by position only (similarity 0.00); token marks skipped.'


def test_a_wide_table_with_few_edits_fits_the_exact_band():
    head, tail = words(100, prefix='h').split(), words(100, prefix='t').split()
    old = ' '.join(head + words(40).split() + tail)
    new = ' '.join(head + words(40, prefix='b').split() + tail)  # a 40-token region replaced by another
    row = diff_row(old, new, 'c')
    assert not row.gated and [m.label for m in row.old] == ['token'] == [m.label for m in row.new]
    assert 0 < row.work <= MAX_DP_CELLS


# --- the alignment is the optimum of its cost: exhaustive search on small inputs -------------------------------------------

ALIGN_ATOMS = ['x', 'y', 'uVar1', 'uVar2', 'lVar3', 'FUN_1000', 'FUN_2000', 'DAT_1000', '+', ';']


def cost_vector(first, second, pairs) -> tuple[int, int, int, int]:
    """(inserted + removed, temporaries paired under another spelling, address names paired under another spelling,
    runs of change): the four parts of the cost, most important first."""
    renamed = sum(1 for i, j in pairs if first[i].key == '~' and first[i].text != second[j].text)
    moved = sum(1 for i, j in pairs if first[i].key != '~' and first[i].weight and first[i].text != second[j].text)
    runs, before_i, before_j = 0, -1, -1
    for i, j in (*pairs, (len(first), len(second))):
        runs += (i - before_i > 1) or (j - before_j > 1)
        before_i, before_j = i, j
    return len(first) + len(second) - 2 * len(pairs), renamed, moved, runs


def chains(first, second):
    """Every set of pairings that keeps both orders and pairs only equal keys."""
    points = [(i, j) for i in range(len(first)) for j in range(len(second)) if first[i].key == second[j].key]

    def extend(start: int, last_i: int, last_j: int):
        yield ()
        for index in range(start, len(points)):
            i, j = points[index]
            if i > last_i and j > last_j:
                for rest in extend(index + 1, i, j):
                    yield ((i, j), *rest)

    return extend(0, -1, -1)


def classic_lcs(a: list[str], b: list[str]) -> int:
    table = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i in range(len(a)):
        for j in range(len(b)):
            table[i + 1][j + 1] = table[i][j] + 1 if a[i] == b[j] else max(table[i][j + 1], table[i + 1][j])
    return table[-1][-1]


@FAST
@given(a=st.lists(st.sampled_from(ALIGN_ATOMS[:5]), max_size=40), b=st.lists(st.sampled_from(ALIGN_ATOMS[:5]), max_size=40))
def test_the_bit_parallel_common_subsequence_equals_the_classic_table(a, b):
    first, second = prepared(' '.join(a)), prepared(' '.join(b))
    assert intraline._lcs_length(first, second) == classic_lcs([t.key for t in first], [t.key for t in second])


@pytest.mark.parametrize('a, b, length', [
    pytest.param('', '', 0, id='both-empty'), pytest.param('x', '', 0, id='one-empty'),
    pytest.param('x y z', 'x y z', 3, id='equal'), pytest.param('x', 'y', 0, id='disjoint'),
    pytest.param('x y x y', 'y x y x', 3, id='alternating'), pytest.param('x x x', 'x', 1, id='repeats'),
    pytest.param('uVar1 uVar2', 'lVar3 x uVar4', 2, id='masked-keys-are-equal-keys')])
def test_common_subsequence_examples(a, b, length):
    assert intraline._lcs_length(prepared(a), prepared(b)) == length


@pytest.mark.parametrize('a, b, expected', [
    pytest.param('a b c', 'a b d', (2, 0, 2, 2), id='head-only'),
    pytest.param('a b c', 'x b c', (0, 2, 2, 2), id='tail-only'),
    pytest.param('a b c d', 'a x y d', (1, 1, 2, 4), id='head-and-tail'),
    pytest.param('a b', 'a b', (2, 0, 2, 0), id='equal-takes-the-head'),
    pytest.param('a b c', 'a c', (1, 1, 2, 1), id='removal'),
    pytest.param('x', 'x x x', (1, 0, 1, 2), id='head-never-overlaps-tail'),
    pytest.param('uVar1 b', 'uVar2 b', (0, 1, 2, 0), id='masked-names-are-not-trimmed'),
    pytest.param('', 'a', (0, 0, 0, 1), id='empty-side')])
def test_head_tail_shared_and_distance(a, b, expected):
    assert tuple(intraline._measure(prepared(a), prepared(b))) == expected


def test_a_table_of_exactly_the_cell_cap_fits_and_one_cell_more_does_not():
    old, new = hostile_pair(0)
    first, second = prepared(old), prepared(new)
    cells = intraline._align(first, second).cells
    assert 0 < cells < MAX_DP_CELLS
    with mock.patch.object(intraline, 'MAX_DP_CELLS', cells):
        assert intraline._align(first, second).pairs is not None
    with mock.patch.object(intraline, 'MAX_DP_CELLS', cells - 1):
        assert intraline._align(first, second).pairs is None


def test_the_band_reaches_as_far_as_a_path_that_inserts_first_and_removes_later():
    """Three tokens are inserted and one removed later: the path leaves the diagonal by three, which only
    (distance + skew) / 2 allows (distance / 2 would not)."""
    found = intraline._align(prepared('a b c d e f'), prepared('a X Y Z b c e f'))
    assert found.distance == 4 and found.pairs == [(0, 0), (1, 4), (2, 5), (4, 6), (5, 7)]


@FAST
@given(a=st.lists(st.sampled_from(ALIGN_ATOMS), max_size=12), b=st.lists(st.sampled_from(ALIGN_ATOMS), max_size=12))
def test_the_measure_and_the_alignment_agree(a, b):
    first, second = prepared(' '.join(a)), prepared(' '.join(b))
    measure, found = intraline._measure(first, second), intraline._align(first, second)
    assert found.distance == measure.distance and len(found.pairs) == measure.shared
    assert measure.distance == len(first) + len(second) - 2 * measure.shared


@pytest.mark.parametrize('old, new', [
    pytest.param('uVar1 FUN_1000', 'FUN_2000 uVar2', id='rename-first'),
    pytest.param('FUN_1000 uVar1', 'uVar2 FUN_2000', id='address-first'),
])
def test_when_a_rename_and_an_address_pair_compete_the_address_pair_is_kept(old, new):
    """Either pairing leaves two tokens unpaired; pairing the temporaries would call two names a rename on the
    strength of a position, so the address names are paired (a muted mark) and the temporaries are changed tokens."""
    first, second = prepared(old), prepared(new)
    found = intraline._align(first, second)
    assert cost_vector(first, second, found.pairs) == (2, 0, 1, 2)
    row = diff_row(old, new, 'c')
    assert not row.gated and sorted(m.state for m in row.old) == ['address-only', 'changed']


@FAST
@given(a=st.lists(st.sampled_from(ALIGN_ATOMS), max_size=6), b=st.lists(st.sampled_from(ALIGN_ATOMS), max_size=6))
def test_the_alignment_is_the_optimum_of_distance_then_renames_then_moves_then_runs(a, b):
    first, second = prepared(' '.join(a)), prepared(' '.join(b))
    found = intraline._align(first, second)
    assert found.pairs is not None
    best = min(cost_vector(first, second, pairs) for pairs in chains(first, second))
    assert cost_vector(first, second, found.pairs) == best
    assert found.distance == best[0] == len(first) + len(second) - 2 * len(found.pairs)
    assert all(first[i].key == second[j].key for i, j in found.pairs)
    assert all(x[0] < y[0] and x[1] < y[1] for x, y in zip(found.pairs, found.pairs[1:], strict=False))


@FAST
@given(a=st.lists(st.sampled_from(ALIGN_ATOMS), max_size=6), b=st.lists(st.sampled_from(ALIGN_ATOMS), max_size=6))
def test_swapping_the_lines_keeps_every_part_of_the_cost(a, b):
    first, second = prepared(' '.join(a)), prepared(' '.join(b))
    forward, backward = intraline._align(first, second), intraline._align(second, first)
    assert cost_vector(first, second, forward.pairs) == cost_vector(second, first, backward.pairs)


def states(marks):
    return Counter(m.state for m in marks)


def changed_tokens(line: str, marks: tuple[Mark, ...]) -> int:
    """Non-blank tokens of `line` that lie inside a `changed` mark."""
    spans = [(m.start, m.end) for m in marks if m.state == 'changed']
    return sum(1 for t in tokenize_line(line, 'c').tokens
               if t.kind != 'ws' and any(start <= t.start and t.end <= end for start, end in spans))


def change_count(row: RowMarks) -> int:
    found = re.match(r'Line \d+ of \d+: (\d+) changes?:', row.summary)
    return int(found[1]) if found else 0


@FAST
@given(a=st.lists(st.sampled_from(ALIGN_ATOMS), max_size=14), b=st.lists(st.sampled_from(ALIGN_ATOMS), max_size=14))
def test_swapping_the_lines_swaps_the_marks_and_keeps_every_count(a, b):
    """Equally good alignments may group the same changed tokens into marks differently, so the number of marks is not
    compared; what the order of the lines cannot change is below."""
    old, new = ' '.join(a), ' '.join(b)
    forward, backward = diff_row(old, new, 'c'), diff_row(new, old, 'c')
    assert (forward.gated, forward.reason, forward.similarity) == (backward.gated, backward.reason, backward.similarity)
    assert changed_tokens(old, forward.old) == changed_tokens(old, backward.new)
    assert changed_tokens(new, forward.new) == changed_tokens(new, backward.old)
    quiet = {'address-only', 'rename-maybe'}
    assert {s: n for s, n in states(forward.old).items() if s in quiet} == {
        s: n for s, n in states(backward.new).items() if s in quiet}
    assert {s: n for s, n in states(forward.new).items() if s in quiet} == {
        s: n for s, n in states(backward.old).items() if s in quiet}
    assert change_count(forward) == change_count(backward)


@FAST
@given(a=st.lists(st.sampled_from(ALIGN_ATOMS), max_size=14))
def test_a_line_has_no_marks_against_itself_or_a_respaced_copy(a):
    line = ' '.join(a)
    assert diff_row(line, line, 'c').old == () == diff_row(line, line, 'c').new
    respaced = diff_row(line, '  '.join(a), 'c')
    assert respaced.old == () == respaced.new and respaced.summary == NO_DIFFERENCE


@FAST
@given(a=st.lists(st.sampled_from(ALIGN_ATOMS), max_size=70), b=st.lists(st.sampled_from(ALIGN_ATOMS), max_size=70))
def test_the_dynamic_programming_never_evaluates_more_cells_than_the_cap(a, b):
    assert intraline._align(prepared(' '.join(a)), prepared(' '.join(b))).cells <= MAX_DP_CELLS


def test_the_cell_cap_holds_for_the_widest_inputs_the_token_cap_allows():
    cases = [(words(256), words(256, prefix='b')), (words(256), words(256, {0, 255})),
             (' '.join(['x'] * 256), ' '.join(['y'] * 256)), (' '.join(['x', 'y'] * 128), ' '.join(['y', 'x'] * 128))]
    for old, new in cases:
        assert intraline._align(prepared(old), prepared(new)).cells <= MAX_DP_CELLS


# --- hostile text -----------------------------------------------------------------------------------------------------------

FRAGMENTS = ['"', "'", '\\', '/*', '*/', '//', ';', '\n', '\r\n', ' ', '\t', '\x00', '\x0b', 'L"', '0x', '1e-', '.5', '::',
             '->', '...', '\U0000202e', '\U0000200b', '\U00002028', '\x85', '\ud800', '\U000000e9', '\U0001f600',
             'FUN_140001000', 'uVar1', 'param_1', 'mov', 'rax', 'ptr', '[', ']', '(', ')', ',', ':', 'x', '0', '0x28',
             'RSP', 'CALL']
SOUP = st.lists(st.sampled_from(FRAGMENTS), max_size=60).map(''.join)
ANY_TEXT = st.one_of(st.text(max_size=120), SOUP)


def unsafe_characters(text: str) -> list[str]:
    """What a one-line status sentence must never carry, judged by Unicode category and not by the implementation's
    table: controls, format characters, line and paragraph separators, surrogates, every space but U+0020, and the
    variation selectors."""
    return [c for c in text if unicodedata.category(c) in ('Cc', 'Cf', 'Cs', 'Zl', 'Zp')
            or (unicodedata.category(c) == 'Zs' and c != ' ') or 0xFE00 <= ord(c) <= 0xFE0F]


def assert_well_formed(old: str, new: str, row: RowMarks, language: str) -> None:
    assert row.reason in REASONS and (row.reason == '') == (not row.gated)
    assert row.similarity is None or 0.0 <= row.similarity <= 1.0
    assert '\n' not in row.summary and not unsafe_characters(row.summary) and len(row.summary) <= MAX_SUMMARY
    assert not (row.gated and (row.old or row.new))
    for side, line, marks in (('older', old, row.old), ('newer', new, row.new)):
        found = tokenize_line(line, language).tokens
        starts, ends = {t.start for t in found}, {t.end for t in found}
        position = 0
        for mark in marks:
            assert isinstance(mark, Mark) and mark.side == side
            assert position <= mark.start < mark.end <= len(line)
            assert mark.state in MARK_STATES and mark.label in LABELS
            assert (mark.state == 'address-only') == (mark.label == 'address-only')
            assert (mark.state == 'rename-maybe') == (mark.label == 'name-only')
            if len(line) <= MAX_LINE_CHARS:  # a mark covers whole tokens
                assert mark.start in starts and mark.end in ends
            assert mark.label != ('call-added' if side == 'older' else 'call-removed')
            position = mark.end


@pytest.mark.parametrize('language', ['c', 'asm'])
@FAST
@given(old=ANY_TEXT, new=ANY_TEXT)
def test_hostile_text_never_raises_and_every_mark_is_well_formed(language, old, new):
    assert_well_formed(old, new, diff_row(old, new, language), language)


@pytest.mark.parametrize('language', ['c', 'asm'])
@FAST
@given(a=SOUP, edit=SOUP, b=SOUP)
def test_hostile_text_that_shares_a_head_and_a_tail_is_well_formed(language, a, edit, b):
    assert_well_formed(a + edit + b, a + b, diff_row(a + edit + b, a + b, language), language)


def test_bidirectional_and_invisible_characters_are_named_not_rendered_in_the_summary():
    old, new = 'x = a' + chr(0x202E) + 'b;', 'x = a' + chr(0x200B) + 'b;'
    row = diff_row(old, new, 'c')
    assert [old[m.start:m.end] for m in row.old] == [chr(0x202E)] and [new[m.start:m.end] for m in row.new] == [chr(0x200B)]
    assert row.summary == 'Line 1 of 1: 1 change: token <U+202E> -> <U+200B>.'


@pytest.mark.parametrize('code', [0x00, 0x09, 0x1B, 0x1F, 0x7F, 0x0D, 0x85, 0x9F, 0xA0, 0xAD, 0x34F, 0x61C, 0x115F, 0x1160,
                                  0x1680, 0x17B4, 0x17B5, 0x180B, 0x180F, 0x2000, 0x200A, 0x200B, 0x200F, 0x2028, 0x2029,
                                  0x202A, 0x202E, 0x202F, 0x205F, 0x2060, 0x206F, 0x2800, 0x3000, 0x3164, 0xD800, 0xFE00,
                                  0xFE0F, 0xFEFF, 0xFFA0, 0xFFF0, 0xFFF9, 0xFFFB, 0x1BCA0, 0x1BCA3, 0x1D173, 0x1D17A,
                                  0xE0000, 0xE0041, 0xE0100, 0xE0FFF],
                         ids=lambda code: f'U+{code:04X}')
def test_every_invisible_or_control_character_is_escaped_in_the_summary(code):
    row = diff_row(f'x = "{chr(code)}";', 'x = "y";', 'c')
    assert row.has_change and not unsafe_characters(row.summary) and '\n' not in row.summary
    assert f'<U+{code:04X}>' in row.summary


def test_a_snippet_is_cut_at_forty_shown_characters_and_marked_as_cut():
    row = diff_row('x = "' + 'a' * 300 + '";', 'x = "' + 'b' * 300 + '";', 'c')
    assert row.summary == f'Line 1 of 1: 1 change: string "{"a" * 39}... -> "{"b" * 39}....'
    exactly = diff_row('x = "' + 'a' * 38 + '";', 'x = "' + 'b' * 38 + '";', 'c')  # 40 characters: not cut
    assert exactly.summary == f'Line 1 of 1: 1 change: string "{"a" * 38}" -> "{"b" * 38}".'


def test_the_cut_counts_the_escaped_form_of_a_hidden_character():
    row = diff_row('x = "' + chr(0) * 10 + '";', 'x = "y";', 'c')
    assert row.summary == 'Line 1 of 1: 1 change: string "' + '<U+0000>' * 4 + '... -> "y".'


def test_the_longest_summary_stays_inside_its_bound():
    strings = [('"' + chr(0) * 30 + str(i) + '"', '"' + chr(1) * 30 + str(i) + '"') for i in range(8)]
    temps = [('uVar' + '1' * 60 + str(i), 'uVar' + '2' * 60 + str(i)) for i in range(8)]
    names = [('PTR_' * 8 + 'DAT_14000000' + f'{i:02d}', 'PTR_' * 8 + 'DAT_14000000' + f'{i + 1:02d}') for i in range(8)]
    filler = ' '.join(f'k{i}' for i in range(50))
    old = filler + ' ' + ' ; '.join(o for o, _ in strings + temps + names) + ' ; ' + filler
    new = filler + ' ' + ' ; '.join(n for _, n in strings + temps + names) + ' ; ' + filler
    row = diff_row(old, new, 'c', row=99999, rows=99999)
    assert not row.gated and 400 < len(row.summary) <= MAX_SUMMARY
    assert row.summary.count(' and ') >= 3 and not unsafe_characters(row.summary)


def test_many_changes_are_listed_up_to_three_with_a_count_of_the_rest():
    old = ' '.join(f'a{i} = {i};' for i in range(40))
    new = ' '.join(f'a{i} = {i + (100 if i % 7 == 0 else 0)};' for i in range(40))
    row = diff_row(old, new, 'c')
    assert row.summary == ('Line 1 of 1: 6 changes: constant 0 -> 100, constant 7 -> 107, constant 14 -> 114 and 3 more.')
    assert len(row.old) == len(row.new) == 6


@pytest.mark.parametrize('line', [
    pytest.param('(' * 4096, id='open-parentheses'), pytest.param('a ' * 2048, id='many-tokens'),
    pytest.param('"' * 4096, id='quotes'), pytest.param('/*' * 2048, id='comment-openers'),
    pytest.param('x;' * 2048, id='statements'), pytest.param('\U0000202e' * 4000, id='bidi-run'),
    pytest.param('\U0001f600' * 4000, id='astral-run'), pytest.param('FUN_140001000' * 300, id='one-giant-name'),
    pytest.param('[' * 2000 + ']' * 2000, id='brackets'), pytest.param('a\n' * 2000, id='newlines'),
    pytest.param('\ud800' * 4096, id='lone-surrogates'), pytest.param('0x' + '1' * 4000, id='one-giant-number')])
@pytest.mark.parametrize('language', ['c', 'asm'])
def test_pathological_lines_are_handled_within_a_generous_bound(language, line):
    started = time.perf_counter()
    for other in (line, line[:-1] + 'z', 'q' + line, line + ' tail'):
        assert_well_formed(line, other, diff_row(line, other, language), language)
    assert time.perf_counter() - started < 5.0


def test_two_hundred_worst_case_pairs_stay_inside_a_generous_bound():
    """The deterministic guarantee is the cell cap above; this only checks that nothing else is slow."""
    cases = [(words(31), words(31, prefix='b')), (words(200), words(200, {0, 199})),
             (' '.join(['x'] * 255), ' '.join(['y'] * 255)), (words(255), words(255, prefix='b'))]
    started = time.perf_counter()
    for index in range(200):
        old, new = cases[index % len(cases)]
        diff_row(old, new, 'c')
    assert time.perf_counter() - started < 10.0


# --- UTF-16 offsets ------------------------------------------------------------------------------------------------------

def utf16_units(text: str) -> int:
    return len(text.encode('utf-16-le', 'surrogatepass')) // 2


@FAST
@given(text=st.text(alphabet=st.characters(exclude_categories=()), max_size=80))
def test_utf16_length_and_offset_match_the_utf16_encoding(text):
    assert utf16_length(text) == utf16_units(text)
    for index in range(len(text) + 1):
        assert utf16_offset(text, index) == utf16_units(text[:index])


def test_utf16_offset_clamps_and_treats_a_lone_surrogate_as_one_unit():
    text = 'a\U0001f600b\ud800c'
    assert [utf16_offset(text, i) for i in range(-1, 8)] == [0, 0, 1, 3, 4, 5, 6, 6, 6]
    assert utf16_length(text) == 6 and utf16_length('') == 0 and utf16_length('plain ascii') == 11


# --- the model -------------------------------------------------------------------------------------------------------------

def syn_model(**options) -> CodeTextModel:
    model = CodeTextModel.from_aligned(SYN_ROWS, 'c', **options)
    model.refresh(0, len(SYN_ROWS) - 1)
    return model


def syn_spans(model: CodeTextModel, side: str, row: int):
    old, new, _ = SYN_ROWS[row]
    text = (old if side == 'older' else new) or ''
    return text, model.spans(side, row, text)


def test_a_model_is_built_from_align_lines_rows():
    model = CodeTextModel.from_aligned(SYN_ROWS, 'c')
    assert model.rows == 15 and model.paired_rows == (0, 3, 4, 6, 7, 10, 11) and model.language == 'c'
    assert model._lines['older'][12] == '' and model._lines['newer'][12] == SYN_NEW.splitlines()[12]


def test_syntax_roles_and_marks_become_spans_of_the_exact_tokens():
    model = syn_model()
    text, spans = syn_spans(model, 'older', 7)
    assert decoded(text, spans) == [('if', 'keyword', None), ('lVar2', 'temp', 'rename-maybe'), ('0', 'number', None),
                                    ('param_2', 'temp', None), ('0x20', 'number', 'changed')]
    text, spans = syn_spans(model, 'newer', 7)
    assert decoded(text, spans) == [('if', 'keyword', None), ('lVar3', 'temp', 'rename-maybe'), ('0', 'number', None),
                                    ('param_2', 'temp', None), ('0x40', 'number', 'changed')]
    text, spans = syn_spans(model, 'older', 0)
    assert decoded(text, spans) == [
        ('undefined8', 'keyword', None), ('FUN_140001000', 'address', 'address-only'), ('longlong', 'keyword', None),
        ('param_1', 'temp', None), ('uint', 'keyword', None), ('param_2', 'temp', None),
        ('undefined8', 'keyword', None), ('param_3', 'temp', None)]
    assert syn_spans(model, 'older', 1)[1] == ()  # a blank row


def test_the_default_text_role_without_a_mark_gets_no_span_and_adjacent_equal_spans_merge():
    text = 'x = (int)(long)a;'
    model = CodeTextModel([text], [text], 'c')
    assert decoded(text, model.spans('older', 0, text)) == [('int', 'keyword', None), ('long', 'keyword', None)]
    run = 'int unsigned a;'
    spans = CodeTextModel([run], [run], 'c').spans('older', 0, run)
    assert [(s.start, s.length) for s in spans] == [(0, 3), (4, 8)]  # the blank between is plain, so no merge
    spans = CodeTextModel(['(int)(long)'], ['(int)(long)'], 'c').spans('older', 0, '(int)(long)')
    assert [(s.start, s.length) for s in spans] == [(1, 3), (6, 4)]


def test_marks_cover_the_blanks_inside_a_changed_run_and_equal_neighbours_merge():
    old, new = 'status = a + b + c + d + e + f + g + h;', 'status = a + b + c + d + e + f + g + h + CheckSize(x);'
    model = CodeTextModel([old], [new], 'c', paired=[0])
    model.refresh(0, 0)
    assert decoded(new, model.spans('newer', 0, new)) == [
        ('+ ', 'text', 'changed'), ('CheckSize', 'symbol', 'changed'), ('(x)', 'text', 'changed')]
    assert model.spans('older', 0, old) == ()


def test_colours_and_marks_switch_independently():
    both = syn_model()
    only_marks = syn_model(colors=False)
    only_colors = syn_model(marks=False)
    neither = syn_model(colors=False, marks=False)
    text = SYN_ROWS[7][0]
    assert decoded(text, only_marks.spans('older', 7, text)) == [('lVar2', 'text', 'rename-maybe'),
                                                                 ('0x20', 'text', 'changed')]
    assert decoded(text, only_colors.spans('older', 7, text)) == [
        ('if', 'keyword', None), ('lVar2', 'temp', None), ('0', 'number', None), ('param_2', 'temp', None),
        ('0x20', 'number', None)]
    assert neither.spans('older', 7, text) == ()
    assert len(both.spans('older', 7, text)) == 5
    assert only_colors.row_marks(7) is None and only_colors.summary(7) == '' and only_colors.refresh(0, 14) == Refresh(0, 0)
    assert only_colors.find_change(-1, 1) == Found(None, True)


def test_spans_never_compute_a_mark_and_a_refresh_makes_them_appear():
    model = CodeTextModel.from_aligned(SYN_ROWS, 'c')
    text = SYN_ROWS[7][0]
    assert [s.style_key.mark for s in model.spans('older', 7, text)] == [None] * 5
    assert model.refresh(7, 7) == Refresh(1, 0)
    assert [s.style_key.mark for s in model.spans('older', 7, text)][-1] == 'changed'


@pytest.mark.parametrize('side, row, text', [
    pytest.param('older', 7, 'something else', id='stale-text'),
    pytest.param('older', 7, SYN_ROWS[7][0] + ' ', id='longer-text'),
    pytest.param('older', 7, '', id='empty-text'),
    pytest.param('older', -1, SYN_ROWS[7][0], id='negative-row'),
    pytest.param('older', 15, SYN_ROWS[7][0], id='row-past-the-end'),
    pytest.param('newer', 7, SYN_ROWS[7][0], id='text-of-the-other-side'),
])
def test_a_model_never_formats_text_it_was_not_built_from(side, row, text):
    assert syn_model().spans(side, row, text) == ()


def test_chrome_rows_get_no_spans_no_marks_and_no_sentence():
    model = CodeTextModel.from_aligned(SYN_ROWS, 'c', chrome=[0, 7])
    assert model.paired_rows == (3, 4, 6, 10, 11)
    model.refresh(0, 14)
    assert model.spans('older', 0, SYN_ROWS[0][0]) == () and model.spans('older', 7, SYN_ROWS[7][0]) == ()
    assert model.summary(0) == '' and model.summary(7) == '' and model.row_marks(7) is None
    assert model.spans('older', 3, SYN_ROWS[3][0]) != ()


def test_a_line_over_the_character_cap_has_no_spans_and_says_so():
    long_line = 'x = ' + 'a' * MAX_LINE_CHARS + ';'
    model = CodeTextModel([long_line, 'y = 1;'], ['z = 5;', 'y = 2;'], 'c', paired=[0, 1])
    model.refresh(0, 1)
    assert model.spans('older', 0, long_line) == ()
    assert decoded('z = 5;', model.spans('newer', 0, 'z = 5;')) == [('5', 'number', None)]  # no marks, still coloured
    assert model.summary(0) == long_line_sentence(0) and model.row_marks(0).reason == 'long-line'
    assert model.summary(1) == 'Line 2 of 2: 1 change: constant 1 -> 2.'


def test_a_line_over_the_cap_is_never_tokenized_by_the_model():
    over = 'a' * (MAX_LINE_CHARS + 1)
    model = CodeTextModel([over], [over], 'c')
    with mock.patch.object(model_module, 'tokenize_line') as tokenizer:
        assert model.spans('older', 0, over) == ()
    tokenizer.assert_not_called()


def test_the_character_cap_includes_the_cap_itself():
    at_cap, over = '0 ' + 'a' * (MAX_LINE_CHARS - 2), '0 ' + 'a' * (MAX_LINE_CHARS - 1)
    assert len(at_cap) == MAX_LINE_CHARS
    model = CodeTextModel([at_cap, over], [at_cap, over], 'c')
    assert decoded(at_cap, model.spans('older', 0, at_cap)) == [('0', 'number', None)]
    assert model.spans('older', 1, over) == ()


def test_a_long_line_on_a_row_that_is_not_a_pair_still_explains_itself():
    long_line = 'x = ' + 'a' * MAX_LINE_CHARS
    model = CodeTextModel(['y', long_line], ['y', 'z'], 'c')
    assert model.summary(1) == long_line_sentence(1) and model.summary(0) == ''


def test_the_least_recently_used_entry_is_the_one_dropped():
    cache = model_module._Lru(3)
    for key in 'abc':
        cache.put(key, key.upper())
    assert cache.get('a') == 'A'  # a is now the most recently used
    cache.put('d', 'D')  # b, the least recently used, goes
    assert [key in cache for key in 'abcd'] == [True, False, True, True]
    cache.put('c', 'C2')  # an update counts as a use
    cache.put('e', 'E')  # a is now the least recently used
    assert [key in cache for key in 'acde'] == [False, True, True, True]
    assert cache.get('c') == 'C2' and len(cache._items) == 3


def test_summary_sentences_per_row():
    model = syn_model()
    assert model.summary(7) == 'Line 8 of 15: 1 change: constant 0x20 -> 0x40; 1 possible rename (lVar2 -> lVar3).'
    assert model.summary(10).startswith('Lines are paired by position only (similarity 0.63)')
    assert [model.summary(row) for row in (1, 2, 5, 12, -1, 15)] == [''] * 6  # not a pair, or outside the panes


UTF_OLD, UTF_NEW = 'x = "\U0001f600" + 0x20;', 'x = "\U0001f600" + 0x40;'


def test_spans_are_in_utf16_units_after_a_character_outside_the_bmp():
    model = CodeTextModel([UTF_OLD], [UTF_NEW], 'c', paired=[0])
    model.refresh(0, 0)
    assert model.row_marks(0).old[0].start == 10  # code points
    assert model.spans('older', 0, UTF_OLD) == (FormatSpan(4, 4, StyleKey('string', None)),
                                                 FormatSpan(11, 4, StyleKey('number', 'changed')))
    lone = 'x = "\ud800" + 0x20;'
    other = 'x = "\ud800" + 0x40;'
    model = CodeTextModel([lone], [other], 'c', paired=[0])
    model.refresh(0, 0)
    assert model.spans('older', 0, lone) == (FormatSpan(4, 3, StyleKey('string', None)),
                                              FormatSpan(10, 4, StyleKey('number', 'changed')))


@FAST
@given(text=SOUP)
def test_spans_stay_inside_the_block_in_utf16_units_for_any_text(text):
    for language in ('c', 'asm'):
        model = CodeTextModel([text], [text + ' '], language, paired=[0])
        model.refresh(0, 0)
        end = utf16_length(text)
        position = 0
        for span in model.spans('older', 0, text):
            assert position <= span.start and span.length > 0 and span.start + span.length <= end
            assert isinstance(span.style_key, StyleKey)
            position = span.start + span.length


def test_a_comment_that_spans_rows_is_coloured_as_a_comment_on_the_rows_it_covers():
    older = ['int x; /* start', ' still comment FUN_140001000 */', 'y = 1;']
    newer = ['int x; /* start', ' still comment FUN_140001040 */', 'y = 2;']
    model = CodeTextModel(older, newer, 'c', paired=[1, 2])
    model.refresh(0, 2)
    assert decoded(older[1], model.spans('older', 1, older[1]))[0][:2] == (older[1], 'comment')
    assert model.row_marks(1).old[0].label == 'token' and model.row_marks(1).old[0].state == 'changed'
    assert decoded(older[0], model.spans('older', 0, older[0])) == [('int', 'keyword', None), ('/* start', 'comment', None)]
    assert [m.label for m in model.row_marks(2).old] == ['constant']


def test_assembly_rows_use_the_assembly_rules():
    older, newer = ['MOV RAX,qword ptr [RSP + 0x28]'], ['MOV RAX,qword ptr [RSP + 0x30]']
    model = CodeTextModel(older, newer, 'asm', paired=[0])
    model.refresh(0, 0)
    assert decoded(older[0], model.spans('older', 0, older[0])) == [
        ('MOV', 'mnemonic', None), ('RAX', 'register', None), ('qword', 'size', None), ('ptr', 'size', None),
        ('RSP', 'register', None), ('0x28', 'stack', 'changed')]


def test_the_oracles_reach_the_marks():
    older, newer = ['CALL FUN_140001000'], ['CALL FUN_140001040']
    model = CodeTextModel(older, newer, 'asm', paired=[0], targets=MatchPairOracle([(0x140001000, 0x140009000)]))
    assert model.row_marks(0).has_change and 'not a matched pair' in model.summary(0)
    assert not CodeTextModel(older, newer, 'asm', paired=[0]).row_marks(0).has_change
    renamed = CodeTextModel(['uVar1 = a;'], ['uVar2 = a;'], 'c', paired=[0], renames=Renames('conflict'))
    assert renamed.row_marks(0).has_change and 'inconsistent rename' in renamed.summary(0)
    assert not CodeTextModel(['uVar1 = a;'], ['uVar2 = a;'], 'c', paired=[0]).row_marks(0).has_change


@pytest.mark.parametrize('arguments, message', [
    pytest.param((['a'], ['a', 'b'], 'c'), 'same number of rows', id='older-pane-shorter'),
    pytest.param((['a', 'b'], ['a'], 'c'), 'same number of rows', id='older-pane-longer'),
    pytest.param((['a'], ['a'], 'rust'), 'unknown language', id='unknown-language'),
])
def test_construction_errors_are_programming_errors(arguments, message):
    with pytest.raises(ValueError, match=message):
        CodeTextModel(*arguments)


@pytest.mark.parametrize('options', [{'paired': [1]}, {'paired': [-1]}, {'chrome': [2]}], ids=['past', 'negative', 'chrome'])
def test_a_row_outside_the_panes_is_a_programming_error(options):
    with pytest.raises(ValueError, match='outside the 1 rows'):
        CodeTextModel(['a'], ['b'], 'c', **options)


def test_the_model_is_deterministic():
    first, second = syn_model(), syn_model()
    for side in ('older', 'newer'):
        for row in range(15):
            text = SYN_ROWS[row][0 if side == 'older' else 1] or ''
            assert first.spans(side, row, text) == second.spans(side, row, text)
    assert [first.summary(r) for r in range(15)] == [second.summary(r) for r in range(15)]


# --- bounded refreshes -----------------------------------------------------------------------------------------------------

def counted_model(count: int) -> CodeTextModel:
    return CodeTextModel([f'x = {i};' for i in range(count)], [f'x = {i + 1000};' for i in range(count)], 'c',
                         paired=range(count))


def test_a_refresh_computes_at_most_200_pairs_in_row_order_and_reports_the_rest():
    model = counted_model(450)
    assert model.refresh(0, 449) == Refresh(200, 250)
    marked = [row for row in range(450) if any(s.style_key.mark for s in model.spans('older', row, f'x = {row};'))]
    assert marked == list(range(200))
    assert model.refresh(0, 449) == Refresh(200, 50)
    assert model.refresh(0, 449) == Refresh(50, 0)
    assert model.refresh(0, 449) == Refresh(0, 0)  # nothing is computed twice


def test_a_refresh_only_looks_at_its_window():
    model = counted_model(450)
    assert model.refresh(100, 109) == Refresh(10, 0)
    assert model.refresh(105, 119) == Refresh(10, 0)  # rows 105..109 are remembered
    assert model.refresh(-5, 2) == Refresh(3, 0)
    assert model.refresh(460, 470) == Refresh(0, 0)


def hostile_pair(index: int) -> tuple[str, str]:
    """250 tokens with every 17th respelled: it passes the gate and its table has about 7,200 cells."""
    first = words(250).split()
    second = [('z' + w[1:]) if i % 17 == 0 else w for i, w in enumerate(first)]
    return ' '.join(first) + f' ; r{index}', ' '.join(second) + f' ; r{index}'


def test_a_refresh_also_stops_when_its_alignment_work_is_spent():
    pairs = [hostile_pair(i) for i in range(80)]
    model = CodeTextModel([old for old, _ in pairs], [new for _, new in pairs], 'c', paired=range(80))
    work = diff_row(*pairs[0], 'c').work
    assert 0 < work <= MAX_DP_CELLS and work * 80 > MAX_WORK_PER_REFRESH
    expected = -(-MAX_WORK_PER_REFRESH // work)  # rows are started until the budget is reached
    assert expected < MAX_PAIRS_PER_REFRESH
    assert model.refresh(0, 79) == Refresh(expected, 80 - expected)
    assert model.refresh(0, 79).computed == expected  # the next window of rows
    assert model.refresh(0, 79).computed == 80 - 2 * expected


def changing_last_model(count: int) -> CodeTextModel:
    older = [f'y = FUN_1000{i:04x}(a);' for i in range(count - 1)] + ['y = 1;']
    newer = [f'y = FUN_1000{i + 1:04x}(a);' for i in range(count - 1)] + ['y = 2;']
    return CodeTextModel(older, newer, 'c', paired=range(count))


def test_a_scan_for_the_next_change_is_bounded_and_resumes_where_the_cache_ends():
    model = changing_last_model(450)
    assert model.find_change(-1, +1, limit=100) == Found(None, False)  # rows 0..99 computed, none has a change
    assert len(model._pairs._items) == 100
    assert model.find_change(-1, +1, limit=100) == Found(None, False)  # 0..99 are free, 100..199 computed
    assert len(model._pairs._items) == 200
    assert model.find_change(-1, +1, limit=100) == Found(None, False)
    assert model.find_change(-1, +1, limit=100) == Found(None, False)
    assert model.find_change(-1, +1, limit=100) == Found(449, True)  # 400..449 computed
    assert model.find_change(450, -1) == Found(449, True)
    assert model.find_change(449, -1) == Found(None, True)  # every row before it is only address-only
    assert model.find_change(449, +1) == Found(None, True)
    assert model.find_change(3, 0) == Found(None, True)


def test_the_scan_stops_when_the_alignment_work_is_spent():
    model = changing_last_model(450)
    assert diff_row('y = FUN_10000000(a);', 'y = FUN_10000001(a);', 'c').work == 2  # a one-token middle
    with mock.patch.object(model_module, 'MAX_WORK_PER_REFRESH', 4):
        assert model.find_change(-1, +1) == Found(None, False)
        assert len(model._pairs._items) == 2  # rows 0 and 1 cost 2 + 2 cells: the budget of 4 is reached, not exceeded
        assert model.find_change(-1, +1) == Found(None, False)  # rows 0 and 1 are free; 2 and 3 spend the budget again
        assert len(model._pairs._items) == 4
        assert model.refresh(0, 449) == Refresh(2, 450 - 4 - 2)


def test_the_caches_are_bounded():
    count = LRU_LINES + 500
    model = CodeTextModel([f'x = {i};' for i in range(count)], [f'x = {i};' for i in range(count)], 'c',
                         paired=range(0, count, 1))
    for row in range(count):
        model.spans('older', row, f'x = {row};')
    assert len(model._syntax._items) == LRU_LINES
    assert model.find_change(-1, +1, limit=count) == Found(None, True)
    assert len(model._pairs._items) == LRU_LINES


def test_two_hundred_typical_pairs_refresh_quickly():
    """Measured about 20 ms here (the plan's budget is 60 ms); best of three, gated at 150 ms for a loaded runner."""
    pairs = [(SYN_ROWS[i][0], SYN_ROWS[i][1]) for i in (0, 3, 4, 6, 7, 10, 11)] * 29
    best, result = float('inf'), None
    for _ in range(3):
        model = CodeTextModel([old for old, _ in pairs], [new for _, new in pairs], 'c', paired=range(len(pairs)))
        started = time.perf_counter()
        result = model.refresh(0, len(pairs) - 1)
        best = min(best, time.perf_counter() - started)
    assert result == Refresh(200, 3) and best < 0.15
