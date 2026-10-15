"""WBQ S7 (codetext-core): the lexical tokenizer and the Ghidra name classes. Synthetic text only: no binaries, no Qt.

Gates from docs/specs/program-e/WBQ-integration-plan.md (s9 row S7): lossless and total on any text (hypothesis);
agrees with Pygments on comment, string and number boundaries (dev oracle, skipped when Pygments is absent);
200 KB in under 150 ms. Besides those: bounded work on hostile text, the documented limits, and no Qt or third-party
import in the package.
"""
from __future__ import annotations

import ast
import subprocess
import sys
import time
from pathlib import Path
from unittest import mock

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from patchtrace.codetext import names, tokens
from patchtrace.codetext.names import AutoName, classify_name, is_temp_name, parse_auto_name
from patchtrace.codetext.tokens import (
    KINDS,
    MAX_DOCUMENT_CHARS,
    MAX_LINE_CHARS,
    Token,
    open_comment_lines,
    tokenize,
    tokenize_line,
)

FAST = settings(deadline=None, suppress_health_check=[HealthCheck.too_slow], max_examples=150)
SRC = Path(__file__).parents[1] / 'src'
PACKAGE = SRC / 'patchtrace' / 'codetext'
LANGUAGES = ['c', 'asm']

# Fragments that stress the scanners: quotes, escapes, comment markers, number starts, controls, bidi and
# line-separator characters, lone surrogates, names of every class.
FRAGMENTS = ['"', "'", '\\', '/*', '*/', '//', ';', '\n', '\r\n', ' ', '\t', '\x00', '\x0b', 'L"', 'u8"', "L'", '0x',
             '1e-', '.5', '::', '->', '...', '\u202e', '\u200b', '\u2028', '\x85', '\ud800', '\u00e9', 'FUN_140001000',
             'uVar1', 'param_1', 'mov', 'rax', 'ptr', '[', ']', '(', ')', ',', ':', 'x', '0']
SOUP = st.lists(st.sampled_from(FRAGMENTS), max_size=80).map(''.join)
ANY_TEXT = st.one_of(st.text(alphabet=st.characters(exclude_categories=()), max_size=120), SOUP)


def assert_covers(text: str, found: tuple[Token, ...], plain_tail_from: int | None = None) -> None:
    """The whole contract of a token list: contiguous, non-empty, known kinds, newlines only as their own `ws`
    (except inside the single plain tail a document cap leaves)."""
    position = 0
    for token in found:
        piece = text[token.start:token.end]
        assert token.kind in KINDS
        assert token.start == position and token.end > token.start
        if plain_tail_from is None or token.start < plain_tail_from:
            assert '\n' not in piece or (token.kind == 'ws' and piece == '\n')
        else:
            assert token.kind == 'other' and token.start == plain_tail_from and token.end == len(text)
        position = token.end
    assert position == len(text)
    assert ''.join(text[t.start:t.end] for t in found) == text


def lexed(text: str, language: str) -> list[tuple[str, str]]:
    found = tokenize(text, language)
    assert_covers(text, found)
    return [(t.kind, text[t.start:t.end]) for t in found if t.kind != 'ws']


def expected(spec: str) -> list[tuple[str, str]]:
    """'kind:text | kind:text'; a kind never contains a colon, a text may."""
    return [tuple(part.split(':', 1)) for part in spec.split(' | ')]


# --- contract ---------------------------------------------------------------------------------------------------

def test_kinds_are_the_codetext_1_list():
    assert KINDS == ('ws', 'comment', 'string', 'char', 'number', 'keyword', 'type', 'auto_name', 'temp', 'ident',
                     'op', 'mnemonic', 'register', 'size', 'symbol', 'punct', 'other')


def test_public_names_resolve_and_the_contract_is_named():
    import patchtrace.codetext as codetext

    assert codetext.CONTRACT == 'codetext/1'
    assert len(set(codetext.__all__)) == len(codetext.__all__)
    for name in codetext.__all__:
        assert hasattr(codetext, name), name


def test_empty_text_has_no_tokens():
    assert tokenize('', 'c') == () and tokenize('', 'asm') == ()
    assert open_comment_lines('') == frozenset()
    assert tokenize_line('', 'c') == ((), False)


def test_unknown_language_is_a_programming_error():
    with pytest.raises(ValueError, match='unknown language'):
        tokenize('x', 'rust')
    with pytest.raises(ValueError, match='unknown language'):
        tokenize_line('x', 'rust')


# --- lossless and total -------------------------------------------------------------------------------------------

@pytest.mark.parametrize('language', LANGUAGES)
@FAST
@given(text=ANY_TEXT)
def test_tokens_cover_any_text_exactly(language, text):
    assert_covers(text, tokenize(text, language))


@pytest.mark.parametrize('language', LANGUAGES)
def test_lone_surrogates_nul_and_astral_characters_are_text(language):
    text = 'a\ud800b\udfff \x00 \U0001f600 \u202e x\u2028y'
    assert_covers(text, tokenize(text, language))


@pytest.mark.parametrize('language', LANGUAGES)
def test_crlf_line_endings_keep_every_character(language):
    text = 'a,\r\nb,\r\n'
    found = tokenize(text, language)
    assert_covers(text, found)
    assert [text[t.start:t.end] for t in found if t.kind == 'ws'] == ['\r', '\n', '\r', '\n']


@FAST
@given(text=SOUP)
def test_window_states_equal_the_document_scan(text):
    """A window may start anywhere if it is given the comment state of its first line (open_comment_lines)."""
    lines = text.split('\n')
    state, base, open_lines, chained = False, 0, set(), []
    for number, line in enumerate(lines):
        if state:
            open_lines.add(number)
        line_tokens, state = tokenize_line(line, 'c', state)
        chained += [Token(t.kind, base + t.start, base + t.end) for t in line_tokens]
        base += len(line) + 1
    assert open_comment_lines(text) == open_lines
    document = [t for t in tokenize(text, 'c') if text[t.start:t.end] != '\n']
    assert document == chained


@FAST
@given(text=SOUP, limit=st.integers(1, 12), cap=st.integers(0, 80))
def test_limits_keep_the_contract_and_the_state_equivalence(text, limit, cap):
    found = tokenize(text, 'c', max_line_chars=limit, max_chars=cap)
    cut = len(text) if len(text) <= cap else text.rfind('\n', 0, cap) + 1
    assert_covers(text, found, plain_tail_from=cut if cut < len(text) else None)
    lines = text[:cut].split('\n')
    state, open_lines = False, set()
    for number, line in enumerate(lines):
        if state:
            open_lines.add(number)
        state = tokenize_line(line, 'c', state, max_chars=limit).in_comment
    assert open_comment_lines(text, max_chars=cap) == open_lines


@pytest.mark.parametrize('language', LANGUAGES)
@FAST
@given(text=ANY_TEXT)
def test_word_memo_never_changes_a_result(language, text):
    memo = tokens._C_MEMO if language == 'c' else tokens._ASM_MEMO
    memo.clear()
    cold = tokenize(text, language)
    assert tokenize(text, language) == cold  # warm
    with mock.patch.object(tokens, '_MEMO_MAX', 2):  # the memo empties itself in the middle of the scan
        assert tokenize(text, language) == cold


# --- classification (reviewed by hand against Ghidra's output forms) -------------------------------------------

C_CASES = [
    pytest.param('uint uVar1;', 'type:uint | temp:uVar1 | punct:;', id='temp-declaration'),
    pytest.param('if ((param_1 < 0x20) && (uVar1 != 0)) {',
                 'keyword:if | punct:( | punct:( | temp:param_1 | op:< | number:0x20 | punct:) | op:&& | punct:( '
                 '| temp:uVar1 | op:!= | number:0 | punct:) | punct:) | punct:{', id='condition'),
    pytest.param('x = CreateFileW (a, b);',
                 'ident:x | op:= | symbol:CreateFileW | punct:( | ident:a | punct:, | ident:b | punct:) | punct:;',
                 id='named-callee-with-space'),
    pytest.param('y = (*pcVar3)(1);',
                 'ident:y | op:= | punct:( | op:* | temp:pcVar3 | punct:) | punct:( | number:1 | punct:) | punct:;',
                 id='indirect-call'),
    pytest.param('FUN_140001000(DAT_14000b000, PTR_FUN_14000c010);',
                 'auto_name:FUN_140001000 | punct:( | auto_name:DAT_14000b000 | punct:, | auto_name:PTR_FUN_14000c010 '
                 '| punct:) | punct:;', id='auto-names'),
    pytest.param('thunk_FUN_140001000();', 'auto_name:thunk_FUN_140001000 | punct:( | punct:) | punct:;',
                 id='thunk'),
    pytest.param('return -5;', 'keyword:return | op:- | number:5 | punct:;', id='sign-is-an-operator'),
    pytest.param('x = a->b.c;', 'ident:x | op:= | ident:a | op:-> | ident:b | op:. | ident:c | punct:;',
                 id='member-access'),
    pytest.param('a <<= 2; b >>= 1; c ... d',
                 'ident:a | op:<<= | number:2 | punct:; | ident:b | op:>>= | number:1 | punct:; | ident:c | op:... '
                 '| ident:d', id='long-operators'),
    pytest.param('CParser::ParsePacket(this, local_18);',
                 'symbol:CParser::ParsePacket | punct:( | ident:this | punct:, | temp:local_18 | punct:) | punct:;',
                 id='scoped-callee'),
    pytest.param(r'p = L"wide\n" "x" u8"y";',
                 r'ident:p | op:= | string:L"wide\n" | string:"x" | string:u8"y" | punct:;', id='string-prefixes'),
    pytest.param(r"""c = 'a' + '\n' + '\'' + L'w';""",
                 r"""ident:c | op:= | char:'a' | op:+ | char:'\n' | op:+ | char:'\'' | op:+ | char:L'w' | punct:;""",
                 id='char-literals'),
    pytest.param('n = 0x20U + 0xFFul + 017 + 5 + 1.5f + .5 + 2e-3 + 1E+5 + 0x1p3 + 0b101;',
                 'ident:n | op:= | number:0x20U | op:+ | number:0xFFul | op:+ | number:017 | op:+ | number:5 | op:+ '
                 '| number:1.5f | op:+ | number:.5 | op:+ | number:2e-3 | op:+ | number:1E+5 | op:+ | number:0x1p3 '
                 '| op:+ | number:0b101 | punct:;', id='number-forms'),
    pytest.param('0xe+1', 'number:0xe | op:+ | number:1', id='hex-e-does-not-take-the-sign'),
    pytest.param('a/*c*/b // tail', 'ident:a | comment:/*c*/ | ident:b | comment:// tail', id='inline-comments'),
    pytest.param('x /* open', 'ident:x | comment:/* open', id='unterminated-block'),
    pytest.param('/*/ x', 'comment:/*/ x', id='slash-star-slash-is-not-closed'),
    pytest.param('dword y = (undefined8 *)z;',
                 'type:dword | ident:y | op:= | punct:( | type:undefined8 | op:* | punct:) | ident:z | punct:;',
                 id='ghidra-types'),
    pytest.param('switchD_140001234::caseD_5:', 'ident:switchD_140001234::caseD_5 | punct::', id='switch-label'),
    pytest.param('__fastcall FUN_140001000', 'keyword:__fastcall | auto_name:FUN_140001000',
                 id='calling-convention'),
    pytest.param('x = a ? b : c;',
                 'ident:x | op:= | ident:a | op:? | ident:b | punct:: | ident:c | punct:;', id='conditional'),
    pytest.param('int i\u00e9 = 1;', 'type:int | ident:i | other:\u00e9 | op:= | number:1 | punct:;',
                 id='non-ascii-is-other'),
    pytest.param('foo\x00bar', 'ident:foo | other:\x00 | ident:bar', id='nul-is-other'),
    pytest.param('a = b @ c # d $ e \\ f',
                 'ident:a | op:= | ident:b | other:@ | ident:c | other:# | ident:d | other:$ | ident:e | other:\\ '
                 '| ident:f', id='stray-characters'),
    pytest.param('sizeof(int) + true + NULL',
                 'keyword:sizeof | punct:( | type:int | punct:) | op:+ | keyword:true | op:+ | keyword:NULL',
                 id='keywords-and-constants'),
    pytest.param('x = y /= 3;', 'ident:x | op:= | ident:y | op:/= | number:3 | punct:;', id='compound-assignment'),
    pytest.param('in_RAX, unaff_RBX, extraout_RAX, iStack_14, local_res8, stack0x00000008',
                 'temp:in_RAX | punct:, | temp:unaff_RBX | punct:, | temp:extraout_RAX | punct:, | temp:iStack_14 '
                 '| punct:, | temp:local_res8 | punct:, | temp:stack0x00000008', id='temp-forms'),
]
ASM_CASES = [
    pytest.param('MOV RAX,qword ptr [RSP + 0x28]',
                 'mnemonic:MOV | register:RAX | punct:, | size:qword | size:ptr | punct:[ | register:RSP | op:+ '
                 '| number:0x28 | punct:]', id='memory-operand'),
    pytest.param('CALL qword ptr [->KERNEL32.DLL::CreateFileW]',
                 'mnemonic:CALL | size:qword | size:ptr | punct:[ | op:-> | symbol:KERNEL32.DLL::CreateFileW '
                 '| punct:]', id='import-call'),
    pytest.param('CALL FUN_140002340', 'mnemonic:CALL | auto_name:FUN_140002340', id='direct-call'),
    pytest.param('LAB_140001234:', 'auto_name:LAB_140001234 | punct::', id='label-line'),
    pytest.param('JZ LAB_140001234', 'mnemonic:JZ | auto_name:LAB_140001234', id='branch'),
    pytest.param('LOCK CMPXCHG dword ptr [RCX],EDX ; swap',
                 'mnemonic:LOCK | mnemonic:CMPXCHG | size:dword | size:ptr | punct:[ | register:RCX | punct:] '
                 '| punct:, | register:EDX | comment:; swap', id='prefix-and-comment'),
    pytest.param('REP STOSQ', 'mnemonic:REP | mnemonic:STOSQ', id='rep-prefix'),
    pytest.param('MOV EAX,dword ptr [RBP + -0x4]',
                 'mnemonic:MOV | register:EAX | punct:, | size:dword | size:ptr | punct:[ | register:RBP | op:+ '
                 '| op:- | number:0x4 | punct:]', id='negative-displacement'),
    pytest.param('MOV RAX,qword ptr GS:[0x30]',
                 'mnemonic:MOV | register:RAX | punct:, | size:qword | size:ptr | register:GS | punct:: | punct:[ '
                 '| number:0x30 | punct:]', id='segment-override'),
    pytest.param('MOVAPS xmmword ptr [RSP + 0x20],XMM0',
                 'mnemonic:MOVAPS | size:xmmword | size:ptr | punct:[ | register:RSP | op:+ | number:0x20 | punct:] '
                 '| punct:, | register:XMM0', id='simd'),
    pytest.param('LEA RAX,[RIP + 0x2f1c]',
                 'mnemonic:LEA | register:RAX | punct:, | punct:[ | register:RIP | op:+ | number:0x2f1c | punct:]',
                 id='rip-relative'),
    pytest.param('MOV R8D,0x20', 'mnemonic:MOV | register:R8D | punct:, | number:0x20', id='extended-register'),
    pytest.param('ADD RSP,-0x80', 'mnemonic:ADD | register:RSP | punct:, | op:- | number:0x80',
                 id='negative-immediate'),
    pytest.param('MOV EAX,"abc"', 'mnemonic:MOV | register:EAX | punct:, | string:"abc"', id='string-operand'),
    pytest.param("mov al,'a'", "mnemonic:mov | register:al | punct:, | char:'a'", id='char-operand'),
    pytest.param('CALL ?ParsePacket@CParser@@QEAAJPEBEK@Z', 'mnemonic:CALL | symbol:?ParsePacket@CParser@@QEAAJPEBEK@Z',
                 id='decorated-name'),
    pytest.param('MOV dword ptr [RSP + local_10],EAX',
                 'mnemonic:MOV | size:dword | size:ptr | punct:[ | register:RSP | op:+ | temp:local_10 | punct:] '
                 '| punct:, | register:EAX', id='stack-variable'),
    pytest.param('JMP qword ptr [PTR_FUN_14000c010]',
                 'mnemonic:JMP | size:qword | size:ptr | punct:[ | auto_name:PTR_FUN_14000c010 | punct:]',
                 id='pointer-cell'),
    pytest.param('mov eax, 10h', 'mnemonic:mov | register:eax | punct:, | number:10h', id='h-suffix'),
    pytest.param('MOV ST0,st1,ymm15,zmm31,k7,cr3',
                 'mnemonic:MOV | register:ST0 | punct:, | register:st1 | punct:, | register:ymm15 | punct:, '
                 '| register:zmm31 | punct:, | register:k7 | punct:, | register:cr3', id='register-families'),
    pytest.param('140001000 MOV RAX,RBX',
                 'number:140001000 | mnemonic:MOV | register:RAX | punct:, | register:RBX', id='address-column'),
    pytest.param('DAT_14000b000 DB 0x90', 'auto_name:DAT_14000b000 | mnemonic:DB | number:0x90',
                 id='generated-name-is-not-a-mnemonic'),
    pytest.param('CALL Ordinal_12', 'mnemonic:CALL | symbol:Ordinal_12', id='ordinal-import-is-a-name'),
    pytest.param('MOV EAX,1.5', 'mnemonic:MOV | register:EAX | punct:, | number:1.5', id='decimal-point'),
    pytest.param('mov Rax,QWORD PTR [rsp]',
                 'mnemonic:mov | register:Rax | punct:, | size:QWORD | size:PTR | punct:[ | register:rsp | punct:]',
                 id='case-insensitive'),
    pytest.param('ADD X0,X1,#0x10', 'mnemonic:ADD | symbol:X0 | punct:, | symbol:X1 | punct:, | other:# | number:0x10',
                 id='arm-registers-are-names'),
    pytest.param('ret', 'mnemonic:ret', id='bare-mnemonic'),
]


@pytest.mark.parametrize('text, spec', C_CASES)
def test_c_classification(text, spec):
    assert lexed(text, 'c') == expected(spec)


@pytest.mark.parametrize('text, spec', ASM_CASES)
def test_asm_classification(text, spec):
    assert lexed(text, 'asm') == expected(spec)


def test_block_comment_is_one_comment_token_per_line_and_newlines_stay_ws():
    text = 'a /* x\ny */ b\n'
    assert tokenize(text, 'c') == (
        Token('ident', 0, 1), Token('ws', 1, 2), Token('comment', 2, 6), Token('ws', 6, 7),
        Token('comment', 7, 11), Token('ws', 11, 12), Token('ident', 12, 13), Token('ws', 13, 14))
    assert open_comment_lines(text) == {1}


def test_a_line_that_starts_inside_a_comment_and_closes_it_resumes_normal_scanning():
    assert tokenize_line('b */ int x; /* again', 'c', in_comment=True) == (
        (Token('comment', 0, 4), Token('ws', 4, 5), Token('type', 5, 8), Token('ws', 8, 9), Token('ident', 9, 10),
         Token('punct', 10, 11), Token('ws', 11, 12), Token('comment', 12, 20)), True)


def test_a_comment_marker_inside_a_string_or_line_comment_opens_nothing():
    text = 'a = "/* no"; // /* nor\nb;\n/* yes\nc */\n'
    assert open_comment_lines(text) == {3}


def test_assembly_has_no_block_comments():
    assert tokenize_line('MOV /* x', 'asm', in_comment=True).in_comment is False
    assert 'comment' not in {t.kind for t in tokenize('/* x\n y */', 'asm')}


def test_tokenize_line_offsets_are_relative_to_the_line():
    line_tokens, _ = tokenize_line('x = 1;', 'c')
    assert line_tokens[0] == Token('ident', 0, 1) and line_tokens[-1] == Token('punct', 5, 6)


# --- Ghidra names ------------------------------------------------------------------------------------------------

AUTO_ACCEPTED = ['FUN_140001000', 'thunk_FUN_140001000', 'SUB_00401000', 'LAB_1000', 'DAT_14000b000', 'UNK_140001000',
                 'EXT_FUN_140001000', 'EXT_140001000', 'OFF_140001000', 'PTR_FUN_140001000', 'PTR_DAT_14000b000',
                 'PTR_14000b000', '_DAT_14000b000', 'BYTE_140001000', 'WORD_140001000', 'DWORD_14000b000',
                 'QWORD_14000b000', 'FLOAT_14000b000', 'DOUBLE_14000b000', 'ADDR_14000b000', 'FUN_ABCDEF01',
                 'FUN_1234567890abcdef']
AUTO_REJECTED = ['', 'FUN_', 'FUN_123', 'FUN_14000100x', 'FUN_12345678901234567', 'fun_140001000', 'CreateFileW',
                 'Ordinal_12', 's_hello_140001000', 'FUN_140001000_1', 'switchD_140001234', 'PTRDAT_140001000',
                 'thunk_', 'local_18', 'FUN_140001000::x', 'myFUN_140001000', 'FUN_140001000 ', 'FUN__140001000']
TEMP_ACCEPTED = ['uVar1', 'bVar1', 'lVar12', 'pcVar3', 'ppuVar4', 'pppuVar5', 'iStack_14', 'uStack_8', 'local_18',
                 'local_res8', 'param_1', 'param_12', 'in_RAX', 'in_stack_00000008', 'unaff_RBX', 'extraout_RAX',
                 'stack0x00000008']
TEMP_REJECTED = ['', 'Var1', 'xVar', 'uVar', 'ppppuVar1', 'UVar1', 'uVar1x', 'param_x', 'param_', 'local_', 'local_xyz',
                 'Param_1', 'in_', 'stack0x', 'FUN_140001000', 'CreateFileW', 'buffer', 'uVar\u0663']


@pytest.mark.parametrize('name', AUTO_ACCEPTED)
def test_auto_names_are_recognised(name):
    assert parse_auto_name(name) is not None
    assert classify_name(name) == 'auto_name'
    assert names.AUTO_NAME.fullmatch(name)


@pytest.mark.parametrize('name', AUTO_REJECTED)
def test_other_names_are_not_auto_names(name):
    assert parse_auto_name(name) is None
    assert classify_name(name) != 'auto_name'


@pytest.mark.parametrize('name', TEMP_ACCEPTED)
def test_decompiler_temporaries_are_recognised(name):
    assert is_temp_name(name)
    assert classify_name(name) == 'temp'


@pytest.mark.parametrize('name', TEMP_REJECTED)
def test_other_names_are_not_temporaries(name):
    assert not is_temp_name(name)
    assert classify_name(name) != 'temp'


@pytest.mark.parametrize('name, kind, address', [
    pytest.param('FUN_140001000', 'function', 0x140001000, id='function'),
    pytest.param('SUB_00401000', 'function', 0x401000, id='subroutine'),
    pytest.param('thunk_FUN_140001000', 'function', 0x140001000, id='thunk'),
    pytest.param('EXT_FUN_140001000', 'function', 0x140001000, id='external-function'),
    pytest.param('LAB_140001234', 'label', 0x140001234, id='label'),
    pytest.param('DAT_14000b000', 'data', 0x14000b000, id='data'),
    pytest.param('_DAT_14000b000', 'data', 0x14000b000, id='decompiler-global'),
    pytest.param('PTR_FUN_14000c010', 'data', 0x14000c010, id='pointer-cell-is-data'),
    pytest.param('PTR_14000c010', 'data', 0x14000c010, id='bare-pointer'),
    pytest.param('EXT_14000c010', 'data', 0x14000c010, id='external-entry'),
    pytest.param('OFF_14000c010', 'data', 0x14000c010, id='offcut'),
    pytest.param('DWORD_14000b000', 'data', 0x14000b000, id='typed-data'),
    pytest.param('UNK_1000', 'data', 0x1000, id='four-digit-address'),
])
def test_parse_auto_name_says_what_the_name_points_at(name, kind, address):
    assert parse_auto_name(name) == AutoName(kind, address)


@pytest.mark.parametrize('name', ['PTR_' * 5000 + 'x', 'a' * 5000 + 'Var', 'in_' + '_' * 5000 + '!',
                                  'FUN_' + '1' * 5000, 'thunk_EXT_' * 800, 'local_' + '0' * 5000 + 'g'],
                         ids=['ptr-repeat', 'var-tail', 'in-underscores', 'long-address', 'prefix-repeat',
                              'long-local'])
def test_name_patterns_do_not_backtrack_on_hostile_names(name):
    started = time.perf_counter()
    classify_name(name)
    parse_auto_name(name)
    is_temp_name(name)
    assert time.perf_counter() - started < 2.5      # 5x slack for shared CI; catastrophic backtracking takes far longer


# --- limits -------------------------------------------------------------------------------------------------------

def test_a_line_over_the_cap_is_one_plain_token():
    text = 'int ' + 'x ' * 10 + ';'
    assert tokenize(text, 'c', max_line_chars=10) == (Token('other', 0, len(text)),)
    assert tokenize(text, 'asm', max_line_chars=10) == (Token('other', 0, len(text)),)
    assert tokenize_line(text, 'c', max_chars=10) == ((Token('other', 0, len(text)),), False)


def test_a_line_exactly_at_the_cap_is_still_tokenized():
    text = 'int xxxxx;'
    assert [t.kind for t in tokenize(text, 'c', max_line_chars=len(text))] == ['type', 'ws', 'ident', 'punct']


def test_the_default_caps():
    assert MAX_LINE_CHARS == 4_096 and MAX_DOCUMENT_CHARS == 1_048_576
    exact = 'x' * MAX_LINE_CHARS
    assert tokenize(exact, 'c') == (Token('ident', 0, MAX_LINE_CHARS),)
    assert tokenize(exact + 'x', 'c') == (Token('other', 0, MAX_LINE_CHARS + 1),)


def test_a_long_line_that_opens_a_comment_keeps_the_next_line_inside_it():
    text = '/* ' + 'x' * 30 + '\na */ int;'
    found = tokenize(text, 'c', max_line_chars=10)
    assert_covers(text, found)
    assert found[0] == Token('other', 0, 33)
    assert [(t.kind, text[t.start:t.end]) for t in found[2:] if t.kind != 'ws'] == [
        ('comment', 'a */'), ('type', 'int'), ('punct', ';')]
    assert tokenize_line(text[:33], 'c', max_chars=10).in_comment is True


def test_a_long_line_inside_a_comment_stays_inside_it():
    text = '/*\n' + 'x' * 30 + '\nint'
    found = tokenize(text, 'c', max_line_chars=10)
    assert_covers(text, found)
    assert [t.kind for t in found if t.kind != 'ws'] == ['comment', 'other', 'comment']
    assert tokenize_line('x' * 30, 'c', True, max_chars=10).in_comment is True


def test_a_long_line_that_closes_a_comment_ends_it():
    text = '/* open\n' + ' ' * 30 + '*/\nint a;'
    found = tokenize(text, 'c', max_line_chars=10)
    assert_covers(text, found)
    assert [t.kind for t in found if t.kind != 'ws'] == ['comment', 'other', 'type', 'ident', 'punct']
    assert tokenize_line(' ' * 30 + '*/', 'c', True, max_chars=10).in_comment is False


def test_document_cap_keeps_whole_lines_then_one_plain_tail():
    text = 'int a;\nint b;\nint c;\n'
    found = tokenize(text, 'c', max_chars=15)
    assert found[-1] == Token('other', 14, 21)  # this tail spans a line break: it is one token on purpose
    assert found[:-1] == tokenize(text[:14], 'c')
    assert_covers(text, found, plain_tail_from=14)


def test_document_cap_smaller_than_the_first_line_leaves_everything_plain():
    text = 'x' * 50 + '\ny'
    assert tokenize(text, 'c', max_chars=10) == (Token('other', 0, len(text)),)


def test_document_cap_at_the_text_length_changes_nothing():
    text = 'int a;\nint b;'
    assert tokenize(text, 'c', max_chars=len(text)) == tokenize(text, 'c')


def test_open_comment_lines_stops_at_the_same_cut():
    text = '/*\na\nb\nc\nd\n'
    assert open_comment_lines(text) == {1, 2, 3, 4, 5}
    assert open_comment_lines(text, max_chars=6) == {1, 2}


# --- hostile text and the time budget -----------------------------------------------------------------------------

def realistic_c() -> str:
    body = '''
undefined8 FUN_140001000(longlong param_1,uint param_2)

{
  uint uVar1;
  longlong lVar2;

  lVar2 = *(longlong *)(param_1 + 8);
  if ((lVar2 != 0) && (param_2 < 0x20)) {
    uVar1 = FUN_140002340(lVar2,param_2);
    FUN_14000a000(DAT_14000b000,uVar1);
    /* WARNING: Could not recover jumptable */
    (*(code *)PTR_FUN_14000c010)(CreateFileW(L"C:\\\\tmp",0xc0000000,3,0,3,0x80,0));
    return 0xffffffffffffffff;
  }
  return 0;
}
'''
    return body * 4_000


def realistic_asm() -> str:
    body = '''MOV RAX,qword ptr [RSP + 0x28]
CALL qword ptr [->KERNEL32.DLL::CreateFileW]
LAB_140001234:
LOCK CMPXCHG dword ptr [RCX],EDX ; swap
JZ LAB_140001234
LEA RCX,[DAT_14000b000]
MOV EAX,dword ptr [RBP + -0x4]
'''
    return body * 4_000


HOSTILE = {
    'quotes': ('"' * 4_000 + '\n') * 30,
    'unterminated-strings': ('"' + 'a\\' * 2_000 + '\n') * 30,
    'escaped-quotes': ('"' + '\\"' * 2_000 + '\n') * 30,
    'escaped-apostrophes': ("'" + "\\'" * 2_000 + '\n') * 30,
    'char-flood': ("'a" * 1_300 + '\n') * 30,
    'comment-openers': ('/*' * 2_000 + '\n') * 30,
    'block-per-line': '/*\n' * 40_000,
    'hex-digits': ('0x' + '1' * 4_000 + '\n') * 30,
    'number-tails': ('1e+' * 1_300 + '\n') * 30,
    'dots': ('.' * 4_000 + '\n') * 30,
    'colons': ('::' * 2_000 + '\n') * 30,
    'name-prefixes': ('PTR_' * 1_000 + 'x\n') * 30,
    'nul-and-bidi': ('\x00\u202e\u200b' * 1_300 + '\n') * 30,
    'whitespace': ' ' * 120_000,
    'one-long-line': 'x ' * 60_000,
}


@pytest.mark.parametrize('language', LANGUAGES)
@pytest.mark.parametrize('text', HOSTILE.values(), ids=list(HOSTILE))
def test_hostile_text_is_covered_within_a_loose_time_bound(text, language):
    started = time.perf_counter()
    found = tokenize(text, language)
    open_comment_lines(text)
    elapsed = time.perf_counter() - started
    assert_covers(text, found)
    assert elapsed < 3.0  # a quadratic scanner needs minutes here; a linear one about a tenth of a second


@pytest.mark.parametrize('language, sample', [('c', realistic_c), ('asm', realistic_asm)], ids=['c', 'asm'])
def test_200k_characters_tokenize_within_the_budget(language, sample):
    """CI gate 150 ms (3x the 50 ms measured for 200,000 characters); best of five absorbs a busy runner."""
    text = sample()[:200_000]
    best = min(_elapsed(lambda: tokenize(text, language)) for _ in range(5))
    assert best < 0.150


def _elapsed(call) -> float:
    started = time.perf_counter()
    call()
    return time.perf_counter() - started


def test_the_comment_pre_pass_stays_within_its_budget():
    text = realistic_c()[:200_000]
    assert min(_elapsed(lambda: open_comment_lines(text)) for _ in range(5)) < 0.050


# --- Pygments as a dev oracle -------------------------------------------------------------------------------------

class Oracle:
    """Comment, string and number boundaries of a text, from Pygments or from our tokens, one label per character.

    A leading `-` belongs to the number in Pygments (`-5` is one token) and is an operator here, so it is relabelled."""

    def __init__(self) -> None:
        from pygments.lexers import CLexer, NasmLexer
        from pygments.token import Comment, Number, String

        self.lexers = {'c': CLexer(stripnl=False), 'asm': NasmLexer(stripnl=False)}
        self.classes = ((Comment, 'c'), (String, 's'), (Number, 'n'))

    def pygments(self, text: str, language: str) -> str:
        labels = ['-'] * len(text)
        source = text if text.endswith('\n') else text + '\n'  # what Lexer.get_tokens does; `//` needs its newline
        for index, kind, value in self.lexers[language].get_tokens_unprocessed(source):
            mark = next((m for cls, m in self.classes if kind in cls), None)
            if mark:
                labels[index:index + len(value)] = mark * min(len(value), len(text) - index)
        for i, char in enumerate(text):
            if char == '-' and labels[i] == 'n' and (i == 0 or labels[i - 1] != 'n'):
                labels[i] = '-'
        return ''.join(labels)

    @staticmethod
    def ours(text: str, language: str) -> str:
        labels = ['-'] * len(text)
        for token in tokenize(text, language):
            mark = {'comment': 'c', 'string': 's', 'char': 's', 'number': 'n'}.get(token.kind)
            if mark:
                labels[token.start:token.end] = mark * (token.end - token.start)
        return ''.join(labels)

    def disagreements(self, text: str, language: str) -> list[int]:
        theirs, ours = self.pygments(text, language), self.ours(text, language)
        return [i for i, char in enumerate(text) if not char.isspace() and theirs[i] != ours[i]]


@pytest.fixture(scope='module')
def oracle() -> Oracle:
    pytest.importorskip('pygments', reason='Pygments is a dev-only test oracle')
    return Oracle()


# Well-formed pieces only: an unterminated `'` (an error token in Pygments, the rest of the line here), a backslash
# before a newline and `#` lines are documented differences, and `/* open` would swallow the following pieces.
C_ATOMS = ['x', 'uVar1', 'FUN_140001000', 'if', 'while', 'int', 'return', 'CreateFileW', '(', ')', '{', '}', ';', ',',
           '=', '+', '*', '<', '&&', '->', '0', '12', '0x20', '0xFFUL', '1.5', '2e-3', '.5f', '017', '5UL', '0x1p3',
           '1e5', '"abc"', '"a\\"b"', '""', '"/* not */"', '"// nor"', '"\\\\"', "'a'", "'\\n'", "'\\''", "'\"'",
           "'\\x41'", 'L"wide"', 'u8"s"', '/* c */', '/**/', '// line', '/* a\nb */', '*/', '/', '?', ':', '[', ']']
ASM_ATOMS = ['rax', 'RSP', 'qword', 'ptr', '[', ']', ',', '+', '-', '*', '0x28', '28', '10h', '0FFh', '1.5', '101b',
             'FUN_140001000', 'LAB_1', '"abc"', "'a'", '"a b"', '; comment', ';', 'xmm0', 'r8d', ':', '(', ')']
MNEMONICS = ['mov', 'lea', 'call', 'jz', 'LOCK', 'xor', 'ret', 'CMPXCHG']
SEPARATORS = [' ', '\n']


@st.composite
def c_programs(draw):
    pieces = draw(st.lists(st.tuples(st.sampled_from(C_ATOMS), st.sampled_from(SEPARATORS)), min_size=1, max_size=40))
    return ''.join(atom + separator for atom, separator in pieces) + draw(st.sampled_from(['', 'x', '/* end']))


@st.composite
def asm_programs(draw):
    lines = draw(st.lists(st.tuples(st.sampled_from(MNEMONICS), st.lists(st.sampled_from(ASM_ATOMS), max_size=8)),
                          min_size=1, max_size=6))
    return '\n'.join(' '.join([mnemonic, *atoms]) for mnemonic, atoms in lines) + draw(st.sampled_from(['', '\n']))


@FAST
@given(program=c_programs())
def test_c_boundaries_agree_with_pygments(oracle, program):
    assert oracle.disagreements(program, 'c') == [], program


@FAST
@given(program=asm_programs())
def test_asm_boundaries_agree_with_pygments(oracle, program):
    assert oracle.disagreements(program, 'asm') == [], program


GHIDRA_C = r'''/* WARNING: Removing unreachable block (ram,0x140001040) */
undefined8 FUN_140001000(longlong param_1, uint param_2)
{
  longlong lVar2;  // temp
  if ((lVar2 != 0) && (param_2 < 0x20)) {
    FUN_14000a000(DAT_14000b000, L"C:\\tmp\n", 'x', -5, 1.5e-3f, 0xFFUL);
    /* multi
       line */
    return 0xffffffffffffffff;
  }
  return -1;
}
'''
GHIDRA_ASM = '''MOV RAX,qword ptr [RSP + 0x28]
CALL qword ptr [->KERNEL32.DLL::CreateFileW]
LOCK CMPXCHG dword ptr [RCX],EDX ; swap 0x10 "x"
MOV EAX,dword ptr [RBP + -0x4]
MOV R8D,0x20
MOV EAX,"abc"
'''


@pytest.mark.parametrize('language, text', [('c', GHIDRA_C), ('asm', GHIDRA_ASM)], ids=['c', 'asm'])
def test_ghidra_shaped_text_agrees_with_pygments(oracle, language, text):
    assert oracle.disagreements(text, language) == []


def test_documented_difference_an_unterminated_char_literal_runs_to_the_end_of_the_line(oracle):
    text = "x = 'a; y\n"
    assert lexed(text, 'c')[-1] == ('char', "'a; y")
    assert oracle.disagreements(text, 'c') != []  # the harness does notice a real difference


def test_documented_differences_from_pygments():
    assert lexed('// c \\\nint x;', 'c')[:2] == [('comment', '// c \\'), ('type', 'int')]  # no line continuation
    assert lexed('#include <x.h>', 'c')[:2] == [('other', '#'), ('ident', 'include')]  # no preprocessor lines
    assert lexed('12ab', 'c') == [('number', '12ab')]  # a number is a run of letters and digits
    assert lexed('"open', 'c') == [('string', '"open')]  # an unterminated quote runs to the end of its line


# --- no Qt, no third party ----------------------------------------------------------------------------------------

def test_package_imports_only_the_standard_library():
    imported: set[str] = set()
    for path in sorted(PACKAGE.glob('*.py')):
        for node in ast.walk(ast.parse(path.read_text(encoding='utf-8'))):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split('.')[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                imported.add(node.module.split('.')[0])
    assert imported <= {'__future__', 'collections', 're', 'types', 'typing'}, imported


def test_importing_the_package_loads_neither_qt_nor_pygments():
    code = ('import sys; sys.path.insert(0, sys.argv[1]); import patchtrace.codetext; '
            "bad = sorted(m for m in sys.modules if m.split('.')[0] in {'PySide6', 'shiboken6', 'pygments'}); "
            'print(bad); sys.exit(1 if bad else 0)')
    result = subprocess.run([sys.executable, '-I', '-B', '-c', code, str(SRC)], capture_output=True, text=True,
                            timeout=60)  # -B: an isolated check must not write bytecode into src/
    assert result.returncode == 0, result.stdout + result.stderr
