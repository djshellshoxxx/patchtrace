"""WB3-S4 L4 literal segmentation: the F13 escape table over every code-point class, FLOSS-shaped cuts, wide and
truncated literals, hostile sizes."""
from __future__ import annotations

import unicodedata

import pytest

from patchtrace.strings import clit
from patchtrace.strings.clit import Segment, extract_literals, segments

_NAMED = {0: '\\0', 7: '\\a', 8: '\\b', 9: '\\t', 10: '\\n', 11: '\\v', 12: '\\f', 13: '\\r',
          ord('\\'): '\\\\', ord('"'): '\\"', ord("'"): "\\'"}
_UNPRINTABLE = {'Cc', 'Cf', 'Cs', 'Co', 'Cn', 'Zl', 'Zp'}


def f13_escape(char: str) -> str:
    """Reference encoder of the Ghidra decompiler's literal escaping (spec F13), kept independent of the code
    under test."""
    code = ord(char)
    if code in _NAMED:
        return _NAMED[code]
    if unicodedata.category(char) not in _UNPRINTABLE:
        return char
    width = 2 if code < 0x100 else 4 if code < 0x10000 else 8
    return f'\\x{code:0{width}x}'


CLASSES = [
    ('nul', '\x00', False), ('bell', '\x07', False), ('backspace', '\x08', False), ('tab', '\t', True),
    ('lf', '\n', False), ('vtab', '\x0b', False), ('formfeed', '\x0c', False), ('cr', '\r', False),
    ('c0-other', '\x1b', False), ('del', '\x7f', False), ('c1', '\x85', False), ('bidi', '‮', False),
    ('zero-width', '​', False), ('line-sep', ' ', False), ('private-use', '', False),
    ('astral-format', '\U000e0001', False), ('backslash', '\\', True), ('dquote', '"', True),
    ('squote', "'", True), ('ascii', 'x', True), ('latin', 'é', True), ('astral', '\U0001f600', True),
]


@pytest.mark.parametrize('char,kept', [c[1:] for c in CLASSES], ids=[c[0] for c in CLASSES])
def test_f13_escape_table(char, kept):
    body = 'ab' + f13_escape(char) + 'yz'
    expected = (Segment('ab' + char + 'yz', True),) if kept else (Segment('ab', False), Segment('yz', True))
    assert segments(body) == expected


def test_literal_with_newline_links_segment():
    assert segments('bad header (%s)\\n') == (Segment('bad header (%s)', False),)


def test_empty_pieces_are_dropped():
    assert segments('\\n\\r') == ()
    assert segments('') == ()


@pytest.mark.parametrize('body,expected', [
    ('ab\\x41BCzz', ('ab', 'BCzz')), ('ab\\x200bcdzz', ('ab', 'cdzz')), ('ab\\x000e0001zz', ('ab', 'zz')),
    ('ab\\x1bzz', ('ab', 'zz')), ('ab\\x4', ('ab',))],
    ids=['two-digit', 'four-digit', 'eight-digit', 'plain', 'short'])
def test_hex_escape_width_follows_the_code_point(body, expected):
    assert tuple(s.text for s in segments(body)) == expected


def test_lone_trailing_backslash_and_unknown_escape_cut():
    assert segments('ab\\') == (Segment('ab', False),)
    assert segments('ab\\qcd') == (Segment('ab', False), Segment('cd', True))


def test_truncated_literal_drops_dots_and_marks_open_end():
    assert segments('prefix text...', truncated=True) == (Segment('prefix text', True),)
    assert segments('prefix text...') == (Segment('prefix text...', True),)


def test_extract_literals_wide_truncated_and_lines():
    code = ('void f(void)\n{\n  puts("one\\n");\n  wprintf(L"two");\n'
            '  puts("long string..." /* TRUNCATED STRING LITERAL */);\n}\n')
    scan = extract_literals(code)
    assert [(lit.body, lit.wide, lit.truncated, lit.line) for lit in scan.literals] == [
        ('one\\n', False, False, 3), ('two', True, False, 4), ('long string...', False, True, 5)]
    assert not scan.capped


def test_comments_and_character_literals_hold_no_strings():
    code = '// "no"\n/* "nor" */ c = \'"\'; puts("yes"); /* tail\n"never" */\n'
    assert [lit.body for lit in extract_literals(code).literals] == ['yes']


def test_quote_escapes_inside_a_literal_do_not_end_it():
    assert [lit.body for lit in extract_literals(r'puts("say \"hi\" now");').literals] == [r'say \"hi\" now']


def test_unterminated_literal_is_ignored_and_lines_stay_aligned():
    scan = extract_literals('puts("broken\\\nputs("fine");\n')
    assert [(lit.body, lit.line) for lit in scan.literals] == [('fine', 2)]


def test_identifier_ending_in_l_is_not_a_wide_prefix():
    assert [lit.wide for lit in extract_literals('FOOL"x"; L"y";').literals] == [False, True]


def test_literal_count_cap(monkeypatch):
    monkeypatch.setattr(clit, 'MAX_LITERALS_PER_FUNCTION', 3)
    scan = extract_literals(''.join(f'a("s{i}");' for i in range(10)))
    assert len(scan.literals) == 3 and scan.capped


def test_line_cap(monkeypatch):
    monkeypatch.setattr(clit, 'MAX_LITERAL_LINES', 5)
    scan = extract_literals('a("x");\n' * 20)
    assert scan.capped and len(scan.literals) <= 5


def test_hostile_code_is_bounded_and_does_not_hang():
    code = '"' * 50_000 + '\\' * 50_000 + '/*' * 1000
    extract_literals(code)
    segments('\\' * 100_000)
