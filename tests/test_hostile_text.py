"""One hostile-character rule (random audit 1, RA-8): control, format and surrogate code points never survive
`intelligence.tools.process.sanitize` (replaced by a space) or `pe_overview._common.clean_text` (replaced by `?`)."""
from __future__ import annotations

import unicodedata

import pytest

from patchtrace.hostile_text import is_hostile
from patchtrace.intelligence.tools.process import sanitize
from patchtrace.pe_overview._common import clean_text

HOSTILE_CATEGORIES = ('Cc', 'Cf', 'Cs')
EVERY_HOSTILE = [cp for cp in range(0x110000) if unicodedata.category(chr(cp)) in HOSTILE_CATEGORIES]


@pytest.mark.parametrize('char', [
    '\x00', '\x1b', '\x7f', '\x80', '\x9b', '\x9f', '\xad', '\u061c', '\u200b', '\u200f', '\u202e', '\u2060', '\u2066',
    '\ufeff', '\U000e0041', '\ud800'],
    ids=['nul', 'esc', 'del', 'c1-first', 'csi', 'c1-last', 'soft-hyphen', 'arabic-mark', 'zero-width', 'rlm', 'rlo',
         'word-joiner', 'isolate', 'bom', 'tag', 'surrogate'])
def test_control_format_and_surrogate_characters_are_hostile(char):
    assert is_hostile(char)


@pytest.mark.parametrize('char', ['a', ' ', '~', '\xa0', '\xe9', '\u65e5', '\U0001f600'],
                         ids=['letter', 'space', 'tilde', 'nbsp', 'e-acute', 'cjk', 'emoji'])
def test_printable_characters_are_not_hostile(char):
    assert not is_hostile(char)


def test_sanitize_replaces_every_hostile_code_point():
    """RA-8: U+009B (C1 CSI) and U+202E (RLO) used to survive; now no code point of Cc, Cf or Cs does."""
    for cp in EVERY_HOSTILE:
        assert sanitize(f'x{chr(cp)}y') == 'x y', hex(cp)
    assert sanitize('a\x9b31m \N{RIGHT-TO-LEFT OVERRIDE}b') == 'a 31m b'


def test_sanitize_keeps_other_text_and_its_other_rules():
    assert sanitize('caf\xe9 \u65e5\u672c\u8a9e \U0001f600 ok') == 'caf\xe9 \u65e5\u672c\u8a9e \U0001f600 ok'
    assert sanitize('\x1b[31merror\x1b[0m in C:\\Users\\bob\\tool.exe\x07') == 'error in tool.exe'
    assert sanitize('a\tb\n c', 3) == 'a b'


def test_clean_text_replaces_every_hostile_latin1_character():
    """RA-8: `clean_text(b'a\\x9b31mb')` kept U+009B although the spec says control characters become `?`."""
    expected = ''.join('?' if unicodedata.category(chr(b)) in HOSTILE_CATEGORIES else chr(b) for b in range(256))
    assert clean_text(bytes(range(256))) == expected
    assert clean_text(b'a\x9b31mb') == 'a?31mb'
    assert clean_text(b'.te\x01\xe9') == '.te?\xe9' and clean_text(b'x\xady') == 'x?y'


def test_both_sinks_judge_the_same_characters():
    hostile = [b for b in range(256) if is_hostile(chr(b))]
    assert hostile and all(clean_text(bytes([b])) == '?' and sanitize(f'a{chr(b)}b') == 'a b' for b in hostile)
