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


@pytest.mark.parametrize(('text', 'expected'), [
    ('a\x1b[2Jb', 'a\\x1b[2Jb'), ('x\u202ey', 'x\\u202ey'), ('k\U000e0041', 'k\\U000e0041'), ('plain \xe9', 'plain \xe9')],
    ids=['esc', 'rlo', 'tag', 'clean'])
def test_escape_text_makes_hostile_characters_visible(text, expected):
    from patchtrace.hostile_text import escape_text
    assert escape_text(text) == expected


def test_escape_text_can_keep_newlines():
    from patchtrace.hostile_text import escape_text
    assert escape_text('a\nb\x00', keep='\n') == 'a\nb\\x00'


# --- SEC-B (WP-03, SEC-9 residual, PE-4, PE-5): the storage-side sanitisers apply the same rule -------------------

RULE_CATEGORIES = ('Cc', 'Cf', 'Cs', 'Zl', 'Zp')
EVERY_RULE_CODE_POINT = [cp for cp in range(0x110000) if unicodedata.category(chr(cp)) in RULE_CATEGORIES]
KBC_BREAKS = '\n\r\t\u2028\u2029'


def _kbc_expected(char: str) -> str:
    if char in KBC_BREAKS:
        return 'a b'
    return 'a\ufffdb' if unicodedata.category(char) == 'Cs' else 'ab'


def _sinks():
    """Each sink with what it documents for `a<hostile>b`: its own replacement and the breaks it keeps."""
    from patchtrace.codetext import intraline
    from patchtrace.kbcorrelation import products
    from patchtrace.pe_overview import resources
    from patchtrace.secondary import bindiff_probe, runs
    return {
        'bindiff-probe': (bindiff_probe.sanitize, lambda c: 'a\tb' if c == '\t' else 'a b'),
        'stderr': (runs.sanitize_stderr, lambda c: f'a{c}b' if c in '\n\t' else 'a?b'),
        'kbc': (products.clean_text, _kbc_expected),
        'pe-resources': (resources.sanitize_text, lambda c: 'ab'),
        'intraline': (intraline._snippet, lambda c: f'a<U+{ord(c):04X}>b'),
    }


SINK_IDS = ['bindiff-probe', 'stderr', 'kbc', 'pe-resources', 'intraline']


@pytest.mark.parametrize('sink', SINK_IDS, ids=SINK_IDS)
def test_no_hostile_code_point_survives_a_storage_side_sanitiser(sink):
    """Every code point of the rule, one replacement per code point. What a sink keeps is what it documents: BinDiff
    text a tab, stored stderr a newline and a tab; advisory text turns its five line breaks into a space."""
    clean, expected = _sinks()[sink]
    wrong = [f'U+{cp:04X}' for cp in EVERY_RULE_CODE_POINT if clean(f'a{chr(cp)}b') != expected(chr(cp))]
    assert wrong[:8] == [], f'{len(wrong)} of {len(EVERY_RULE_CODE_POINT)} code points are not handled by the rule'


@pytest.mark.parametrize('sink', SINK_IDS, ids=SINK_IDS)
def test_a_storage_side_sanitiser_keeps_printable_text(sink):
    text = 'caf\xe9 \u65e5\u672c\u8a9e \U0001f600 ok'
    assert _sinks()[sink][0](text) == text


@pytest.mark.parametrize('char', [
    '\x9b', '\u061c', '\u202e', '\u2028', '\u2029', '\xad', '\u200b', '\ufeff', '\u0600', '\U000e0041', '\udc80'],
    ids=['csi', 'arabic-mark', 'rlo', 'line-separator', 'paragraph-separator', 'soft-hyphen', 'zero-width', 'bom',
         'arabic-number-sign', 'tag', 'surrogate'])
def test_the_characters_the_audit_named_reach_no_stored_field(char):
    """The inventory's probe (I1-T02): BinDiff text kept U+202E, U+2028 and C1 CSI; stored stderr kept U+009B and
    U+061C; advisory text kept U+2028 and U+2029; PE resource text kept the soft hyphen, zero-width and tag
    characters; the summary snippet showed U+0600 raw."""
    for sink, (clean, _expected) in _sinks().items():
        assert char not in clean(f'x{char}y'), sink


def test_a_sanitiser_changes_nothing_but_the_hostile_characters_of_a_long_mixed_text():
    """The table path and the per-character rule agree on a text that mixes every kind, at the size of a stored
    stderr tail."""
    from patchtrace.pe_overview.resources import sanitize_text
    from patchtrace.secondary.runs import STDERR_STORED, sanitize_stderr
    text = ('line \u65e5\u672c\n\ttab\x1b[31m red\x9b0m \u202eevil\u2028next\xad\u200b\ud800 \U000e0041 end\r\n' * 4096)
    stored = sanitize_stderr(text)
    assert len(stored) == STDERR_STORED and len(text) > STDERR_STORED
    assert stored == ''.join(c if c in '\n\t' or not is_hostile(c) else '?' for c in text[-STDERR_STORED:])
    assert sanitize_text(text) == ''.join(c for c in text if not is_hostile(c))


def test_replace_hostile_replaces_each_code_point_once_and_keeps_what_it_is_told_to():
    from patchtrace.hostile_text import replace_hostile
    text = 'a\x00b\u202ec\u2028d\ud800e\nf\tg'
    assert replace_hostile(text, '?') == 'a?b?c?d?e?f?g'
    assert replace_hostile(text, '?', keep='\n\t') == 'a?b?c?d?e\nf\tg'
    assert replace_hostile(text, '') == 'abcdefg' and replace_hostile(text) == 'abcdefg'
    assert len(replace_hostile(text, ' ')) == len(text)
    assert replace_hostile('caf\xe9 \xa0\u65e5 ok', '?') == 'caf\xe9 \xa0\u65e5 ok' and replace_hostile('', '?') == ''


def test_replace_hostile_and_is_hostile_judge_the_same_code_points():
    from patchtrace.hostile_text import replace_hostile
    every = ''.join(map(chr, range(0x110000)))
    assert replace_hostile(every, '') == ''.join(char for char in every if not is_hostile(char))
