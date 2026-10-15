from __future__ import annotations

import pytest

from patchtrace.strings.lookalike import (
    CodepointDiff,
    LookalikePair,
    codepoint_diff,
    describe_codepoints,
    lookalike_key,
    pair_lookalikes,
)

CYR_E = '\u0415'

SAME_KEY = [
    ('Error', CYR_E + 'rror'),
    ('Error', 'ERROR'),
    ('Error', 'E\u200brror'),
    ('Error', '\uff25rror'),
    ('caf\u00e9', 'cafe\u0301'),
    ('open', 'op\u0435n'),
    ('Hello', '\u0397ello'),
]
DIFF_KEY = [('Error', 'Errors'), ('Error', 'Terror'), ('abc', 'abd')]


@pytest.mark.parametrize('a,b', SAME_KEY, ids=[f's{i}' for i in range(len(SAME_KEY))])
def test_same_key(a, b):
    assert lookalike_key(a) == lookalike_key(b)


@pytest.mark.parametrize('a,b', DIFF_KEY, ids=['suffix', 'prefix', 'letter'])
def test_different_key(a, b):
    assert lookalike_key(a) != lookalike_key(b)


def test_error_with_cyrillic_ie_pairs():
    assert pair_lookalikes(['Error'], [CYR_E + 'rror']) == (LookalikePair('Error', CYR_E + 'rror'),)


def test_pairing_is_orientation_aware():
    assert pair_lookalikes([CYR_E + 'rror'], ['Error']) == (LookalikePair(CYR_E + 'rror', 'Error'),)


def test_ambiguous_group_is_not_paired():
    assert pair_lookalikes(['Error', 'ERROR'], [CYR_E + 'rror']) == ()
    assert pair_lookalikes(['Error'], [CYR_E + 'rror', 'E\u200brror']) == ()


def test_unrelated_values_do_not_pair():
    assert pair_lookalikes(['alpha'], ['beta']) == ()
    assert pair_lookalikes([], []) == ()


def test_pairs_are_sorted_by_key():
    got = pair_lookalikes(['zeta', 'Error'], ['ZETA', CYR_E + 'rror'])
    assert [p.older for p in got] == ['Error', 'zeta']


def test_codepoint_diff_isolates_the_homoglyph():
    assert codepoint_diff('Error', CYR_E + 'rror') == (CodepointDiff(0, 'E', 0, CYR_E),)


def test_codepoint_diff_insertion_and_limit():
    assert codepoint_diff('ab', 'a\u200bb') == (CodepointDiff(1, '', 1, '\u200b'),)
    assert len(codepoint_diff('a' * 100, ''.join(chr(0x4e00 + i) if i % 2 else 'a' for i in range(100)),
                              limit=5)) == 5


def test_codepoint_diff_identical_is_empty():
    assert codepoint_diff('same', 'same') == ()


def test_describe_codepoints_names_characters_and_never_echoes_them():
    text = describe_codepoints(CYR_E + '\u200b')
    assert text == 'U+0415 CYRILLIC CAPITAL LETTER IE, U+200B ZERO WIDTH SPACE'
    assert CYR_E not in text
    assert describe_codepoints('') == '(none)'
    assert describe_codepoints('\ue000') == 'U+E000 <unnamed>'
