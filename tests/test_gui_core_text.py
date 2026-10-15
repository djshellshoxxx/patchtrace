"""GUI core (slice F1): untrusted-text safety and claim wording (GUI-integration-plan 8.4 and section 6).

Pure and hermetic: no Qt, no network, no project files. `sanitize_text` is checked by hypothesis properties and a
character-by-character oracle; `ClaimsProfile` by examples that mirror the C6 (`secondary.evidence_view`) rules.
"""
from __future__ import annotations

import unicodedata

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from patchtrace.gui.text import (
    CLAIMS_NEUTRAL,
    CLAIMS_PAIRING,
    LABEL_LIMIT,
    VIEW_LIMIT,
    ClaimsProfile,
    sanitize_text,
)

PROPS = settings(max_examples=300, deadline=None, derandomize=True, database=None,
                 suppress_health_check=[HealthCheck.too_slow])

# Every code point the sanitizer must remove; BREAKS are replaced (single line) or normalised (multiline) instead.
BIDI = ''.join(chr(c) for c in (0x061c, 0x200e, 0x200f, *range(0x202a, 0x202f), *range(0x2066, 0x206a)))
SEPARATORS = chr(0x2028) + chr(0x2029)
CONTROLS = ''.join(chr(c) for c in [*range(0x00, 0x20), *range(0x7f, 0xa0)])
BREAKS = '\t\n\v\f\r\x85'
SURROGATES = ''.join(chr(c) for c in (0xd800, 0xdbff, 0xdc00, 0xdfff))
INTERESTING = CONTROLS + BIDI + SEPARATORS + SURROGATES + 'abc XYZ <>&%{}' + chr(0xe9) + chr(0x4e2d) + chr(0x1f600)
TEXTS = st.text(st.one_of(st.characters(exclude_categories=[]), st.sampled_from(INTERESTING)), max_size=120)
DENSE = st.text(st.sampled_from(INTERESTING), min_size=1, max_size=40)  # almost every character is a special one
LIMITS = st.integers(min_value=0, max_value=150)
# Every BMP code point and a stride through the other planes: one pass of the sanitizer over each mode.
EVERY_CODE_POINT = ''.join(chr(c) for c in [*range(0x10000), *range(0x10000, 0x110000, 97)])


def oracle(text: str, multiline: bool) -> str:
    """Independent, loop-based reading of the contract (no regular expressions).

    Single line: a run of break characters becomes one space. Multiline: every break character becomes one
    newline (a tab stays a tab). Every other control, bidi, separator and surrogate is dropped.
    """
    out: list[str] = []
    in_break = False
    text = text.replace('\r\n', '\n') if multiline else text
    for ch in text:
        if ch in BREAKS:
            if multiline:
                out.append('\t' if ch == '\t' else '\n')
            elif not in_break:
                out.append(' ')
            in_break = True
            continue
        in_break = False
        code = ord(ch)
        if code < 0x20 or 0x7f <= code <= 0x9f or ch in BIDI or ch in SEPARATORS or 0xd800 <= code <= 0xdfff:
            continue
        out.append(ch)
    return ''.join(out)


@PROPS
@given(TEXTS, LIMITS)
def test_sanitize_is_bounded_idempotent_and_encodable(text, limit):
    once = sanitize_text(text, limit)
    assert len(once) <= limit
    assert sanitize_text(once, limit) == once
    once.encode('utf-8')


@PROPS
@given(TEXTS, LIMITS)
def test_sanitize_block_is_bounded_and_idempotent(text, limit):
    once = sanitize_text(text, limit, multiline=True)
    assert len(once) <= limit
    assert sanitize_text(once, limit, multiline=True) == once


@PROPS
@given(TEXTS)
def test_single_line_output_is_control_free(text):
    out = sanitize_text(text, 500)
    assert not any(unicodedata.category(ch) in ('Cc', 'Cs') for ch in out)
    assert not any(ch in BIDI or ch in SEPARATORS for ch in out)


@PROPS
@given(TEXTS)
def test_multiline_keeps_only_tab_and_newline_controls(text):
    out = sanitize_text(text, 500, multiline=True)
    assert {ch for ch in out if unicodedata.category(ch) in ('Cc', 'Cs')} <= {'\n', '\t'}
    assert not any(ch in BIDI or ch in SEPARATORS for ch in out)


@PROPS
@given(TEXTS, st.booleans())
def test_sanitize_matches_the_oracle_below_the_limit(text, multiline):
    expected = oracle(text, multiline)
    assert len(expected) <= 500
    assert sanitize_text(text, 500, multiline=multiline) == expected


@PROPS
@given(DENSE, st.booleans())
def test_special_character_dense_text_matches_the_oracle(text, multiline):
    out = sanitize_text(text, 500, multiline=multiline)
    assert out == oracle(text, multiline)
    assert sanitize_text(out, 500, multiline=multiline) == out


@pytest.mark.parametrize('multiline', [False, True], ids=['line', 'block'])
def test_every_code_point_is_classified_like_the_oracle(multiline):
    out = sanitize_text(EVERY_CODE_POINT, len(EVERY_CODE_POINT), multiline=multiline)
    assert out == oracle(EVERY_CODE_POINT, multiline)
    removed = set(EVERY_CODE_POINT) - set(out)
    assert {chr(0xd800), chr(0xdfff), chr(0x61c), chr(0x202e), chr(0x2066), chr(0x2028), chr(0x7f), '\x00',
            '\x9f'} <= removed
    assert chr(0xe9) in out and chr(0x4e2d) in out
    assert all(ch in out for ch in EVERY_CODE_POINT if ord(ch) >= 0x10000)  # no astral character is touched


@PROPS
@given(TEXTS, st.integers(min_value=-5, max_value=-1))
def test_negative_limits_give_empty_text(text, limit):
    assert sanitize_text(text, limit) == ''


@PROPS
@given(TEXTS, st.integers(min_value=4, max_value=60))
def test_overlong_text_is_cut_to_the_limit_with_an_ellipsis(text, limit):
    expected = oracle(text, False)
    out = sanitize_text(text, limit)
    if len(expected) <= limit:
        assert out == expected
    else:
        assert out == expected[:limit - 3] + '...' and len(out) == limit


@PROPS
@given(TEXTS, st.integers(min_value=0, max_value=3))
def test_tiny_limits_never_exceed_the_limit(text, limit):
    assert len(sanitize_text(text, limit)) <= limit


@PROPS
@given(st.text(alphabet=st.characters(min_codepoint=0x20, max_codepoint=0x7e), max_size=LABEL_LIMIT))
def test_clean_printable_ascii_passes_through_unchanged(text):
    assert sanitize_text(text) == text


@PROPS
@given(st.one_of(st.none(), st.integers(), st.floats(allow_nan=True), st.booleans(), st.binary(max_size=30)))
def test_non_text_values_never_raise(value):
    out = sanitize_text(value)
    assert isinstance(out, str) and len(out) <= LABEL_LIMIT


def test_none_is_empty_and_defaults_are_the_documented_limits():
    assert sanitize_text(None) == ''
    assert (LABEL_LIMIT, VIEW_LIMIT) == (200, 4000)
    assert len(sanitize_text('x' * 1000)) == LABEL_LIMIT
    assert len(sanitize_text('x' * 9000, VIEW_LIMIT, multiline=True)) == VIEW_LIMIT


HOSTILE = {
    'markup': ('<img src=x onerror=1>{0}' + chr(0x202e), '<img src=x onerror=1>{0}'),
    'bold-and-format': ('<b>pwn</b>\x1b[31m%s', '<b>pwn</b>[31m%s'),
    'nul': ('a\x00b', 'ab'),
    'line-separators': ('one' + chr(0x2028) + 'two' + chr(0x2029) + 'three', 'onetwothree'),
    'newline-injection': ('name\nVerdict: agree', 'name Verdict: agree'),
    'crlf-and-tab': ('a\r\n\tb', 'a b'),
    'c1': ('x\x85y\x9fz', 'x yz'),
    'isolates': (chr(0x2066) + 'a' + chr(0x2069) + 'b', 'ab'),
}


@pytest.mark.parametrize('text,expected', list(HOSTILE.values()), ids=list(HOSTILE))
def test_hostile_text_survives_as_literal_plain_text(text, expected):
    assert sanitize_text(text) == expected


def test_multiline_normalises_every_newline_form_to_one_character():
    assert sanitize_text('a\r\nb\rc\x85d\ve\ff\tg', multiline=True) == 'a\nb\nc\nd\ne\nf\tg'


# ---- claims ---------------------------------------------------------------------------------------------------


def test_pairing_profile_is_exactly_the_c6_banned_list():
    from patchtrace.secondary.evidence_view import BANNED
    assert set(CLAIMS_PAIRING.banned_stems) | set(CLAIMS_PAIRING.banned_words) == set(BANNED)
    assert not set(CLAIMS_PAIRING.banned_stems) & set(CLAIMS_PAIRING.banned_words)
    assert set(CLAIMS_PAIRING.banned_stems) == {'probab', 'likelihood', 'vulnerab', 'exploit'}


@pytest.mark.parametrize('text,hits', [
    ('Probably the same', ('probab',)),
    ('likelihood and Vulnerabilities', ('likelihood', 'vulnerab')),
    ('It is SAFE and Fixed', ('fixed', 'safe')),
    ('a secure, verified, proven, certain result', ('certain', 'proven', 'secure', 'verified')),
    ('confidence % shown', ('confidence %',)),
    ('Exploitable path', ('exploit',)),
], ids=['stem-case', 'two-stems', 'words-case', 'four-words', 'phrase', 'prefix'])
def test_pairing_profile_flags_claim_wording(text, hits):
    assert CLAIMS_PAIRING.violations(text) == hits


@pytest.mark.parametrize('text', [
    'provenance of the pair', 'safeguard', 'unsafe', 'prefixed', 'a certainly', 'secured', 'verifier',
    'unfixed', 'Scores are engine-native and uncalibrated', '',
], ids=['provenance', 'safeguard', 'unsafe', 'prefixed', 'certainly', 'secured', 'verifier', 'unfixed',
        'uncalibrated', 'empty'])
def test_words_match_whole_words_only(text):
    assert CLAIMS_PAIRING.violations(text) == ()


def test_sanctioned_negations_are_removed_before_checking():
    text = ('This panel assesses function pairing only, not vulnerabilities or patch validity. '
            'PatchTrace engine evidence (function pairing only; not a vulnerability assessment). '
            'BinDiff confidence is algorithm-dependent, not a probability.')
    assert CLAIMS_PAIRING.violations(text) == ()
    assert CLAIMS_PAIRING.violations(text + ' It is vulnerable.') == ('vulnerab',)
    assert CLAIMS_PAIRING.violations('NOT A VULNERABILITY ASSESSMENT') == ()


def test_removing_a_phrase_cannot_glue_words_into_a_banned_one():
    profile = ClaimsProfile(banned_words=('safe',), allowed_phrases=('not',))
    assert profile.violations('sanotfe') == ()
    assert profile.violations('safe not') == ('safe',)


def test_overlapping_allowed_phrases_remove_the_longest_match():
    profile = ClaimsProfile(banned_stems=('probab',), allowed_phrases=('not', 'not a probability'))
    assert profile.violations('this is not a probability') == ()
    assert profile.violations('not a probable cause') == ('probab',)


def test_empty_profile_entries_match_nothing():
    profile = ClaimsProfile(banned_stems=('',), banned_words=('',), allowed_phrases=('',))
    assert profile.violations('anything at all') == ()


def test_neutral_profile_bans_the_claim_drift_examples_of_the_plan():
    for text in ('confidence % 80', 'it is safe', 'already fixed', 'likelihood', 'probably'):
        assert CLAIMS_NEUTRAL.violations(text), text
    assert CLAIMS_NEUTRAL.violations('uncalibrated ordering aid, not a probability') == ()
    assert CLAIMS_NEUTRAL.violations('The advisory describes a vulnerability and an exploit') == ()


def test_custom_profiles_are_independent_and_hashable():
    mine = ClaimsProfile(banned_stems=('Foo',), banned_words=('bar',), allowed_phrases=('no bar',))
    assert mine.violations('football') == ('foo',)
    assert mine.violations('Foolish bar') == ('bar', 'foo')
    assert mine.violations('no bar here') == ()
    assert hash(mine) == hash(ClaimsProfile(('Foo',), ('bar',), ('no bar',)))


@PROPS
@given(st.text(max_size=200))
def test_claims_scan_never_raises_and_an_empty_profile_is_clean(text):
    assert isinstance(CLAIMS_PAIRING.violations(text), tuple)
    assert ClaimsProfile().violations(text) == ()
