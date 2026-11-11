"""QA-FUZZ: sanitisers for untrusted text fields (tool output, CSAF labels, advisory text, PE strings).

Properties: each sink returns plain text that contains no control, format (bidi, zero-width, BOM) or surrogate
characters, respects its length cap for arbitrarily long or deeply nested input, and never raises for any JSON value.
Unicode canonical variants (NFC, NFD, compatibility forms) pass through as ordinary text; nothing is normalised away
silently, and nothing is executed.
"""
from __future__ import annotations

import unicodedata

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from patchtrace.intelligence.csaf.validate import safe_label
from patchtrace.intelligence.tools.common import DISPLAY_LIMIT, display_text
from patchtrace.kbcorrelation.products import clean_text as advisory_text
from patchtrace.pe_overview._common import clean_text as pe_text

SETTINGS = settings(max_examples=300, deadline=None, database=None, suppress_health_check=[HealthCheck.too_slow])
HOSTILE = frozenset({'Cc', 'Cf', 'Cs'})
ANY_TEXT = st.text(max_size=400)  # includes surrogates, controls and format characters
VALUE = st.recursive(st.none() | st.booleans() | st.integers() | st.floats(allow_nan=True) | ANY_TEXT,
                     lambda kids: st.lists(kids, max_size=4) | st.dictionaries(ANY_TEXT, kids, max_size=4),
                     max_leaves=30)


def _has_hostile(text: str) -> bool:
    return any(unicodedata.category(char) in HOSTILE for char in text)


@SETTINGS
@given(ANY_TEXT)
def test_display_text_is_plain_and_capped(text):
    out = display_text(text)
    assert not _has_hostile(out)
    assert len(out) <= DISPLAY_LIMIT


@SETTINGS
@given(st.text(alphabet=st.characters(blacklist_categories=('Cc', 'Cf', 'Cs', 'Co', 'Cn', 'Zl', 'Zp')),
               max_size=DISPLAY_LIMIT - 4))
def test_display_text_leaves_clean_short_text_unchanged(text):
    assert display_text(text) == text


@SETTINGS
@given(st.integers(DISPLAY_LIMIT, 200_000), st.sampled_from(['a', '‮', 'é', '\U0001F600']))
def test_display_text_of_oversized_input_is_truncated_with_an_ellipsis(size, char):
    out = display_text(char * size)
    assert len(out) <= DISPLAY_LIMIT
    assert out.endswith('...')


@SETTINGS
@given(st.text(alphabet=['‮', '​', '﻿', '\x1b', '\x00', '\ud800', 'A'], max_size=60))
def test_display_text_escapes_bidi_and_zero_width_characters(text):
    out = display_text(text)
    for hostile in ('‮', '​', '﻿', '\x1b', '\x00', '\ud800'):
        assert hostile not in out


@SETTINGS
@given(VALUE, st.integers(1, 120))
def test_safe_label_never_raises_and_respects_its_cap(value, limit):
    out = safe_label(value, limit)
    assert isinstance(out, str)
    assert len(out) <= limit
    assert not _has_hostile(out)


BIDI = frozenset('‎‏؜‪‫‬‭‮⁦⁧⁨⁩')


@SETTINGS
@given(ANY_TEXT)
def test_advisory_text_strips_controls_bidi_and_surrogates_and_respects_its_cap(text):
    out = advisory_text(text)
    assert isinstance(out, str)
    assert not any(unicodedata.category(char) in {'Cc', 'Cs'} for char in out)
    assert not BIDI & set(out)
    assert '\n' not in out and '\t' not in out
    assert len(out) <= 1000


def test_advisory_text_removes_every_format_character():
    out = advisory_text('​CVE-2099­-1﻿\U000e0001')
    assert not any(unicodedata.category(char) == 'Cf' for char in out)


@SETTINGS
@given(st.binary(max_size=500))
def test_pe_strings_map_one_byte_to_one_character(raw):
    out = pe_text(raw)
    assert len(out) == len(raw)
    assert not _has_hostile(out)


def test_canonical_variants_are_not_merged_by_the_display_sinks():
    nfc, nfd = 'café', 'café'
    assert display_text(nfc) == nfc
    assert display_text(nfd) == nfd
    assert safe_label(nfc) == nfc and safe_label(nfd) == nfd
