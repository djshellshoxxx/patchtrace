"""GUI core (slice F1): colour maths and the contrast gates (GUI-integration-plan 8.6). Pure, no Qt."""
from __future__ import annotations

import pytest
from hypothesis import HealthCheck, assume, given, settings
from hypothesis import strategies as st

from patchtrace.gui.theme_math import (
    NON_TEXT_CONTRAST,
    TEXT_CONTRAST,
    contrast_ratio,
    ensure_contrast,
    parse_color,
    relative_luminance,
)

PROPS = settings(max_examples=300, deadline=None, derandomize=True, database=None,
                 suppress_health_check=[HealthCheck.too_slow])
COLORS = st.from_regex(r'#[0-9a-fA-F]{6}', fullmatch=True)
GREYS = st.integers(0, 255).map(lambda v: f'#{v:02x}{v:02x}{v:02x}')


def test_wcag_thresholds_are_the_documented_constants():
    assert (TEXT_CONTRAST, NON_TEXT_CONTRAST) == (4.5, 3.0)


@pytest.mark.parametrize('first,second,expected', [
    ('#000000', '#ffffff', 21.0),
    ('#ffffff', '#ffffff', 1.0),
    ('#767676', '#ffffff', 4.54),
    ('#777777', '#ffffff', 4.48),
    ('#161b22', '#8fd19e', 9.705),
], ids=['black-white', 'same', 'aa-pass-grey', 'aa-fail-grey', 'dark-theme-badge'])
def test_known_ratios(first, second, expected):
    assert contrast_ratio(first, second) == pytest.approx(expected, abs=0.005)


def test_ratio_matches_the_c6_implementation_exactly():
    """`contrast_ratio` moves here from `ui_evidence`, which will re-export it: no number may change."""
    from patchtrace import ui_evidence
    pairs = [('#161b22', color) for color in ui_evidence.BADGE_COLORS.values()]
    pairs += [(ui_evidence.BADGE_TEXT, color) for color in ui_evidence.BADGE_COLORS.values()]
    pairs += [('#123456', '#fedcba'), ('#000001', '#010000')]
    for first, second in pairs:
        assert contrast_ratio(first, second) == ui_evidence.contrast_ratio(first, second)


@PROPS
@given(COLORS, COLORS)
def test_ratio_is_symmetric_and_bounded(first, second):
    ratio = contrast_ratio(first, second)
    assert ratio == contrast_ratio(second, first)
    assert 1.0 <= ratio <= 21.0 + 1e-9


@PROPS
@given(COLORS)
def test_a_colour_against_itself_has_ratio_one_in_either_case(color):
    assert contrast_ratio(color, color) == 1.0
    assert contrast_ratio(color, color.upper()) == 1.0


@PROPS
@given(GREYS, GREYS)
def test_against_white_darker_greys_never_contrast_less(first, second):
    assume(relative_luminance(first) <= relative_luminance(second))
    assert contrast_ratio(first, '#ffffff') >= contrast_ratio(second, '#ffffff')


@PROPS
@given(COLORS)
def test_luminance_is_between_zero_and_one(color):
    assert 0.0 <= relative_luminance(color) <= 1.0


@pytest.mark.parametrize('bad', ['', '#fff', 'ffffff', '#gggggg', '#1234567', 'red', '#12345', ' #123456', None, 123],
                         ids=['empty', 'short', 'no-hash', 'not-hex', 'long', 'name', 'five', 'padded', 'none', 'int'])
def test_malformed_colours_raise_value_error(bad):
    with pytest.raises(ValueError):
        parse_color(bad)
    with pytest.raises(ValueError):
        contrast_ratio(bad, '#000000')


def test_parse_color_reads_both_cases():
    assert parse_color('#0A1b2C') == (10, 27, 44)


def test_ensure_contrast_keeps_a_passing_colour_and_falls_back_below_the_minimum():
    assert ensure_contrast('#000000', '#ffffff', '#222222') == '#000000'
    assert ensure_contrast('#bbbbbb', '#ffffff', '#222222') == '#222222'


def test_ensure_contrast_is_inclusive_at_the_minimum_and_honours_a_custom_one():
    ratio = contrast_ratio('#767676', '#ffffff')
    assert ensure_contrast('#767676', '#ffffff', '#000000', minimum=ratio) == '#767676'
    assert ensure_contrast('#767676', '#ffffff', '#000000', minimum=ratio + 0.001) == '#000000'
    assert ensure_contrast('#949494', '#ffffff', '#000000', minimum=NON_TEXT_CONTRAST) == '#949494'
    assert ensure_contrast('#949494', '#ffffff', '#000000') == '#000000'
