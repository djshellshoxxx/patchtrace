"""WBQ S7 (codetext-core): the dark palette, WCAG contrast and colour-vision-deficiency checks. Pure; no Qt is needed
except for one parity test against `ui_evidence.contrast_ratio`.

The numbers were recomputed here rather than copied from docs/specs/program-e/WBQ-integration-plan.md (s2 and s8):
the contrast table with the WCAG formula, the colour-blind distances with CIEDE2000 on Machado 2009 simulations.
The CIEDE2000 implementation below reproduces the published test pairs of Sharma, Wu and Dalal (2005) to four
decimals (test_ciede2000_reproduces_the_published_pairs), so a wrong formula cannot make the palette look safe.
"""
from __future__ import annotations

import math
import random
import re
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from patchtrace.codetext import tokens
from patchtrace.codetext.palette import (
    MARK_STATES,
    MIN_MARK_CONTRAST,
    MIN_TEXT_CONTRAST,
    ROLE_BY_KIND,
    ROLES,
    MarkStyle,
    Palette,
    Style,
    contrast_ratio,
    guard_color,
)

FAST = settings(deadline=None, suppress_health_check=[HealthCheck.too_slow], max_examples=150)
UI_SOURCE = Path(__file__).parents[1] / 'src' / 'patchtrace' / 'ui.py'
DARK = Palette('dark')
HEX = re.compile(r'#[0-9a-f]{6}')


def colors():
    return st.integers(0, 0xFFFFFF).map(lambda n: f'#{n:06x}')


# --- the WCAG formula -----------------------------------------------------------------------------------------------

@pytest.mark.parametrize('first, second, ratio', [
    pytest.param('#000000', '#ffffff', 21.0, id='black-white'),
    pytest.param('#ffffff', '#ffffff', 1.0, id='same'),
    pytest.param('#767676', '#ffffff', 4.54, id='aa-boundary-grey'),
    pytest.param('#777777', '#ffffff', 4.48, id='just-below-aa'),
])
def test_contrast_ratio_known_values(first, second, ratio):
    assert contrast_ratio(first, second) == pytest.approx(ratio, abs=0.005)


@FAST
@given(first=colors(), second=colors())
def test_contrast_ratio_is_symmetric_and_in_range(first, second):
    ratio = contrast_ratio(first, second)
    assert ratio == contrast_ratio(second, first)
    assert 1.0 <= ratio <= 21.0 + 1e-9


@FAST
@given(color=colors())
def test_a_colour_has_no_contrast_with_itself(color):
    assert contrast_ratio(color, color) == 1.0


@pytest.mark.parametrize('bad', ['red', '#fff', '#12345g', '', '#1234567', 'ffffff', '#ffffff '],
                         ids=['name', 'shorthand', 'not-hex', 'empty', 'too-long', 'no-hash', 'space'])
def test_contrast_ratio_refuses_anything_but_hex_rgb(bad):
    with pytest.raises(ValueError, match='#rrggbb'):
        contrast_ratio(bad, '#000000')


@pytest.fixture(scope='module')
def evidence_ratio():
    pytest.importorskip('PySide6.QtWidgets', reason='the parity target lives in a Qt module')
    from patchtrace.ui_evidence import contrast_ratio as ratio

    return ratio


@FAST
@given(first=colors(), second=colors())
def test_contrast_ratio_equals_the_evidence_panel_helper(evidence_ratio, first, second):
    assert contrast_ratio(first, second) == pytest.approx(evidence_ratio(first, second), abs=1e-12)


# --- the palette ----------------------------------------------------------------------------------------------------

def test_dark_theme_is_the_only_theme():
    assert Palette().theme == 'dark'
    with pytest.raises(ValueError, match="unknown theme 'light'"):
        Palette('light')


def test_every_role_and_mark_state_has_a_style():
    assert ROLES == ('text', 'keyword', 'number', 'string', 'comment', 'address', 'register', 'stack', 'symbol', 'size',
                     'temp', 'mnemonic')
    assert MARK_STATES == ('changed', 'address-only', 'rename-maybe')
    for role in ROLES:
        assert isinstance(DARK.style(role), Style) and HEX.fullmatch(DARK.style(role).color)
    for state in MARK_STATES:
        assert isinstance(DARK.mark(state), MarkStyle) and HEX.fullmatch(DARK.mark(state).color)
    with pytest.raises(KeyError):
        DARK.style('nonexistent')
    with pytest.raises(KeyError):
        DARK.mark('nonexistent')


def test_every_token_kind_maps_to_a_role():
    assert set(ROLE_BY_KIND) == set(tokens.KINDS)
    assert set(ROLE_BY_KIND.values()) <= set(ROLES)
    with pytest.raises(TypeError):
        ROLE_BY_KIND['ws'] = 'comment'


def test_forms_repeat_what_colour_says():
    """Bold, italic and underline style carry the class too: Qt's UI Automation provider hides colour."""
    assert DARK.style('mnemonic') == Style(DARK.style('text').color, bold=True)
    assert DARK.style('comment').italic and not DARK.style('comment').bold
    assert DARK.mark('changed') == MarkStyle('single', '#f0e442', bold=True)
    assert DARK.mark('address-only') == MarkStyle('dotted', '#93a7bd', italic=True)
    assert DARK.mark('rename-maybe') == MarkStyle('dashed', '#93a7bd')
    assert len({DARK.mark(state).underline for state in MARK_STATES}) == 3


def test_no_two_roles_share_a_colour_except_mnemonic_and_text():
    seen: dict[str, str] = {}
    for role in ROLES:
        color = DARK.style(role).color
        assert color not in seen or {role, seen[color]} == {'text', 'mnemonic'}, (role, seen.get(color))
        seen[color] = role


# --- contrast on the three backgrounds (WCAG 1.4.3 text 4.5:1, 1.4.11 marks 3:1) -------------------------------------

# Ratios on the pane base printed in the plan (s8), one decimal.
PLAN_ON_BASE = {'text': 13.9, 'keyword': 7.9, 'number': 8.9, 'string': 9.6, 'comment': 7.4, 'address': 7.7,
                'register': 9.6, 'stack': 10.6, 'symbol': 13.9}


def test_the_three_backgrounds_are_the_theme_backgrounds():
    assert DARK.backgrounds == ('#10151c', '#263a43', '#33392b')
    assert (DARK.base, DARK.hunk_replace, DARK.hunk_edit) == DARK.backgrounds


@pytest.mark.parametrize('role', ROLES)
def test_every_text_role_reaches_aa_on_all_three_backgrounds(role):
    ratios = [contrast_ratio(DARK.style(role).color, background) for background in DARK.backgrounds]
    assert min(ratios) >= MIN_TEXT_CONTRAST, ratios


@pytest.mark.parametrize('role, printed', sorted(PLAN_ON_BASE.items()), ids=sorted(PLAN_ON_BASE))
def test_contrast_on_the_base_equals_the_printed_table(role, printed):
    assert contrast_ratio(DARK.style(role).color, DARK.base) == pytest.approx(printed, abs=0.05)


def test_the_weakest_pair_is_comment_on_the_replace_hunk():
    pairs = {(role, background): contrast_ratio(DARK.style(role).color, background)
             for role in ROLES for background in DARK.backgrounds}
    weakest = min(pairs, key=pairs.__getitem__)
    assert weakest == ('comment', DARK.hunk_replace)
    assert pairs[weakest] == pytest.approx(4.81, abs=0.01)


@pytest.mark.parametrize('state', MARK_STATES)
def test_every_mark_colour_reaches_the_non_text_minimum(state):
    ratios = [contrast_ratio(DARK.mark(state).color, background) for background in DARK.backgrounds]
    assert min(ratios) >= MIN_MARK_CONTRAST, ratios


def test_the_changed_mark_is_the_strongest_on_the_hunks():
    on_hunks = [contrast_ratio(DARK.mark('changed').color, b) for b in (DARK.hunk_replace, DARK.hunk_edit)]
    assert min(on_hunks) == pytest.approx(8.98, abs=0.01)


def test_the_thresholds_are_the_wcag_levels():
    assert MIN_TEXT_CONTRAST == 4.5 and MIN_MARK_CONTRAST == 3.0


# --- bound to the app: ui.py is read as text, never imported ----------------------------------------------------------

def ui_text() -> str:
    return UI_SOURCE.read_text(encoding='utf-8')


def test_pane_base_is_the_code_view_background_of_dark_style():
    match = re.search(r'QLineEdit, QPlainTextEdit, QTextEdit, QListWidget \{ background: (#[0-9a-f]{6});', ui_text())
    assert match and match.group(1) == DARK.base


def test_text_role_is_the_default_text_colour_of_dark_style():
    match = re.search(r'QWidget \{ background: #[0-9a-f]{6}; color: (#[0-9a-f]{6});', ui_text())
    assert match and match.group(1) == DARK.style('text').color


def test_hunk_colours_are_the_ones_the_panes_paint():
    """Since migration M4 the panes paint hunks through `gui.qt.codediff.hunk_background` with the theme tokens."""
    from patchtrace.gui.qt.codediff import hunk_background
    from patchtrace.gui.qt.theme import DARK as DARK_TOKENS
    assert hunk_background('replace', DARK_TOKENS).lower() == DARK.hunk_replace
    assert hunk_background('insert', DARK_TOKENS).lower() == DARK.hunk_edit


# --- the runtime guard ------------------------------------------------------------------------------------------------

@pytest.mark.parametrize('color, backgrounds, minimum, expected', [
    pytest.param('#56b4e9', ['#10151c'], 4.5, '#56b4e9', id='readable'),
    pytest.param('#10151c', ['#10151c'], 4.5, '#d9e1ec', id='invisible'),
    pytest.param('#56b4e9', ['#10151c', '#ffffff'], 4.5, '#d9e1ec', id='one-background-fails'),
    pytest.param('#56b4e9', [], 4.5, '#56b4e9', id='no-background-no-objection'),
    pytest.param('#767676', ['#ffffff'], 4.5, '#767676', id='just-over'),
    pytest.param('#777777', ['#ffffff'], 4.5, '#d9e1ec', id='just-under'),
    pytest.param('#777777', ['#ffffff'], 4.4, '#777777', id='custom-minimum'),
])
def test_guard_keeps_a_readable_colour_and_replaces_an_unreadable_one(color, backgrounds, minimum, expected):
    assert guard_color(color, backgrounds, '#d9e1ec', minimum) == expected


@pytest.mark.parametrize('color, background', [('#56b4e9', '#10151c'), ('#777777', '#ffffff'), ('#93a7bd', '#263a43')],
                         ids=['readable', 'just-under-aa', 'weakest-palette-pair'])
def test_guard_threshold_is_inclusive(color, background):
    """A colour exactly at the minimum is readable: the boundary is the pair's own ratio, not a rounded figure."""
    ratio = contrast_ratio(color, background)
    assert guard_color(color, [background], '#d9e1ec', ratio) == color
    assert guard_color(color, [background], '#d9e1ec', math.nextafter(ratio, math.inf)) == '#d9e1ec'


def test_guard_accepts_any_iterable_of_backgrounds():
    assert guard_color('#56b4e9', iter(DARK.backgrounds), '#d9e1ec') == '#56b4e9'


# --- colour-vision deficiency ---------------------------------------------------------------------------------------

# Machado, Oliveira and Fernandes (2009), "A Physiologically-based Model for Simulation of Color Vision Deficiency"
# (IEEE TVCG), severity 1.0 (dichromacy), applied to linear sRGB. This is the one validated set: the numbers are
# MACHADO_ET_AL_MATRICES[...][100] of colorspacious 1.1.2 (MIT, cvd.py), compared entry by entry when this file was
# written. Do not add a second copy; the GUI plan (s10, item 10) says to reuse these.
MACHADO = {
    'protan': ((0.152286, 1.052583, -0.204868), (0.114503, 0.786281, 0.099216), (-0.003882, -0.048116, 1.051998)),
    'deutan': ((0.367322, 0.860646, -0.227968), (0.280085, 0.672501, 0.047413), (-0.011820, 0.042940, 0.968881)),
    'tritan': ((1.255528, -0.076749, -0.178779), (-0.078411, 0.930809, 0.147602), (0.004733, 0.691367, 0.303900)),
}
IDENTITY = ((1.0, 0.0, 0.0), (0.0, 1.0, 0.0), (0.0, 0.0, 1.0))
VISIONS = {'normal': IDENTITY, **MACHADO}
# sRGB (D65) to XYZ, IEC 61966-2-1; the white point is the sum of its rows.
SRGB_TO_XYZ = ((0.4124564, 0.3575761, 0.1804375), (0.2126729, 0.7151522, 0.0721750), (0.0193339, 0.1191920, 0.9503041))
WHITE = tuple(sum(row) for row in SRGB_TO_XYZ)


def to_linear(channel: float) -> float:
    return channel / 12.92 if channel < 0.04045 else ((channel + 0.055) / 1.055) ** 2.4


def to_srgb(channel: float) -> float:
    return channel * 12.92 if channel <= 0.0031308 else 1.055 * channel ** (1 / 2.4) - 0.055


def linear_rgb(color: str) -> tuple[float, float, float]:
    r, g, b = (to_linear(int(color[i:i + 2], 16) / 255) for i in (1, 3, 5))
    return r, g, b


def apply(matrix, vector):
    return tuple(sum(matrix[row][col] * vector[col] for col in range(3)) for row in range(3))


def lab(linear: tuple[float, float, float]) -> tuple[float, float, float]:
    xyz = apply(SRGB_TO_XYZ, linear)

    def f(t: float) -> float:
        return t ** (1 / 3) if t > (6 / 29) ** 3 else t / (3 * (6 / 29) ** 2) + 4 / 29

    fx, fy, fz = (f(xyz[i] / WHITE[i]) for i in range(3))
    return 116 * fy - 16, 500 * (fx - fy), 200 * (fy - fz)


def ciede2000(first, second) -> float:
    """CIEDE2000 between two Lab colours, following Sharma, Wu and Dalal (2005) step by step."""
    l1, a1, b1 = first
    l2, a2, b2 = second
    c_mean = (math.hypot(a1, b1) + math.hypot(a2, b2)) / 2
    g = 0.5 * (1 - math.sqrt(c_mean ** 7 / (c_mean ** 7 + 25 ** 7)))
    ap1, ap2 = (1 + g) * a1, (1 + g) * a2
    cp1, cp2 = math.hypot(ap1, b1), math.hypot(ap2, b2)
    hp1 = math.degrees(math.atan2(b1, ap1)) % 360 if (b1 or ap1) else 0.0
    hp2 = math.degrees(math.atan2(b2, ap2)) % 360 if (b2 or ap2) else 0.0
    d_l, d_c = l2 - l1, cp2 - cp1
    if cp1 * cp2 == 0:
        d_h = 0.0
    else:
        d_h = hp2 - hp1
        d_h -= 360 if d_h > 180 else -360 if d_h < -180 else 0
    d_big_h = 2 * math.sqrt(cp1 * cp2) * math.sin(math.radians(d_h / 2))
    l_mean, c_bar = (l1 + l2) / 2, (cp1 + cp2) / 2
    if cp1 * cp2 == 0:
        h_bar = hp1 + hp2
    elif abs(hp1 - hp2) <= 180:
        h_bar = (hp1 + hp2) / 2
    else:
        h_bar = (hp1 + hp2 + (360 if hp1 + hp2 < 360 else -360)) / 2
    t = (1 - 0.17 * math.cos(math.radians(h_bar - 30)) + 0.24 * math.cos(math.radians(2 * h_bar))
         + 0.32 * math.cos(math.radians(3 * h_bar + 6)) - 0.20 * math.cos(math.radians(4 * h_bar - 63)))
    r_c = 2 * math.sqrt(c_bar ** 7 / (c_bar ** 7 + 25 ** 7))
    s_l = 1 + 0.015 * (l_mean - 50) ** 2 / math.sqrt(20 + (l_mean - 50) ** 2)
    s_c, s_h = 1 + 0.045 * c_bar, 1 + 0.015 * c_bar * t
    r_t = -math.sin(math.radians(2 * 30 * math.exp(-(((h_bar - 275) / 25) ** 2)))) * r_c
    return math.sqrt((d_l / s_l) ** 2 + (d_c / s_c) ** 2 + (d_big_h / s_h) ** 2
                     + r_t * (d_c / s_c) * (d_big_h / s_h))


def distance(first: str, second: str, vision: str) -> float:
    """CIEDE2000 between two #rrggbb colours as seen with the given vision (normal, protan, deutan, tritan)."""
    seen = [lab(apply(VISIONS[vision], linear_rgb(color))) for color in (first, second)]
    return ciede2000(*seen)


# Pairs 1, 2, 7, 9, 13, 16 to 20 of the Sharma, Wu and Dalal (2005) test data: (Lab 1, Lab 2, CIEDE2000).
SHARMA = [
    ((50.0, 2.6772, -79.7751), (50.0, 0.0, -82.7485), 2.0425),
    ((50.0, 3.1571, -77.2803), (50.0, 0.0, -82.7485), 2.8615),
    ((50.0, 0.0, 0.0), (50.0, -1.0, 2.0), 2.3669),
    ((50.0, 2.49, -0.001), (50.0, -2.49, 0.0009), 7.1792),
    ((50.0, -0.001, 2.49), (50.0, 0.0009, -2.49), 4.8045),
    ((50.0, 2.5, 0.0), (50.0, 0.0, -2.5), 4.3065),
    ((50.0, 2.5, 0.0), (73.0, 25.0, -18.0), 27.1492),
    ((50.0, 2.5, 0.0), (61.0, -5.0, 29.0), 22.8977),
    ((50.0, 2.5, 0.0), (56.0, -27.0, -3.0), 31.9030),
    ((50.0, 2.5, 0.0), (58.0, 24.0, 15.0), 19.4535),
]


@pytest.mark.parametrize('first, second, published', SHARMA, ids=[f'pair-{i}' for i in range(len(SHARMA))])
def test_ciede2000_reproduces_the_published_pairs(first, second, published):
    assert ciede2000(first, second) == pytest.approx(published, abs=6e-5)
    assert ciede2000(second, first) == pytest.approx(published, abs=6e-5)


@pytest.mark.parametrize('vision', sorted(MACHADO))
def test_machado_rows_sum_to_one_so_greys_stay_grey(vision):
    for row in MACHADO[vision]:
        assert sum(row) == pytest.approx(1.0, abs=2e-6)
    for grey in ('#000000', '#808080', '#ffffff'):
        seen = apply(MACHADO[vision], linear_rgb(grey))
        assert seen == pytest.approx(linear_rgb(grey), abs=2e-6)


def test_distance_between_identical_colours_is_zero_and_symmetric():
    for vision in VISIONS:
        assert distance('#e9a93a', '#e9a93a', vision) == pytest.approx(0.0, abs=1e-9)
        assert distance('#e9a93a', '#e08fbf', vision) == pytest.approx(distance('#e08fbf', '#e9a93a', vision), abs=1e-9)


# Floors are the plan's printed figures (s8) less 0.1: "scalar versus address >= 35.6 under protan and deutan, 8.4
# under tritan; register versus address >= 10.3". Recomputed here: 42.7, 35.58, 8.42 and 10.27 (protan) respectively.
@pytest.mark.parametrize('vision, floor', [('protan', 35.5), ('deutan', 35.5), ('tritan', 8.3), ('normal', 35.5)])
def test_number_and_address_colours_stay_apart_under_colour_blindness(vision, floor):
    assert distance(DARK.style('number').color, DARK.style('address').color, vision) >= floor


@pytest.mark.parametrize('vision', sorted(VISIONS))
def test_register_and_address_colours_stay_apart_under_colour_blindness(vision):
    assert distance(DARK.style('register').color, DARK.style('address').color, vision) >= 10.2


@pytest.mark.parametrize('first, second, vision, printed', [
    pytest.param('number', 'address', 'deutan', 35.6, id='scalar-address-deutan'),
    pytest.param('number', 'address', 'tritan', 8.4, id='scalar-address-tritan'),
    pytest.param('register', 'address', 'protan', 10.3, id='register-address-protan'),
])
def test_the_printed_distances_reproduce(first, second, vision, printed):
    """The plan prints the minima; they must be the actual minima, not just lower bounds of a different palette."""
    assert distance(DARK.style(first).color, DARK.style(second).color, vision) == pytest.approx(printed, abs=0.1)


@FAST
@given(first=colors(), second=colors())
def test_the_colour_difference_is_a_symmetric_non_negative_number(first, second):
    """Random pairs cross the hue-wrap and zero-chroma branches of CIEDE2000, where implementations go wrong."""
    for vision in VISIONS:
        forward = distance(first, second, vision)
        assert forward >= 0.0
        assert forward == pytest.approx(distance(second, first, vision), abs=1e-9)


def test_simulation_equals_colorspacious_when_it_is_installed():
    cs = pytest.importorskip('colorspacious', reason='the validation oracle is optional and not a dependency')
    names = {'protan': 'protanomaly', 'deutan': 'deuteranomaly', 'tritan': 'tritanomaly'}
    rng = random.Random(2026)
    for _ in range(300):
        color = f'#{rng.randrange(1 << 24):06x}'
        rgb = [int(color[i:i + 2], 16) / 255 for i in (1, 3, 5)]
        for vision, name in names.items():
            want = cs.cspace_convert(rgb, {'name': 'sRGB1+CVD', 'cvd_type': name, 'severity': 100}, 'sRGB1')
            got = [to_srgb(c) for c in apply(MACHADO[vision], linear_rgb(color))]
            assert got == pytest.approx(list(want), abs=1e-9), (color, vision)
