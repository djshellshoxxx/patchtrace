"""Theme tokens and the stylesheet builder (GUI plan 8.6; slice F3). The dark stylesheet is the existing look."""
from __future__ import annotations

import dataclasses

import pytest
from qt_support import join_gui_threads  # noqa: F401

from patchtrace.gui.qt import theme
from patchtrace.gui.qt.theme import DARK, ThemeTokens, build_stylesheet, chip_text_color, contrast_problems
from patchtrace.gui.state import CHIP_TOKENS
from patchtrace.gui.theme_math import contrast_ratio


def test_the_dark_stylesheet_is_the_existing_one_byte_for_byte():
    from patchtrace.ui import DARK_STYLE
    assert build_stylesheet(DARK) == DARK_STYLE


def test_a_token_change_reaches_the_stylesheet():
    other = dataclasses.replace(DARK, accent='#112233')
    sheet = build_stylesheet(other)
    assert sheet.count('#112233') == 2 and sheet.count(DARK.accent) == 0


def test_the_dark_stylesheet_parses_without_warnings(qtbot, qtlog):
    from PySide6.QtWidgets import QWidget
    widget = QWidget()
    qtbot.addWidget(widget)
    widget.setStyleSheet(build_stylesheet(DARK))
    assert not [message for message in qtlog.records if 'parse' in message.message.lower()]


def test_every_dark_token_pair_meets_its_contrast_minimum():
    assert contrast_problems(DARK) == []


@pytest.mark.parametrize('field, value, needle', [
    ('text', '#20262e', 'text on'), ('border', '#222a33', 'border on'), ('focus_ring', '#1a2028', 'focus_ring on'),
], ids=['text', 'border', 'ring'])
def test_a_failing_pair_is_named(field, value, needle):
    problems = contrast_problems(dataclasses.replace(DARK, **{field: value}))
    assert problems and any(needle in problem for problem in problems)


def test_a_failing_chip_edge_is_named():
    chips = tuple((name, theme.ChipColors(colors.fill, '#1c2128')) if name == 'ok' else (name, colors)
                  for name, colors in DARK.chips)
    assert any('chip ok edge' in problem for problem in contrast_problems(dataclasses.replace(DARK, chips=chips)))


def test_every_chip_token_has_colours_and_plain_has_no_fill():
    for token in CHIP_TOKENS:
        colors = DARK.chip(token)
        assert colors.fill.startswith('#') and colors.edge.startswith('#')
    assert DARK.chip('plain').fill == DARK.surface
    assert {name for name, _ in DARK.chips} == set(CHIP_TOKENS) - {'plain'}
    with pytest.raises(KeyError):
        DARK.chip('rainbow')


def test_chip_text_falls_back_to_black_on_an_unreadable_fill():
    assert chip_text_color(DARK, 'ok') == DARK.text
    pale = dataclasses.replace(DARK, chips=(('ok', theme.ChipColors('#e8f5e9', '#2e7d32')),))
    assert chip_text_color(pale, 'ok') == '#000000'
    assert contrast_ratio('#000000', '#e8f5e9') >= 4.5


def test_tokens_are_frozen_and_hashable():
    assert hash(DARK) == hash(dataclasses.replace(DARK))
    with pytest.raises(dataclasses.FrozenInstanceError):
        DARK.text = '#ffffff'  # type: ignore[misc]
    assert isinstance(DARK, ThemeTokens)
