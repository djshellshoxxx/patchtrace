"""System theme, automatic high contrast, reduced motion and View > Theme (GUI plan 8.6; slice F7). The platform is a
simulated provider: no test depends on the OS, on a display, or on real high-contrast settings."""
from __future__ import annotations

from collections.abc import Callable

import pytest
from host_support import private_tooltip_registry  # noqa: F401
from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QPalette
from PySide6.QtWidgets import QApplication, QMainWindow, QMenu
from qt_support import join_gui_threads, main_window, settings  # noqa: F401

from patchtrace.gui.qt.theme import (
    DARK,
    SETTINGS_KEY,
    QtSystemPrefs,
    ThemeController,
    contrast_problems,
    install_theme_menu,
    system_tokens,
)
from patchtrace.gui.state import CHIP_TOKENS
from patchtrace.gui.tips import register_gui_tips


def palette(window: str, text: str, base: str | None = None, highlight: str = '#3875d7',
            link: str = '#1a5fb4') -> QPalette:
    result = QPalette()
    for role, color in ((QPalette.ColorRole.Window, window), (QPalette.ColorRole.WindowText, text),
                        (QPalette.ColorRole.Base, base or window), (QPalette.ColorRole.Highlight, highlight),
                        (QPalette.ColorRole.Link, link), (QPalette.ColorRole.PlaceholderText, '#808080')):
        result.setColor(role, QColor(color))
    return result


LIGHT = palette('#f4f4f4', '#202020', '#ffffff')
DARKISH = palette('#2b2b2b', '#e8e8e8', '#1e1e1e', '#4a90d9', '#7ab7ff')
HC_BLACK = palette('#000000', '#ffffff', '#000000', '#1aebff', '#ffff00')
HC_WHITE = palette('#ffffff', '#000000', '#ffffff', '#37006e', '#00009f')
HOSTILE = palette('#808080', '#8a8a8a', '#7a7a7a', '#838383', '#868686')


class FakePrefs:
    """A simulated platform: contrast and motion preferences and a palette, with a change notification."""

    def __init__(self, pal: QPalette = LIGHT, *, contrast: bool = False, reduced: bool = False) -> None:
        self.pal, self.contrast, self.reduced = pal, contrast, reduced
        self.callbacks: list[Callable[[], None]] = []

    def high_contrast(self) -> bool:
        return self.contrast

    def reduced_motion(self) -> bool:
        return self.reduced

    def palette(self) -> QPalette:
        return self.pal

    def on_change(self, callback: Callable[[], None]) -> None:
        self.callbacks.append(callback)

    def change(self, **fields: object) -> None:
        for name, value in fields.items():
            setattr(self, name, value)
        for callback in self.callbacks:
            callback()


@pytest.fixture(autouse=True)
def tips(private_tooltip_registry):  # noqa: F811
    register_gui_tips()


@pytest.fixture
def window(qtbot):
    result = QMainWindow()
    qtbot.addWidget(result)
    return result


def make(window, settings, prefs):  # noqa: F811
    result = ThemeController(window, settings, prefs, parent=window)
    result.refresh()
    return result


# ---- contrast per variant ---------------------------------------------------------------------------------------

@pytest.mark.parametrize('pal, high', [(LIGHT, False), (DARKISH, False), (HC_BLACK, True), (HC_WHITE, True)],
                         ids=['light', 'dark', 'hc-black', 'hc-white'])
def test_every_token_pair_of_a_real_palette_meets_its_minimum(pal, high):
    assert contrast_problems(system_tokens(pal, high_contrast=high)) == []


def test_a_hostile_palette_degrades_to_text_without_hiding_it():
    tokens = system_tokens(HOSTILE)
    assert tokens.accent == tokens.text and tokens.focus_ring == tokens.text


def test_high_contrast_drops_fills_tints_and_dimming():
    tokens = system_tokens(HC_BLACK, high_contrast=True)
    assert tokens.high_contrast and tokens.text_muted == tokens.text and tokens.border == tokens.text
    assert {tokens.chip(name).fill for name in CHIP_TOKENS} == {tokens.surface}
    assert {tokens.chip(name).edge for name in CHIP_TOKENS if name != 'plain'} == {tokens.text}
    assert tokens.hunk_replace == tokens.hunk_other == tokens.surface_alt


def test_a_light_system_palette_keeps_the_chip_edges_distinct():
    tokens = system_tokens(LIGHT)
    assert not tokens.high_contrast
    assert len({tokens.chip(name).edge for name in CHIP_TOKENS if name != 'plain'}) == len(CHIP_TOKENS) - 1


# ---- the controller ---------------------------------------------------------------------------------------------

def test_dark_is_the_default_and_keeps_the_stylesheet(window, settings):  # noqa: F811
    theme = make(window, settings, FakePrefs())
    assert theme.variant == 'dark' and theme.effective == 'dark' and theme.tokens == DARK
    assert 'background: #161b22' in window.styleSheet()


def test_system_has_no_stylesheet_and_reads_the_palette(window, settings):  # noqa: F811
    theme = make(window, settings, FakePrefs(LIGHT))
    theme.set_variant('system')
    assert window.styleSheet() == '' and theme.tokens.surface == '#f4f4f4'
    assert settings.value(SETTINGS_KEY) == 'system'


def test_the_choice_is_restored_and_a_bad_stored_value_means_dark(window, settings):  # noqa: F811
    settings.setValue(SETTINGS_KEY, 'system')
    assert make(window, settings, FakePrefs()).variant == 'system'
    settings.setValue(SETTINGS_KEY, 'neon')
    assert make(window, settings, FakePrefs()).variant == 'dark'


def test_an_unknown_variant_is_rejected(window, settings):  # noqa: F811
    with pytest.raises(ValueError, match='neon'):
        make(window, settings, FakePrefs()).set_variant('neon')


def test_high_contrast_switches_on_and_off_automatically(window, settings):  # noqa: F811
    prefs = FakePrefs(HC_BLACK)
    theme = make(window, settings, prefs)
    seen = []
    theme.theme_changed.connect(seen.append)
    prefs.change(contrast=True)
    assert theme.effective == 'high-contrast' and window.styleSheet() == '' and seen[-1].high_contrast
    assert theme.variant == 'dark'  # the choice is kept, only overridden
    prefs.change(contrast=False)
    assert theme.effective == 'dark' and theme.tokens == DARK and window.styleSheet() != '' and len(seen) == 2


def test_a_palette_change_re_emits_and_an_unchanged_one_does_not(window, settings):  # noqa: F811
    prefs = FakePrefs(LIGHT)
    theme = make(window, settings, prefs)
    theme.set_variant('system')
    seen = []
    theme.theme_changed.connect(seen.append)
    prefs.change()
    assert seen == []
    prefs.change(pal=DARKISH)
    assert [tokens.surface for tokens in seen] == ['#2b2b2b']


def test_reduced_motion_disables_widget_animations_and_restores_them(window, settings):  # noqa: F811
    before = QApplication.isEffectEnabled(Qt.UIEffect.UI_AnimateMenu)
    prefs = FakePrefs()
    theme = make(window, settings, prefs)
    flags = []
    theme.motion_changed.connect(flags.append)
    prefs.change(reduced=True)
    assert theme.reduced_motion and not QApplication.isEffectEnabled(Qt.UIEffect.UI_AnimateMenu) and flags == [True]
    prefs.change(contrast=False)  # an unrelated change does not repeat the signal
    assert flags == [True]
    prefs.change(reduced=False)
    assert QApplication.isEffectEnabled(Qt.UIEffect.UI_AnimateMenu) == before and flags == [True, False]
    QApplication.setEffectEnabled(Qt.UIEffect.UI_AnimateMenu, before)


def test_the_qt_provider_reports_a_quiet_platform(qapp):
    prefs = QtSystemPrefs(qapp)
    assert prefs.high_contrast() is False and prefs.reduced_motion() is False
    assert prefs.palette().color(QPalette.ColorRole.Window).isValid()
    hits = []
    prefs.on_change(lambda: hits.append(1))
    prefs._notify()
    assert hits == [1]
    prefs.deleteLater()


# ---- View > Theme -----------------------------------------------------------------------------------------------

def test_the_theme_menu_checks_the_variant_and_explains_high_contrast(window, settings):  # noqa: F811
    prefs = FakePrefs(HC_BLACK)
    theme = make(window, settings, prefs)
    sub = install_theme_menu(window.menuBar().addMenu('View'), theme)
    actions = {action.objectName(): action for action in sub.actions()}
    assert sub.objectName() == 'menu.view.theme'
    assert actions['gui.theme.dark'].isChecked() and not actions['gui.theme.system'].isChecked()
    assert actions['gui.theme.note'].isVisible() is False
    actions['gui.theme.system'].trigger()
    assert theme.variant == 'system' and actions['gui.theme.system'].isChecked()
    prefs.change(contrast=True)
    assert actions['gui.theme.note'].isVisible() and not actions['gui.theme.note'].isEnabled()


def test_the_host_installs_the_theme_menu_and_follows_the_choice(main_window):  # noqa: F811
    host = main_window.panels
    assert host.view_menu.findChild(QMenu, 'menu.view.theme') is not None
    seen = []
    host.theme_controller.theme_changed.connect(seen.append)
    host.theme_controller.set_variant('system')
    assert host.tokens is seen[-1] and main_window.styleSheet() == ''
    host.theme_controller.set_variant('dark')
    assert host.tokens == DARK and main_window.styleSheet() != ''
