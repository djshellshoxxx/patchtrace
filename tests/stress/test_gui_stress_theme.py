# ruff: noqa: F811 - the main_window fixture is imported for its name, as in test_gui_host.py
"""Stress: theme switching and a palette change while a background task loads (GUI plan 8.6, slice F3).

The task reports progress in a tight loop and delivers its result on the GUI thread. Every switch must leave the
window stylesheet, the host's tokens and the controller's tokens equal to the one chosen variant, and the task must
still deliver. Waits are on conditions; the only pacing is the runner's own checkpoint."""
from __future__ import annotations

import dataclasses

from PySide6.QtGui import QPalette
from PySide6.QtWidgets import QApplication
from qt_support import join_gui_threads, main_window, settings  # noqa: F401

from patchtrace.gui.qt.theme import DARK, build_stylesheet

SWITCHES = 60
LOAD_STEPS = 40_000


def start_load(host, results, progress):
    def load(token, report):
        for index in range(LOAD_STEPS):
            report('load', index, LOAD_STEPS)
            token.checkpoint()
        return 'loaded'
    return host.tasks.submit('load', load, results.append, None, progress.append)


def assert_consistent(window, host, variant: str) -> None:
    theme = host.theme_controller
    assert theme.variant == variant
    assert host.tokens is theme.tokens or host.tokens == theme.tokens
    expected = build_stylesheet(DARK) if theme.effective == 'dark' else ''
    assert window.styleSheet() == expected


def test_sixty_theme_switches_during_a_load_keep_every_surface_on_one_variant(qtbot, main_window):
    window, host = main_window, main_window.panels
    window.show()
    qtbot.waitExposed(window)
    for panel_id in [pid for pid, panel in host.panels.items() if panel.dock is not None][:3]:
        host.show_panel(panel_id)
    results, progress = [], []
    start_load(host, results, progress)
    for index in range(SWITCHES):
        variant = 'system' if index % 2 else 'dark'
        host.theme_controller.set_variant(variant)
        QApplication.processEvents()
        assert_consistent(window, host, variant)
    qtbot.waitUntil(lambda: results == ['loaded'])
    assert progress and progress[-1].done == LOAD_STEPS - 1
    assert_consistent(window, host, 'system')


def test_a_palette_change_mid_load_retokens_the_host_without_losing_the_result(qtbot, main_window):
    window, host = main_window, main_window.panels
    window.show()
    qtbot.waitExposed(window)
    host.theme_controller.set_variant('system')
    results, progress = [], []
    start_load(host, results, progress)
    before = host.tokens
    palette = QPalette(QApplication.palette())
    palette.setColor(QPalette.ColorRole.Window, palette.color(QPalette.ColorRole.Base).darker(180))
    palette.setColor(QPalette.ColorRole.WindowText, palette.color(QPalette.ColorRole.Text).lighter(140))
    try:
        QApplication.setPalette(palette)
        QApplication.processEvents()
        assert host.tokens == host.theme_controller.tokens
        assert host.tokens != DARK
    finally:
        QApplication.setPalette(QApplication.style().standardPalette())
        QApplication.processEvents()
    qtbot.waitUntil(lambda: results == ['loaded'])
    assert before is not None
    assert dataclasses.is_dataclass(host.tokens)
