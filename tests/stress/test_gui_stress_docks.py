# ruff: noqa: F811 - the main_window fixture is imported for its name, as in test_gui_host.py
"""Stress: every dock of the real main window shown, hidden, floated, moved and reset in a seeded random order
(GUI plan 8.2 lifecycle, 8.3 layout). The panels are the shipped manifest, not fakes.

After each operation the test waits (on a condition, not a sleep) until the host's view of each panel agrees with
Qt: a panel is active exactly when its dock is visible, its toggle action is checked, and its controller, once built,
is never built a second time. No second top-level main window may appear: a floating dock is not one."""
from __future__ import annotations

import random

from host_support import (  # noqa: E402,F401 - the fake-panel host of the host tests
    make_host,
    private_tooltip_registry,
    spec,
)
from PySide6.QtWidgets import QApplication, QMainWindow
from qt_support import join_gui_threads, main_window, settings, top_level_windows  # noqa: F401

from patchtrace.gui.qt.docks import PanelDock

SEED = 20261015
CYCLES = 3
AREAS = ('left', 'right', 'top', 'bottom')
OPERATIONS = ('show', 'hide', 'toggle', 'float', 'move', 'focus')


def docked(host) -> dict[str, PanelDock]:
    return {panel_id: panel.dock for panel_id, panel in host.panels.items() if panel.dock is not None}


def agreement(host) -> list[str]:
    """Where the host's view and Qt's disagree, empty when they agree."""
    problems = []
    for panel_id, dock in docked(host).items():
        panel = host.panels[panel_id]
        if panel.active != dock.isVisible():
            problems.append(f'{panel_id}: active={panel.active} visible={dock.isVisible()}')
        if dock.toggleViewAction().isChecked() != dock.isVisible():
            problems.append(f'{panel_id}: toggle action disagrees with visibility')
    return problems


def controllers_built(host) -> dict[str, int]:
    return {pid: id(panel.controller) for pid, panel in host.panels.items() if panel.controller is not None}


def foreign_main_windows(window) -> list[str]:
    return [type(w).__name__ for w in top_level_windows() if isinstance(w, QMainWindow) and w is not window]


def test_every_dock_is_shown_hidden_floated_moved_and_reset_in_a_seeded_order(qtbot, main_window):
    window, host = main_window, main_window.panels
    window.show()
    qtbot.waitExposed(window)
    docks = docked(host)
    core = {'evidence', 'series', 'files', 'unified', 'leads'}
    assert core <= set(docks), f'the shipped manifest builds the five core docks and more, found {sorted(docks)}'
    exercise(qtbot, window, host, docks)


def exercise(qtbot, window, host, docks) -> None:
    rng = random.Random(SEED)
    built_once: dict[str, int] = {}
    for cycle in range(CYCLES):
        for panel_id in sorted(docks):
            operation = rng.choice(OPERATIONS)
            if operation == 'show':
                host.show_panel(panel_id)
            elif operation == 'hide':
                docks[panel_id].hide()
            elif operation == 'toggle':
                host.toggle(panel_id)
            elif operation == 'float':
                host.float_panel(panel_id)
            elif operation == 'move':
                host.move_panel(panel_id, rng.choice(AREAS))
            else:
                host.focus_panel(panel_id)
            QApplication.processEvents()
            qtbot.waitUntil(lambda: not agreement(host), timeout=5000)
            assert not foreign_main_windows(window), 'a dock opened a second main window'
        for panel_id, identity in controllers_built(host).items():
            assert built_once.setdefault(panel_id, identity) == identity, f'{panel_id} was built twice'
        if cycle == 0:
            host.reset_layout()
            QApplication.processEvents()
            qtbot.waitUntil(lambda: not agreement(host), timeout=5000)
    state = window.saveState()
    assert window.restoreState(state)
    qtbot.waitUntil(lambda: not agreement(host), timeout=5000)
    assert len(docked(host)) == len(docks) and len(window.findChildren(PanelDock)) >= len(docks)


FAKE_AREAS = ('left', 'right', 'top', 'bottom', 'left', 'right', 'bottom', 'top', 'right', 'bottom', 'left', 'top')


def test_twelve_docks_across_all_areas_and_tab_groups_stay_consistent(qtbot, settings):  # noqa: F811
    tabs = {4: 'p00', 5: 'p01', 9: 'p03'}  # tab groups must share a dock area, or the manifest lint rejects them
    specs = [spec(f'p{index:02d}', area, tabify_with=tabs.get(index)) for index, area in enumerate(FAKE_AREAS)]
    window, host = make_host(qtbot, settings, *specs)
    window.show()
    qtbot.waitExposed(window)
    host.restore_layout()
    assert not host.problems, host.problems
    assert all(host.panels[s.id].dock is not None for s in specs)
    exercise(qtbot, window, host, docked(host))


def test_a_floated_dock_that_is_hidden_and_shown_keeps_one_controller(qtbot, main_window):
    window, host = main_window, main_window.panels
    window.show()
    qtbot.waitExposed(window)
    panel_id = next(pid for pid, dock in docked(host).items() if dock.spec.area != 'none')
    host.show_panel(panel_id)
    first = host.panels[panel_id].controller
    assert first is not None
    for _ in range(25):
        host.float_panel(panel_id)
        host.float_panel(panel_id)
        docked(host)[panel_id].hide()
        host.show_panel(panel_id)
        QApplication.processEvents()
    qtbot.waitUntil(lambda: not agreement(host), timeout=5000)
    assert host.panels[panel_id].controller is first
    assert host.is_shown(panel_id) and host.dock_area(panel_id) != 'none'
    assert not foreign_main_windows(window)
