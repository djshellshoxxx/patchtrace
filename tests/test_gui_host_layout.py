# ruff: noqa: F811
"""Dock layout persistence, reset, the View menu and the notice wrapper (GUI plan 8.3, PT-GUI-LAYOUT)."""
from __future__ import annotations

import hashlib

import pytest
from host_support import Window, make_host, private_tooltip_registry, spec, tips_for  # noqa: F401
from PySide6.QtCore import QByteArray, Qt, qInstallMessageHandler
from PySide6.QtWidgets import QPlainTextEdit, QTabBar, QToolBar
from qt_support import join_gui_threads, settings  # noqa: F401

from patchtrace.gui.qt import layout
from patchtrace.gui.qt.host import PanelHost

LEFT, RIGHT = Qt.DockWidgetArea.LeftDockWidgetArea, Qt.DockWidgetArea.RightDockWidgetArea


@pytest.fixture
def qt_messages():
    seen: list[str] = []
    previous = qInstallMessageHandler(lambda _kind, _context, message: seen.append(message))
    yield seen
    qInstallMessageHandler(previous)


def started(qtbot, settings, *specs):
    window, host = make_host(qtbot, settings, *specs)
    window.show()
    host.restore_layout()
    return window, host


def test_a_first_run_restores_nothing_and_says_nothing(qtbot, settings):
    window, host = started(qtbot, settings, spec('alpha'), spec('beta', default_visible=True))
    assert window.statusBar().currentMessage() == ''
    assert host.panels['beta'].dock.isVisible() and host.panels['alpha'].dock.isHidden()


def test_the_layout_round_trips_through_settings(qtbot, settings):
    window, host = started(qtbot, settings, spec('alpha'))
    host.move_panel('alpha', 'left')
    host.shutdown()
    assert settings.value('layout/schema') in (1, '1') and len(bytes(settings.value('layout/state'))) > 0
    second, again = make_host(qtbot, settings, spec('alpha'))
    again.restore_layout()
    dock = again.panels['alpha'].dock
    assert second.dockWidgetArea(dock) == LEFT and not dock.isHidden()


def save_good_layout(qtbot, settings):
    window, host = started(qtbot, settings, spec('alpha'))
    host.show_panel('alpha')
    host.shutdown()
    return bytes(settings.value('layout/state'))


def corrupt_digest(settings, state):
    settings.setValue('layout/state_sha256', 'f' * 64)


def corrupt_schema(settings, state):
    settings.setValue('layout/schema', 99)


def oversize(settings, state):
    big = state + b'\0' * layout.MAX_STATE_BYTES
    settings.setValue('layout/state', QByteArray(big))
    settings.setValue('layout/state_sha256', hashlib.sha256(big).hexdigest())


def garbage_with_a_valid_digest(settings, state):
    junk = b'not a qt main window state'
    settings.setValue('layout/state', QByteArray(junk))
    settings.setValue('layout/state_sha256', hashlib.sha256(junk).hexdigest())


def missing_state(settings, state):
    settings.remove('layout/state')


@pytest.mark.parametrize('damage', [corrupt_digest, corrupt_schema, oversize, garbage_with_a_valid_digest,
                                    missing_state], ids=['digest', 'schema', 'oversize', 'garbage', 'no-state'])
def test_an_untrusted_layout_means_defaults_and_a_status_line(qtbot, settings, damage):
    state = save_good_layout(qtbot, settings)
    damage(settings, state)
    window, host = started(qtbot, settings, spec('alpha'))
    assert window.statusBar().currentMessage() == layout.FAILED_TEXT
    assert host.panels['alpha'].dock.isHidden() and window.dockWidgetArea(host.panels['alpha'].dock) == RIGHT
    assert not settings.contains('layout/state')  # the bad blob is dropped, not retried at every start


def test_reset_clears_the_settings_and_puts_every_panel_back(qtbot, settings, monkeypatch):
    window, host = started(qtbot, settings, spec('alpha'), spec('beta', default_visible=True))
    host.move_panel('alpha', 'left')
    host.shutdown()
    again_window, again = make_host(qtbot, settings, spec('alpha'), spec('beta', default_visible=True))
    again_window.show()
    again.restore_layout()
    sent = []
    monkeypatch.setattr(again.announcer, '_sender', lambda target, text, assertive: sent.append(text))
    again.reset_layout()
    assert not any(settings.contains(key) for key in ('layout/schema', 'layout/state', 'layout/state_sha256'))
    assert again_window.dockWidgetArea(again.panels['alpha'].dock) == RIGHT and again.panels['beta'].dock.isVisible()
    assert again_window.statusBar().currentMessage() == layout.RESET_TEXT and sent == [layout.RESET_TEXT]


def test_saving_and_restoring_never_warns_about_unnamed_objects(qtbot, settings, qt_messages):
    window = Window(settings)
    qtbot.addWidget(window)
    window.addToolBar('Main actions')
    window.addToolBar('')
    host = PanelHost(window, ())
    window.show()
    host.restore_layout()
    host.shutdown()
    names = [bar.objectName() for bar in window.findChildren(QToolBar)]
    assert window.objectName() == 'main' and all(names) and len(set(names)) == len(names)
    assert not [message for message in qt_messages if 'objectName' in message]


def test_dock_tab_bars_are_named_and_described(qtbot, settings):
    window, host = started(qtbot, settings, spec('alpha', 'bottom'), spec('beta', 'bottom', tabify_with='alpha'))
    host.show_panel('alpha')
    host.show_panel('beta')
    window.tabifiedDockWidgetActivated.emit(host.panels['beta'].dock)
    bars = [bar for bar in window.findChildren(QTabBar) if bar.parent() is window]
    assert bars and all(bar.objectName() == 'panels.dock_tabs' for bar in bars)
    assert bars[0].accessibleName() == 'Panel tabs' and bars[0].toolTip()


def test_the_view_menu_sits_before_help_and_lists_toggles_and_framework_commands(qtbot, settings):
    window, host = started(qtbot, settings, spec('alpha', shortcut='Ctrl+Shift+Q'), spec('card', 'none'))
    titles = [action.text() for action in window.menuBar().actions()]
    assert titles == ['Project', 'View', 'Help']
    menu = host.view_menu
    shortcuts = {action.text(): action.shortcut().toString() for action in menu.actions() if action.text()}
    assert shortcuts['Alpha'] == 'Ctrl+Shift+Q' and shortcuts['Command palette'] == 'Ctrl+Shift+P'
    assert shortcuts['Next panel'] == 'F6' and shortcuts['Previous panel'] == 'Shift+F6'
    assert {'Reset panel layout', 'Navigate back', 'Navigate forward'} <= set(shortcuts)
    assert 'Card' not in shortcuts  # no dock, no toggle
    assert all(action.toolTip() for action in menu.actions() if action.text())
    toggle = host.toggle_action('alpha')
    toggle.trigger()
    assert host.panels['alpha'].dock.isVisible()


def test_the_central_widget_is_wrapped_without_losing_it(qtbot, settings):
    window = Window(settings)
    qtbot.addWidget(window)
    editor = window.centralWidget()
    assert isinstance(editor, QPlainTextEdit)
    host = PanelHost(window, ())
    host.restore_layout()
    assert window.centralWidget().objectName() == 'workspace.wrapper'
    assert editor.parentWidget() is window.centralWidget() and host.strip.parentWidget() is window.centralWidget()
    assert not host.strip.isVisibleTo(window)  # nothing to say, nothing shown


def test_the_blob_size_limit_is_enforced_on_save(qtbot, settings, monkeypatch):
    window, host = started(qtbot, settings, spec('alpha'))
    monkeypatch.setattr(layout, 'MAX_STATE_BYTES', 4)
    host.shutdown()
    assert not settings.contains('layout/state')
