# ruff: noqa: F811
"""Command palette, host commands and the F6 focus cycle (GUI plan 8.3)."""
from __future__ import annotations

import pytest
from host_support import make_host, private_tooltip_registry, spec  # noqa: F401
from PySide6.QtCore import Qt
from PySide6.QtGui import QAction, QGuiApplication, QKeySequence
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication, QMainWindow, QPlainTextEdit
from qt_support import HOSTILE_PARAMS, join_gui_threads, main_window, settings, top_level_windows  # noqa: F401

from patchtrace.gui.capabilities import Availability
from patchtrace.gui.qt.commands import action_entries
from patchtrace.gui.qt.palette import RECENT_KEY, PaletteEntry, matches
from patchtrace.gui.registry import PALETTE_RESULTS, CommandSpec
from patchtrace.tooltips import TooltipEntry


def activate(qtbot, window):
    window.show()
    window.activateWindow()
    qtbot.waitActive(window)
    qtbot.waitUntil(lambda: QGuiApplication.focusWindow() is window.windowHandle())  # shortcuts follow the focus window


def entry(command_id: str, title: str, *keywords: str, enabled: bool = True) -> PaletteEntry:
    return PaletteEntry(command_id, title, lambda: None, keywords, enabled=enabled)


# ---- filtering (pure) --------------------------------------------------------------------------------------


@pytest.mark.parametrize('query, expected', [
    ('', ['a', 'b', 'c']),
    ('FOCUS', ['a', 'b']),
    ('focus search', ['b']),
    ('zzz', []),
    ('  graph ', ['a']),
], ids=['empty', 'case', 'all-words', 'none', 'trim'])
def test_matching_is_a_case_insensitive_substring_on_every_word(query, expected):
    entries = [entry('a', 'Focus Graph panel'), entry('b', 'Focus panel', 'search'), entry('c', 'Open project')]
    assert [e.id for e in matches(entries, query)] == expected


def test_recent_commands_come_first_only_for_an_empty_query():
    entries = [entry('a', 'Alpha'), entry('b', 'Beta'), entry('c', 'Gamma')]
    assert [e.id for e in matches(entries, '', ('c', 'b'))] == ['c', 'b', 'a']
    assert [e.id for e in matches(entries, 'ta', ('c',))] == ['b']


def test_results_are_capped():
    many = [entry(f'c{n}', f'Command {n}') for n in range(PALETTE_RESULTS + 30)]
    assert len(matches(many, 'command')) == PALETTE_RESULTS


def test_a_disabled_entry_reads_unavailable_with_its_reason():
    assert entry('a', 'Run').label() == 'Run'
    off = PaletteEntry('a', 'Run', lambda: None, enabled=False, reason='Open a project first.')
    assert off.label() == 'Run  (unavailable: Open a project first.)'
    assert '(unavailable: not available now)' in PaletteEntry('a', 'Run', lambda: None, enabled=False).label()


# ---- the widget -------------------------------------------------------------------------------------------


def with_commands(qtbot, settings, ran, *, extra_spec=None):
    command = CommandSpec(id='alpha.go', title='Go alpha', run=lambda: ran.append('alpha.go'), keywords=('jump',))
    off = CommandSpec(id='alpha.off', title='Off alpha', run=lambda: ran.append('off'),
                      enabled=lambda: Availability(False, 'Open a project first.'))
    window, host = make_host(qtbot, settings, spec('alpha', commands=(command, off)))
    window.show()
    host.restore_layout()
    return window, host


def test_the_palette_lists_panel_host_and_menu_commands(qtbot, settings):
    ran = []
    window, host = with_commands(qtbot, settings, ran)
    host.open_palette()
    labels = [host.palette.results.item(row).text() for row in range(host.palette.results.count())]
    assert 'Go alpha' in labels and 'Off alpha  (unavailable: Open a project first.)' in labels
    assert 'Show Alpha panel' in labels and 'Focus Alpha panel' in labels and 'Float or dock Alpha panel' in labels
    assert not any(label.startswith('Move Alpha panel to the right') for label in labels)  # it is already there
    assert 'Move Alpha panel to the left' in labels and 'View > Reset panel layout' in labels
    assert 'Project' not in labels and not host.palette.isWindow()
    assert len(top_level_windows()) == 1


def test_enter_runs_the_chosen_command_and_closes_the_palette(qtbot, settings):
    ran = []
    window, host = with_commands(qtbot, settings, ran)
    host.open_palette()
    qtbot.keyClicks(host.palette.search, 'jump')
    assert host.palette.results.count() == 1
    qtbot.keyClick(host.palette.search, Qt.Key.Key_Return)
    assert ran == ['alpha.go'] and host.palette.isHidden()
    assert [str(item) for item in settings.value(RECENT_KEY)] == ['alpha.go']


def test_an_unavailable_command_explains_itself_and_stays_open(qtbot, settings):
    ran = []
    window, host = with_commands(qtbot, settings, ran)
    host.open_palette()
    qtbot.keyClicks(host.palette.search, 'off alpha')
    qtbot.keyClick(host.palette.search, Qt.Key.Key_Return)
    assert not ran and host.palette.isVisible()
    assert window.statusBar().currentMessage() == 'Off alpha is unavailable: Open a project first.'


def test_escape_closes_the_palette_without_cancelling_the_job(qtbot, settings):
    window, host = with_commands(qtbot, settings, [])
    cancelled = []
    cancel = QAction('Cancel job', window)
    cancel.setShortcut(QKeySequence('Escape'))
    cancel.triggered.connect(lambda: cancelled.append(1))
    window.addAction(cancel)
    activate(qtbot, window)
    editor = window.centralWidget().findChild(QPlainTextEdit)
    editor.setFocus()
    host.open_palette()
    qtbot.keyClick(host.palette.search, Qt.Key.Key_Escape)
    assert host.palette.isHidden() and not cancelled
    assert window.focusWidget() is editor  # focus goes back where it was


def test_escape_in_the_result_list_closes_the_palette_without_cancelling_the_job(qtbot, settings):
    window, host = with_commands(qtbot, settings, [])
    cancelled = []
    cancel = QAction('Cancel job', window)
    cancel.setShortcut(QKeySequence('Escape'))
    cancel.triggered.connect(lambda: cancelled.append(1))
    window.addAction(cancel)
    activate(qtbot, window)
    host.open_palette()
    host.palette.results.setFocus()
    qtbot.keyClick(host.palette.results, Qt.Key.Key_Escape)
    assert host.palette.isHidden() and not cancelled


def test_submenu_actions_all_reach_the_palette(qtbot):
    window = QMainWindow()
    qtbot.addWidget(window)
    for number in range(50):
        menu = window.menuBar().addMenu(f'Menu {number}')
        menu.addAction(f'Top {number}').setObjectName(f'top.{number}')
        sub = menu.addMenu(f'Sub {number}')
        for leaf in range(3):
            sub.addAction(f'Leaf {number} {leaf}').setObjectName(f'leaf.{number}.{leaf}')
        menu.addAction(f'Tail {number}').setObjectName(f'tail.{number}')
    ids = {item.id for item in action_entries(window)}
    expected = {f'{kind}.{n}' for n in range(50) for kind in ('top', 'tail')}
    expected |= {f'leaf.{n}.{k}' for n in range(50) for k in range(3)}
    assert expected <= ids


def test_arrow_keys_move_the_selection_without_leaving_the_search_box(qtbot, settings):
    window, host = with_commands(qtbot, settings, [])
    activate(qtbot, window)
    host.open_palette()
    qtbot.keyClick(host.palette.search, Qt.Key.Key_Down)
    assert host.palette.results.currentRow() == 1 and window.focusWidget() is host.palette.search
    qtbot.keyClick(host.palette.search, Qt.Key.Key_Up)
    qtbot.keyClick(host.palette.search, Qt.Key.Key_Up)
    assert host.palette.results.currentRow() == 0


def test_recent_commands_lead_the_next_listing(qtbot, settings):
    ran = []
    window, host = with_commands(qtbot, settings, ran)
    host.open_palette()
    qtbot.keyClicks(host.palette.search, 'jump')
    qtbot.keyClick(host.palette.search, Qt.Key.Key_Return)
    host.open_palette()
    assert host.palette.results.item(0).text() == 'Go alpha'


def test_the_result_count_is_announced_politely_after_typing_stops(qtbot, settings, monkeypatch):
    window, host = with_commands(qtbot, settings, [])
    sent = []
    monkeypatch.setattr(host.announcer, '_sender', lambda target, text, assertive: sent.append((text, assertive)))
    host.open_palette()
    qtbot.keyClicks(host.palette.search, 'jump')
    assert not sent  # not while typing
    qtbot.waitUntil(lambda: bool(sent), timeout=2000)
    assert sent[-1] == ('1 command', False)


@pytest.mark.parametrize('text', HOSTILE_PARAMS)
def test_hostile_action_titles_are_shown_as_plain_text(qtbot, settings, text):
    window, host = with_commands(qtbot, settings, [])
    action = QAction(text, window)
    window.menuBar().actions()[0].menu().addAction(action)
    host.open_palette()
    shown = ' '.join(host.palette.results.item(row).text() for row in range(host.palette.results.count()))
    assert '\x00' not in shown and '‮' not in shown and '\x1b' not in shown


def test_menu_actions_keep_their_shortcut_and_unavailable_reason(qtbot, settings):
    window, host = with_commands(qtbot, settings, [])
    action = QAction('Run comparison', window)
    action.setShortcut(QKeySequence('F5'))
    from patchtrace.tooltips import REGISTRY, apply_tooltip
    REGISTRY['zz.run'] = TooltipEntry('Run the comparison.', 'Why.', 'Effect.', availability='Needs a project.')
    apply_tooltip(action, 'zz.run')
    action.setEnabled(False)
    window.menuBar().actions()[0].menu().addAction(action)
    host.open_palette()
    labels = [host.palette.results.item(row).text() for row in range(host.palette.results.count())]
    assert 'Project > Run comparison  [F5]  (unavailable: Needs a project.)' in labels


# ---- host commands and focus ---------------------------------------------------------------------------------


def test_host_commands_show_float_and_move_a_panel(qtbot, settings):
    window, host = with_commands(qtbot, settings, [])
    entries = {e.id: e for e in host.palette_entries()}
    entries['alpha.toggle'].run()
    assert host.is_shown('alpha') and host.dock_area('alpha') == 'right'
    entries['alpha.move_bottom'].run()
    assert host.dock_area('alpha') == 'bottom'
    entries['alpha.float'].run()
    assert host.panels['alpha'].dock.isFloating()
    entries['alpha.float'].run()
    assert not host.panels['alpha'].dock.isFloating()
    entries['alpha.toggle'].run()
    assert not host.is_shown('alpha')
    assert {e.title for e in host.palette_entries() if e.id == 'alpha.toggle'} == {'Show Alpha panel'}


def test_a_command_that_raises_costs_a_status_line(qtbot, settings):
    def boom():
        raise RuntimeError('private')

    window, host = make_host(qtbot, settings, spec('alpha', commands=(CommandSpec(id='alpha.boom', title='Boom', run=boom),)))
    {e.id: e for e in host.palette_entries()}['alpha.boom'].run()
    assert window.statusBar().currentMessage() == 'Command failed: RuntimeError.'


def test_f6_cycles_through_the_regions_and_wraps(main_window, qtbot):
    window = main_window
    activate(qtbot, window)
    order = [window.navigator, window.views['older'], window.findings_list, window.logs]
    window.navigator.setFocus()
    seen = []
    for _ in range(len(order) + 1):
        window.panels.cycle_focus(1)
        seen.append(QApplication.focusWidget() or window.focusWidget())
    assert seen == [*order[1:], order[0], order[1]]
    window.panels.cycle_focus(-1)
    assert (QApplication.focusWidget() or window.focusWidget()) is order[0]


def test_the_main_window_menu_and_palette_shortcut_are_registered(main_window, qtbot):
    window = main_window
    titles = [action.text() for action in window.menuBar().actions()]
    assert titles.index('View') == titles.index('Help') - 1
    shortcuts = {a.shortcut().toString() for a in window.menuBar().actions()[titles.index('View')].menu().actions()}
    assert {'Ctrl+Shift+P', 'F6', 'Shift+F6', 'Alt+Left', 'Alt+Right'} <= shortcuts
    activate(qtbot, window)
    window.navigator.setFocus()
    # A real key press proves the shortcut is live. Not Ctrl+Shift+P: QTest leaves the modifiers of a chord set,
    # which turns a later selectRow() in another test into a toggle.
    QTest.keyClick(window.navigator, Qt.Key.Key_F6)
    assert window.focusWidget() is window.views['older']
    next(a for a in window.menuBar().actions()[titles.index('View')].menu().actions()
         if a.shortcut().toString() == 'Ctrl+Shift+P').trigger()
    assert window.panels.palette.isVisible()
    labels = [window.panels.palette.results.item(r).text() for r in range(window.panels.palette.results.count())]
    assert any(label.startswith('Project > Open') for label in labels) and any('Interpret selection' in label for label in labels)
