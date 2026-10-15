"""SPEC-26 requirement A: every functional control carries a registry tooltip."""
from __future__ import annotations

import html
import os
import re
from types import SimpleNamespace

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

import pytest
from PySide6.QtCore import QSettings, Qt
from PySide6.QtGui import QAction
from PySide6.QtWidgets import (
    QAbstractButton,
    QAbstractItemView,
    QAbstractSpinBox,
    QComboBox,
    QDialog,
    QHeaderView,
    QLineEdit,
    QMenu,
    QMessageBox,
    QPlainTextEdit,
    QSlider,
    QTabBar,
    QTextEdit,
    QToolBar,
    QToolButton,
)

from patchtrace import tooltips
from patchtrace import ui as ui_module
from patchtrace.evidence import build_context
from patchtrace.service import ProjectService
from patchtrace.tooltips import EXEMPT_IDS, REGISTRY, TEMPLATES, TooltipEntry, template, tooltip
from patchtrace.ui import (
    AcquisitionDialog,
    ContextDialog,
    CorrectMatchDialog,
    ExportDialog,
    MainWindow,
    NewProjectDialog,
    SetupDialog,
    confirm_tips,
)

GENERIC = {'button', 'ok', 'cancel', 'click here', 'todo', 'tooltip', 'tbd', 'description', 'text'}
FOCUSABLE = (QAbstractButton, QComboBox, QLineEdit, QAbstractSpinBox, QAbstractItemView, QPlainTextEdit,
             QTextEdit, QSlider, QTabBar)


def plain(markup: str) -> str:
    return html.unescape(re.sub(r'<[^>]+>', ' ', markup.replace('<br>', '\n'))).strip()


def check_text(label: str, markup: str) -> None:
    text = plain(markup)
    assert text, f'{label}: empty tooltip'
    assert len(text) >= 25, f'{label}: too short: {text!r}'
    assert text.lower() not in GENERIC, f'{label}: generic placeholder'
    assert text.startswith('What:'), f'{label}: not from the registry: {text[:40]!r}'


def internal(widget) -> bool:
    """Qt-created helpers that users do not interact with as controls."""
    if isinstance(widget, QHeaderView) or widget.objectName().startswith('qt_'):
        return True
    if isinstance(widget, QToolButton) and (widget.defaultAction() is not None
                                            or isinstance(widget.parent(), (QTabBar, QToolBar))):
        return True
    parent = widget.parent()
    while parent is not None:
        if isinstance(parent, (QComboBox, QAbstractSpinBox)):
            return True
        parent = parent.parent()
    return False


def controls(root):
    seen = []
    for kind in FOCUSABLE:
        for widget in root.findChildren(kind):
            if widget not in seen and not internal(widget):
                seen.append(widget)
    return seen


def actions(root, exempt=()):
    found = []
    candidates = list(root.findChildren(QAction))
    for menu in root.findChildren(QMenu):
        candidates += menu.actions()
    for bar in root.findChildren(QToolBar):
        candidates += bar.actions() + [bar.toggleViewAction()]
    toggles = {bar.toggleViewAction() for bar in root.findChildren(QToolBar)}
    for action in candidates:
        if (action in found or action in exempt or action in toggles or action.isSeparator()
                or not action.text().strip()):
            continue
        found.append(action)
    return found


def audit(root, exempt=()):
    covered = set()
    for widget in controls(root):
        label = f'{type(widget).__name__}:{widget.objectName() or widget.accessibleName()}'
        check_text(label, widget.toolTip())
        assert widget.objectName(), f'{label}: no semantic object name'
        assert widget.accessibleDescription(), f'{label}: no accessible description'
        assert len(widget.accessibleDescription()) <= 160 and not widget.accessibleDescription().startswith('What:'), label
        base = widget.objectName()
        if base in REGISTRY:
            assert widget.toolTip() == tooltip(base)
        covered.add(base.split('.')[0] + '.' + base.split('.')[1] if base.count('.') > 1 else base)
    for action in actions(root, exempt):
        label = f'QAction:{action.text()}'
        check_text(label, action.toolTip())
        assert action.statusTip(), f'{label}: no status tip'
        covered.add(action.objectName())
    return covered


@pytest.fixture
def settings(tmp_path):
    return QSettings(str(tmp_path / 'ui.ini'), QSettings.Format.IniFormat)


@pytest.fixture
def window(qtbot, tmp_path, settings):
    view = MainWindow(ProjectService.sample(tmp_path / 's'), settings, tmp_path / 'profiles')
    qtbot.addWidget(view)
    yield view
    if view.service:
        view.service.close()
        view.service = None


# -- registry as pure data ------------------------------------------------------------------


def test_registry_entries_render_and_are_unique():
    assert len(REGISTRY) >= 100
    rendered = {}
    for key, entry in REGISTRY.items():
        assert isinstance(entry, TooltipEntry)
        text = entry.render()
        assert entry.what and entry.why and entry.effect, key
        assert text.startswith('What: '), key
        assert '<' not in text and '>' not in text, key
        assert text not in rendered, f'{key} duplicates {rendered.get(text)}'
        rendered[text] = key
    whats = [entry.what for entry in REGISTRY.values()]
    assert len(whats) == len(set(whats)), 'two entries share the same What text'
    for key in TEMPLATES:
        assert '<' not in TEMPLATES[key].render()


def test_unknown_id_raises_and_exempt_ids_are_the_two_actions():
    with pytest.raises(KeyError):
        tooltip('nope.nope')
    assert EXEMPT_IDS == {'action.new', 'action.open'}


def test_code_pane_entries_state_provenance():
    for key in ('viewer.older_code', 'viewer.newer_code'):
        text = REGISTRY[key].render()
        for phrase in ('C-like decompiler output', 'Ghidra via Ghidriff', 'not original source',
                       'upstream Ghidriff result retained', 'saved normalized or raw analysis',
                       'display alignment only', 'No text view implies'):
            assert phrase in text, (key, phrase)


def test_template_escapes_and_caps_untrusted_values():
    hostile = '<script>\x00name'
    rendered = template('action.recent_project', path=hostile)
    assert '<script>' not in rendered and '\x00' not in rendered
    assert '&lt;script&gt;name' in rendered
    assert rendered.count('<') == rendered.count('<p') + rendered.count('<br>') + rendered.count('</p>')
    long = template('profile.detector_weight', detector='A' * 5000)
    assert len(long) < 1200
    assert tooltips.clean_value('a\x00b c') == 'abc'


# -- main window ---------------------------------------------------------------------------


def test_main_window_every_action_and_control_has_a_registry_tooltip(window):
    exempt = {window.new_action, window.open_action}
    audit(window, exempt)
    for action in exempt:
        assert action.text() in ('New', 'Open')
        assert not action.toolTip() or not plain(action.toolTip()).startswith('What:')


def test_every_registry_id_is_applied_somewhere(window, qtbot, tmp_path, settings, monkeypatch):
    monkeypatch.setattr(ui_module, 'discover_local_runtimes',
                        lambda: SimpleNamespace(python_executables=[], ghidra_roots=[]))
    names = set()
    roots = [window]
    context = build_context(window.project, [window.current_match().id])
    roots += [NewProjectDialog(), AcquisitionDialog(), SetupDialog(settings, None, tmp_path / 'p2'),
              ContextDialog(context, settings, window),
              CorrectMatchDialog(window.project, window.current_match(), window),
              ExportDialog(window.project, window.service.root, [], window)]
    for root in roots[1:]:
        qtbot.addWidget(root)
    window.show_file_overview()
    series = window.panels.show_panel('series') and window.panels.controller('series').open_series(
        tmp_path / 'no-series.json')
    qtbot.waitUntil(lambda: series.loaded is not None, timeout=5000)
    roots.append(series)
    names |= {series.objectName(), series.banner.objectName()}
    # C6: the dock and stale banner are containers/labels, not focusable controls.
    names |= {window.panels.controller('evidence').dock.objectName(), window.panels.controller('evidence').panel.stale_banner.objectName()}
    # M3: the series and files docks are containers too.
    names |= {window.panels.panels[panel_id].dock.objectName() for panel_id in ('series', 'files')}
    names |= {'unified.dock', 'unified.tab', 'unified.source.unknown', 'leads.dock'}
    # Track G: the BinDiff setup group and its warning label are a container and a label.
    setup = window.panels.controller('evidence').panel.bindiff_setup
    names |= {setup.objectName(), setup.warning.objectName()}
    # F5: framework widgets and every panel the manifest has built, without listing panel roots by hand.
    from PySide6.QtWidgets import QDockWidget

    from patchtrace.gui.qt.docks import name_tab_bars
    from patchtrace.gui.qt.state_view import StateView
    state = StateView('zz', 'Zz')
    qtbot.addWidget(state)
    roots += [state] + [c.widget() for c in window.panels.build_all_for_test().values() if c.widget() is not None]
    first, second = QDockWidget('A', window), QDockWidget('B', window)
    first.setObjectName('zz_a.dock'), second.setObjectName('zz_b.dock')
    window.addDockWidget(Qt.DockWidgetArea.BottomDockWidgetArea, first)
    window.tabifyDockWidget(first, second)
    name_tab_bars(window)
    names |= {window.panels.strip.objectName()}
    for root in roots + [window]:
        names |= {w.objectName() for w in controls(root)}
        names |= {a.objectName() for a in actions(root)}
    shown = {w.toolTip() for root in roots + [window] for w in controls(root)}
    shown |= {a.toolTip() for root in roots + [window] for a in actions(root)}
    names |= {tip_id for tip_id in REGISTRY if tooltip(tip_id) in shown}  # a control may carry a per-panel name
    names |= {'dialog.text_view', 'dialog.close', 'confirm.yes', 'confirm.no'}
    names |= {n.rsplit('.', 1)[0] for n in names if n.startswith('profile.detector')}
    missing = set(REGISTRY) - names - EXEMPT_IDS
    assert not missing, sorted(missing)


def test_disabled_controls_keep_tooltip_and_state_prerequisite(qtbot, settings, tmp_path):
    empty = MainWindow(None, settings, tmp_path / 'profiles')
    qtbot.addWidget(empty)
    assert not empty.run_action.isEnabled() and not empty.correct_button.isEnabled()
    assert not empty.previous_diff.isEnabled()
    for control in (empty.correct_button, empty.previous_diff, empty.next_diff, empty.bookmark_button):
        assert not control.isEnabled()
        check_text(control.objectName(), control.toolTip())
        assert 'Availability:' in control.toolTip()
    for action in (empty.run_action, empty.export_action, empty.interpret_action, empty.rank_action):
        assert not action.isEnabled()
        check_text(action.text(), action.toolTip())
        assert 'Availability:' in action.toolTip()
    panel = empty.panels.controller('evidence').panel  # C6: no project -> run/copy/goto disabled, prerequisite stated
    for control in (panel.run_button, panel.copy_button, panel.goto_button):
        assert not control.isEnabled()
        check_text(control.objectName(), control.toolTip())
        assert 'Availability:' in control.toolTip()
    setup = panel.bindiff_setup  # track G: no project -> the BinDiff setup controls are disabled, prerequisite stated
    for control in (setup.toggle_button, setup.path, setup.probe_button, setup.older, setup.validate_button,
                    setup.accept_box, setup.cancel_button):
        assert not control.isEnabled(), control.objectName()
        check_text(control.objectName(), control.toolTip())
        assert 'Availability:' in control.toolTip()


def test_recent_project_actions_use_escaped_template(window):
    window.settings.setValue('recent/projects', ['/tmp/<b>evil</b>\x00'])
    window.refresh_recent()
    recent = [a for a in window.recent_menu.actions()]
    assert recent and '<b>' not in recent[0].toolTip() and '&lt;b&gt;evil' in recent[0].toolTip()


# -- dialogs ---------------------------------------------------------------------------------


def test_new_project_dialog(qtbot):
    dialog = NewProjectDialog()
    qtbot.addWidget(dialog)
    audit(dialog)
    assert len(controls(dialog)) >= 10


def test_acquisition_dialog(qtbot):
    dialog = AcquisitionDialog()
    qtbot.addWidget(dialog)
    audit(dialog)
    assert not dialog.download_button.isEnabled()
    assert 'Needs both' in plain(dialog.download_button.toolTip())


def test_setup_dialog_all_tabs_and_profiles(qtbot, settings, tmp_path, monkeypatch):
    monkeypatch.setattr(ui_module, 'discover_local_runtimes',
                        lambda: SimpleNamespace(python_executables=[], ghidra_roots=[]))
    dialog = SetupDialog(settings, None, tmp_path / 'profiles')
    qtbot.addWidget(dialog)
    audit(dialog)
    assert not dialog.cancel_install.isEnabled()
    assert 'Only enabled while' in plain(dialog.cancel_install.toolTip())
    panel = dialog.profiles
    assert panel.weights and all(spin.toolTip() for spin in panel.weights.values())
    assert 'BND' in plain(panel.weights['BND'].toolTip())


def test_context_dialog(qtbot, window):
    context = build_context(window.project, [window.current_match().id])
    dialog = ContextDialog(context, window.settings, window)
    qtbot.addWidget(dialog)
    audit(dialog)


def test_correct_match_dialog(qtbot, window):
    dialog = CorrectMatchDialog(window.project, window.current_match(), window)
    qtbot.addWidget(dialog)
    audit(dialog)


def test_export_dialog(qtbot, window):
    dialog = ExportDialog(window.project, window.service.root, [], window)
    qtbot.addWidget(dialog)
    audit(dialog)
    assert not dialog.selection.isEnabled()
    assert 'Needs findings selected' in plain(dialog.selection.toolTip())


def test_files_panel(qtbot, window):
    window.show_file_overview()
    files = window.panels.controller('files').widget()
    audit(files)
    assert len(controls(files)) >= 1
    assert sorted(t.accessibleName() for t in files.findChildren(QAbstractItemView) if t.objectName().startswith('overview.')) == [
        'PE comparison fields', 'Recorded artifact fields']


def test_text_dialogs_and_confirmation_boxes(qtbot, window, monkeypatch):
    shown = []
    monkeypatch.setattr(QDialog, 'exec', lambda self: shown.append(self) or 0)
    window.show_help()
    assert shown
    audit(shown[0])
    box = QMessageBox(QMessageBox.Icon.Question, 'Title', 'Body',
                      QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
    qtbot.addWidget(box)
    confirm_tips(box)
    audit(box)
    assert box.button(QMessageBox.StandardButton.Yes).objectName() == 'confirm.yes'


def test_evidence_ids_prefix_complete(window):
    """Every evidence.* widget/action name is a registry ID and every evidence.* ID is used (C6 7.2)."""
    ids = {key for key in REGISTRY if key.startswith('evidence.')}
    templates = {key for key in TEMPLATES if key.startswith('evidence.')}
    assert len(ids) >= 22 and {'evidence.row', 'evidence.cell', 'evidence.badge'} <= templates
    dock = window.panels.controller('evidence').dock
    used = {w.objectName() for w in dock.findChildren(object) if hasattr(w, 'objectName')}
    used |= {dock.objectName(), window.panels.toggle_action('evidence').objectName()}
    # the host's StateView around the panel names its own children `evidence.state_*` (gui tips, not this registry)
    evidence_names = {name for name in used if name.startswith('evidence.') and '.state_' not in name}
    assert evidence_names <= ids, sorted(evidence_names - ids)
    assert ids <= evidence_names, sorted(ids - evidence_names)
    audit(dock)


def test_engine_setup_ids_prefix_complete(window):
    """Track G (spec 16.8): every engine_setup.* id is used in the dock and every such widget is registered."""
    ids = {key for key in REGISTRY if key.startswith('engine_setup.')}
    assert len(ids) == 15
    dock = window.panels.controller('evidence').dock
    used = {w.objectName() for w in dock.findChildren(object) if hasattr(w, 'objectName')}
    names = {name for name in used if name.startswith('engine_setup.')}
    assert names == ids, sorted(names ^ ids)
    setup = window.panels.controller('evidence').panel.bindiff_setup
    for widget in controls(setup) + [setup.toggle_button]:
        assert widget.objectName().startswith('engine_setup.'), widget.objectName()
        assert widget.toolTip() == tooltip(widget.objectName())
        assert widget.accessibleName() and widget.accessibleDescription(), widget.objectName()
    for key in ids:
        entry = REGISTRY[key]
        assert len(entry.render()) >= 120, key  # verbose: what, why and effect each say something real
