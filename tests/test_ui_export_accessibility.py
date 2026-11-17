"""Keyboard-only export controls; Qt events are accessibility proxies, not screen-reader acceptance."""
from __future__ import annotations

import pytest
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication, QDialog, QDialogButtonBox, QPushButton

from patchtrace.service import ProjectService
from patchtrace.ui import ExportDialog


@pytest.fixture
def dialog(qtbot, tmp_path):
    service = ProjectService.sample(tmp_path / 'sample')
    view = ExportDialog(service.project, service.root, ['finding-1'])
    qtbot.addWidget(view)
    view.show()
    view.activateWindow()
    qtbot.waitUntil(view.isActiveWindow)
    yield view
    view.close()
    service.close()


def focus(qtbot, widget):
    widget.setFocus()
    qtbot.waitUntil(widget.hasFocus)


def reshow(qtbot, dialog):
    dialog.hide()
    QApplication.processEvents()
    dialog.show()
    dialog.activateWindow()
    QApplication.setActiveWindow(dialog)  # offscreen has no window manager to reactivate a hidden window
    qtbot.waitUntil(dialog.isActiveWindow)


@pytest.mark.parametrize('control', ['format', 'destination', 'contract', 'profile', 'sections_list', 'code', 'notes'])
@pytest.mark.parametrize('key', [Qt.Key.Key_Return, Qt.Key.Key_Enter])
@pytest.mark.parametrize('visit_write_first', [False, True])
def test_enter_in_options_never_writes_report(qtbot, dialog, control, key, visit_write_first):
    # Check initial default state and that a visited button's default does not linger.
    if visit_write_first:
        focus(qtbot, dialog.buttons.button(QDialogButtonBox.StandardButton.Ok))
    focus(qtbot, getattr(dialog, control))
    qtbot.keyClick(getattr(dialog, control), key)
    assert dialog.isVisible()
    assert dialog.result() != QDialog.DialogCode.Accepted


@pytest.mark.parametrize('key', [Qt.Key.Key_Return, Qt.Key.Key_Enter, Qt.Key.Key_Space])
def test_focused_write_button_accepts_with_native_keys(qtbot, dialog, key):
    write = dialog.buttons.button(QDialogButtonBox.StandardButton.Ok)
    focus(qtbot, write)
    qtbot.keyClick(write, key)
    assert dialog.result() == QDialog.DialogCode.Accepted


def test_enter_on_browse_and_cancel_keeps_their_actions(qtbot, dialog, monkeypatch):
    calls = []
    monkeypatch.setattr('patchtrace.ui.QFileDialog.getSaveFileName',
                        lambda *_: calls.append(True) or ('', ''))
    reshow(qtbot, dialog)
    browse = dialog.findChild(QPushButton, 'export.browse')
    focus(qtbot, browse)
    qtbot.keyClick(browse, Qt.Key.Key_Return)
    assert calls == [True] and dialog.isVisible()
    focus(qtbot, dialog.destination)
    qtbot.keyClick(dialog.destination, Qt.Key.Key_Return)
    assert calls == [True] and dialog.isVisible()
    cancel = dialog.buttons.button(QDialogButtonBox.StandardButton.Cancel)
    focus(qtbot, cancel)
    qtbot.keyClick(cancel, Qt.Key.Key_Return)
    assert not dialog.isVisible()
    assert dialog.result() == QDialog.DialogCode.Rejected


@pytest.mark.parametrize(('key', 'control'), [
    (Qt.Key.Key_C, 'contract'), (Qt.Key.Key_P, 'profile'), (Qt.Key.Key_S, 'sections_list'),
])
def test_export_option_mnemonics_focus_their_controls(qtbot, dialog, key, control):
    focus(qtbot, dialog.destination)
    qtbot.keyClick(dialog.destination, key, Qt.KeyboardModifier.AltModifier)
    assert getattr(dialog, control).hasFocus()


def test_tab_and_backtab_follow_visible_export_order(qtbot, dialog):
    browse = dialog.findChild(QPushButton, 'export.browse')
    write = dialog.buttons.button(QDialogButtonBox.StandardButton.Ok)
    cancel = dialog.buttons.button(QDialogButtonBox.StandardButton.Cancel)
    controls = [dialog.format, dialog.destination, browse, dialog.contract, dialog.profile,
                dialog.sections_list, dialog.code, dialog.notes, dialog.selection, dialog.preview, write, cancel]
    focus(qtbot, controls[0])
    for expected in controls[1:]:
        qtbot.keyClick(QApplication.focusWidget(), Qt.Key.Key_Tab)
        assert expected.hasFocus()
    for expected in reversed(controls[:-1]):
        qtbot.keyClick(QApplication.focusWidget(), Qt.Key.Key_Backtab)
        assert expected.hasFocus()


def test_destination_editing_and_escape_stay_native(qtbot, dialog):
    focus(qtbot, dialog.destination)
    dialog.destination.selectAll()
    qtbot.keyClicks(dialog.destination, 'local-report.json')
    qtbot.keyClick(dialog.destination, Qt.Key.Key_Left)
    qtbot.keyClick(dialog.destination, Qt.Key.Key_Backspace)
    assert dialog.destination.text() == 'local-report.jsn'
    qtbot.keyClick(dialog.destination, Qt.Key.Key_Escape)
    assert not dialog.isVisible() and dialog.result() == QDialog.DialogCode.Rejected


def test_return_in_open_combo_selects_without_accepting_dialog(qtbot, dialog):
    focus(qtbot, dialog.contract)
    qtbot.keyClick(dialog.contract, Qt.Key.Key_Down, Qt.KeyboardModifier.AltModifier)
    qtbot.keyClick(dialog.contract.view(), Qt.Key.Key_Down)
    qtbot.keyClick(dialog.contract.view(), Qt.Key.Key_Return)
    assert dialog.contract.currentIndex() == 1
    assert dialog.isVisible() and not dialog.contract.view().isVisible()
    assert dialog.contract.hasFocus()


def test_hide_show_does_not_restore_a_default_for_options(qtbot, dialog):
    write = dialog.buttons.button(QDialogButtonBox.StandardButton.Ok)
    focus(qtbot, write)
    focus(qtbot, dialog.destination)
    reshow(qtbot, dialog)
    qtbot.waitUntil(dialog.destination.hasFocus)
    qtbot.keyClick(dialog.destination, Qt.Key.Key_Return)
    assert dialog.isVisible()
    focus(qtbot, write)
    qtbot.keyClick(write, Qt.Key.Key_Return)
    assert dialog.result() == QDialog.DialogCode.Accepted
