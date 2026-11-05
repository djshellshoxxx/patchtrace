"""Keyboard access to the real offline dialog; no provider or target execution."""
from __future__ import annotations

import pytest
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QLabel

from patchtrace.kbcorrelation.investigation_qt import InvestigationDialog


@pytest.fixture
def dialog(qtbot, tmp_path):
    widget = InvestigationDialog(workspace=tmp_path / 'workspace')
    qtbot.addWidget(widget)
    widget.show()
    widget.activateWindow()
    qtbot.waitUntil(widget.isActiveWindow)
    yield widget
    widget.reject()


@pytest.mark.parametrize('key', ['workspace', 'source', 'lead', 'older', 'newer', 'destination', 'name'])
def test_composite_field_label_targets_edit(dialog, key):
    field = dialog.fields[key]
    labels = [label for label in dialog.findChildren(QLabel) if label.buddy() is field]
    assert len(labels) == 1
    assert '&' in labels[0].text()
    assert field.accessibleName()
    assert field.accessibleDescription()


@pytest.mark.parametrize(('key', 'mnemonic'), [('workspace', 'W'), ('lead', 'K'), ('older', 'O'), ('name', 'M')])
def test_label_mnemonic_moves_keyboard_focus(qtbot, dialog, key, mnemonic):
    dialog.buttons['close'].setFocus()
    qtbot.keyClick(dialog, getattr(Qt.Key, 'Key_' + mnemonic), Qt.KeyboardModifier.AltModifier)
    qtbot.waitUntil(lambda: dialog.fields[key].hasFocus())


def test_product_selection_occurs_between_search_and_binary_fields(qtbot, dialog):
    dialog._investigation_id = 'constructed-investigation'
    dialog._set_scopes([{'scope_id': 'constructed-scope', 'display_name': 'Product', 'architecture': 'amd64'}], None)
    dialog._enable()
    dialog.buttons['search'].setFocus()
    qtbot.keyClick(dialog, Qt.Key.Key_Tab)
    assert dialog.scope.hasFocus()
    qtbot.keyClick(dialog, Qt.Key.Key_Tab)
    assert dialog.fields['older'].hasFocus()
    qtbot.keyClick(dialog, Qt.Key.Key_Backtab)
    assert dialog.scope.hasFocus()


def test_missing_workspace_validation_focuses_correctable_field(dialog):
    dialog.fields['workspace'].clear()
    dialog.buttons['search'].setFocus()
    dialog.buttons['search'].click()
    assert dialog.fields['workspace'].hasFocus()
    assert 'Choose an advisory workspace directory' in dialog.status.full_text()
    assert dialog._pending is None


def test_binary_only_tab_order_skips_disabled_advisory_fields(qtbot, dialog):
    dialog.manual_pair_start.setChecked(True)
    dialog.buttons['browse_workspace'].setFocus()
    qtbot.keyClick(dialog, Qt.Key.Key_Tab)
    assert dialog.fields['older'].hasFocus()
