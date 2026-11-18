"""SPEC-01a: explicit timeout edits cannot silently save a different budget."""
from __future__ import annotations

import pytest
from PySide6.QtCore import QSettings, Qt
from PySide6.QtWidgets import QDialog, QDialogButtonBox

from patchtrace import ui
from patchtrace.ui_timeout import ERROR


@pytest.fixture
def dialog(qtbot, tmp_path, monkeypatch):
    # This slice must never inspect or launch local backend installations.
    monkeypatch.setattr(ui.SetupDialog, 'discover_existing', lambda self: None)
    settings = QSettings(str(tmp_path / 'setup.ini'), QSettings.Format.IniFormat)
    settings.setValue('backend/timeout', 4567)
    view = ui.SetupDialog(settings, profile_directory=tmp_path / 'profiles')
    qtbot.addWidget(view)
    view.show()
    return view, settings


@pytest.mark.parametrize('text', ['', '0', '9', '-1', '86401', '100000', '12.5', '1e3', 'abc', '１２'])
def test_invalid_entry_survives_focus_change_and_blocks_save_and_diagnosis(dialog, qtbot, monkeypatch, text):
    view, settings = dialog
    view.timeout.setFocus()
    view.timeout.setText(text)
    view.check.setFocus()  # unlike QSpinBox, preserve the invalid input on blur
    calls = []
    monkeypatch.setattr(ui, 'diagnose', lambda *_: calls.append('diagnosed'))
    qtbot.mouseClick(view.check, Qt.MouseButton.LeftButton)
    assert view.worker is None and not calls
    assert view.timeout.text() == text
    assert view.timeout_choice.error.text() == ERROR
    buttons = view.findChild(QDialogButtonBox)
    qtbot.mouseClick(buttons.button(QDialogButtonBox.StandardButton.Ok), Qt.MouseButton.LeftButton)
    assert view.isVisible() and view.result() != QDialog.DialogCode.Accepted
    assert settings.value('backend/timeout', type=int) == 4567
    assert view.timeout.hasFocus()


@pytest.mark.parametrize('seconds', [10, 3600, 7200, 14400, 86400])
def test_valid_budget_reaches_config_and_save(dialog, seconds):
    view, settings = dialog
    view.timeout.setText(str(seconds))
    assert view.config().timeout_seconds == seconds
    assert view.timeout_choice.error.text() == ''
    view.accept()
    assert view.result() == QDialog.DialogCode.Accepted
    # MainWindow owns persistence; simply choosing/accepting here cannot write.
    assert settings.value('backend/timeout', type=int) == 4567


def test_presets_are_keyboard_accessible_and_custom_retains_text(dialog, qtbot):
    view, settings = dialog
    presets = view.timeout_choice.presets
    assert presets.currentText() == 'Custom'
    assert view.timeout.value() == 4567
    presets.setFocus()
    qtbot.keyClick(presets, Qt.Key.Key_Down)
    assert view.timeout.value() == 3600
    qtbot.keyClick(presets, Qt.Key.Key_Down)
    assert view.timeout.value() == 7200
    qtbot.keyClick(presets, Qt.Key.Key_Down)
    assert view.timeout.value() == 14400
    presets.setCurrentIndex(0)
    presets.activated.emit(0)
    assert view.timeout.value() == 14400
    view.timeout.setText('12345')
    assert presets.currentText() == 'Custom'
    view.timeout.setText('0')
    presets.setCurrentIndex(1)
    presets.activated.emit(1)
    assert view.timeout.value() == 3600 and view.timeout_choice.error.text() == ''
    assert presets.accessibleName() and presets.accessibleDescription()
    view.reject()
    assert settings.value('backend/timeout', type=int) == 4567


def test_save_invalid_timeout_from_profiles_returns_to_visible_error(dialog):
    view, settings = dialog
    view.timeout.setText('')
    view.tabs.setCurrentWidget(view.profiles)
    view.accept()
    assert view.tabs.currentIndex() == 0
    assert view.timeout.hasFocus()
    assert view.isVisible() and view.timeout_choice.error.text() == ERROR
    assert settings.value('backend/timeout', type=int) == 4567
