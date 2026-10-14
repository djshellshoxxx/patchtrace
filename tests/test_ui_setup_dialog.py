"""2026-10-14 audit P2: SetupDialog unsaved-profile prompt, background discovery, reject behavior."""
from __future__ import annotations

import os

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

import pytest
from PySide6.QtCore import QSettings
from PySide6.QtWidgets import QDialog

from patchtrace.enrichment import profiles
from patchtrace.enrichment.profiles import ProfileStore
from patchtrace.service import ProjectService
from patchtrace.ui import MainWindow, SetupDialog


@pytest.fixture
def window(qtbot, tmp_path):
    service = ProjectService.sample(tmp_path / 'sample')
    settings = QSettings(str(tmp_path / 'ui.ini'), QSettings.Format.IniFormat)
    view = MainWindow(service, settings)
    qtbot.addWidget(view)
    view.show()
    yield view
    view.close()


def make_dialog(qtbot, window, tmp_path):
    store = ProfileStore(tmp_path / 'profiles')
    store.save(profiles.build({'name': 'triage', 'snapshot_max_age_days': 7}))
    dialog = SetupDialog(window.settings, window, tmp_path / 'profiles')
    qtbot.addWidget(dialog)
    dialog.profiles.reload('triage')
    return dialog, store


def test_accept_prompts_for_unsaved_profile_edits(qtbot, window, tmp_path, monkeypatch):
    dialog, store = make_dialog(qtbot, window, tmp_path)
    assert not dialog.profiles.is_dirty()
    dialog.profiles.max_age.setValue(30)
    assert dialog.profiles.is_dirty()
    asked = []
    monkeypatch.setattr(dialog.profiles, 'confirm_save', lambda name: asked.append(name) or False)
    dialog.accept()  # user chose to keep editing
    assert asked == ['triage'] and dialog.result() != QDialog.DialogCode.Accepted
    assert store.get('triage').snapshot_max_age_days == 7
    monkeypatch.setattr(dialog.profiles, 'confirm_save', lambda name: True)
    dialog.accept()
    assert dialog.result() == QDialog.DialogCode.Accepted
    assert store.get('triage').snapshot_max_age_days == 30


def test_accept_stays_open_when_profile_save_fails(qtbot, window, tmp_path, monkeypatch):
    dialog, _ = make_dialog(qtbot, window, tmp_path)
    dialog.profiles.feature_ids.setText('not-a-number')
    monkeypatch.setattr(dialog.profiles, 'confirm_save', lambda name: True)
    dialog.accept()
    assert dialog.result() != QDialog.DialogCode.Accepted
    assert dialog.tabs.currentWidget() is dialog.profiles and 'Not saved' in dialog.profiles.error.text()


def test_accept_without_edits_does_not_prompt(qtbot, window, tmp_path, monkeypatch):
    dialog, _ = make_dialog(qtbot, window, tmp_path)
    monkeypatch.setattr(dialog.profiles, 'confirm_save', lambda name: pytest.fail('prompted'))
    dialog.accept()
    assert dialog.result() == QDialog.DialogCode.Accepted
